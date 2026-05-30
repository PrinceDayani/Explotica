"""Adaptive UDP scan engine — state-aware, ICMP-pacing, no admin required.

Three things make this better than a naive "send bytes, wait for reply":

1. **Connected-socket state detection, zero privileges.** A ``connect()``-ed UDP
   socket surfaces the target's ICMP port-unreachable as a *socket error* on the
   next operation — ``ECONNREFUSED`` on Linux, ``WSAECONNRESET`` (10054) on
   Windows. So we get the three real states — ``open`` (data back), ``closed``
   (conn-refused), ``open|filtered`` (silent) — cross-platform, **without raw
   sockets or admin**. nmap needs Npcap/root to read ICMP; we don't.

   (We use blocking sockets in a thread pool rather than asyncio datagram
   transports on purpose: Windows' ProactorEventLoop EINVALs on connected-UDP
   ``sendto``. UDP is ICMP-rate-limited anyway, so massive concurrency buys
   nothing — moderate threading + adaptive pacing is simpler and more correct.)

2. **Protocol-correct payloads** (``udp_payloads``) so open ports actually
   answer, + **rich parsers** (``udp_parsers``) so we report intel, not just
   "open".

3. **Adaptive ICMP-aware pacing.** Hosts rate-limit ICMP port-unreachable
   (Linux: ~1/sec by default). Blast 65535 ports and most *closed* ports look
   silent because the host suppressed the ICMP — you'd misreport them as
   ``open|filtered``. We measure the host's actual ICMP budget from the
   conn-refused we *do* get, then retransmit the silent set at that pace so each
   port gets an un-suppressed chance. This is nmap's congestion-control idea,
   done with stdlib sockets.

Output: a list of ``Port`` objects (protocol="udp"), so UDP results flow through
the same JSON / TUI / dashboard path as TCP. Open ports also carry parsed intel
in ``Port.service_intel``.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from ..core.models import Port
from . import udp_payloads
from .udp_parsers import parse_udp_response

log = logging.getLogger(__name__)

ALL_UDP_PORTS = list(range(1, 65536))


# ════════════════════════════════════════════════════════════════════════════
#  YOUR CONTRIBUTION — outcome classifier + retransmit policy
# ════════════════════════════════════════════════════════════════════════════
# This tiny function is the *honesty core* of the whole scanner. Every probe
# ends in one of four raw outcomes; this maps an outcome to a Port state and
# decides whether the port deserves another packet.
#
# The hard call is the TIMEOUT case. A silent port might be:
#   (a) genuinely open but mute (we don't speak its protocol), OR
#   (b) closed, but the host suppressed its ICMP reply due to rate-limiting.
# You can NEVER be 100% sure which from a single probe — that ambiguity is
# exactly why nmap reports "open|filtered". The decisions you own here:
#
#   • should_retry: is it worth spending another packet on a TIMEOUT? Retrying
#     resolves rate-limited-closed ports into honest "closed", at the cost of
#     time. (Returning False for everything = fast but lots of open|filtered.)
#   • The final state we assign a TIMEOUT that survived all retries. The honest
#     answer is "open|filtered". Tempting shortcut: if we KNOW the host emits
#     ICMP (host_emits_icmp=True, we saw conn-refused elsewhere) you *could*
#     lean toward "filtered" — but that's a heuristic, not evidence.
#
# A sensible default is provided so the module runs. Tune it to taste.
def classify_outcome(outcome: str, *, errno: int = 0,
                     final: bool = False,
                     host_emits_icmp: bool = False) -> tuple[str, str, bool]:
    """Map a probe outcome to (port_state, reason, should_retry).

    Args:
      outcome: one of 'data' | 'refused' | 'timeout' | 'error'.
      errno:   OS errno when outcome == 'error'.
      final:   True if this was the last allowed retransmission round.
      host_emits_icmp: True if any conn-refused was seen on this host (proof the
                       host *does* answer with ICMP, so silence is suspicious).

    Returns (state, reason, should_retry). ``should_retry`` is ignored when the
    state is terminal (open/closed/error).
    """
    if outcome == "data":
        return ("open", "udp reply received", False)
    if outcome == "refused":
        return ("closed", "ICMP port-unreachable", False)
    if outcome == "error":
        return ("filtered", f"socket errno={errno}", False)
    # outcome == "timeout"
    if not final:
        # Retry while there's still budget. Silence on a host we KNOW emits ICMP
        # is suspicious (likely rate-limited-closed) and worth another packet;
        # on a host that has never sent ICMP, the silent port is more plausibly
        # genuinely open|filtered, but a couple of retries are still cheap.
        return ("open|filtered", "no response", True)
    return ("open|filtered", "no response (after retries)", False)
# ════════════════════════════════════════════════════════════════════════════


def _probe_once(ip: str, port: int, payload: bytes,
                timeout: float) -> tuple[str, object]:
    """One connected-UDP probe (blocking). Returns (outcome, extra).

    outcome ∈ {'data','refused','timeout','error'};
    extra is the reply bytes for 'data', the errno for 'error', else None.

    The connected socket is what makes ICMP port-unreachable observable without
    raw sockets: the refusal surfaces as ConnectionResetError (Windows) /
    ConnectionRefusedError (Linux) on send() or recv().
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.send(payload)
        data = s.recv(4096)
        return ("data", data)
    except socket.timeout:
        return ("timeout", None)
    except (ConnectionResetError, ConnectionRefusedError):
        return ("refused", None)
    except OSError as e:
        return ("error", e.errno or 0)
    finally:
        try:
            s.close()
        except Exception:
            pass


class _Pacer:
    """Thread-safe launch pacer — caps the send cadence to 1/interval.

    interval<=0 means unthrottled. Used to keep retransmit rounds within the
    target host's measured ICMP budget so closed ports aren't suppressed into
    looking open|filtered.
    """

    def __init__(self, interval: float) -> None:
        self.interval = interval
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep = self._next - now if self._next > now else 0.0
            self._next = max(now, self._next) + self.interval
        if sleep > 0:
            time.sleep(sleep)


def _run_round(ip: str, ports: list[int], *, timeout: float, workers: int,
               pace_interval: float,
               progress=None) -> dict[int, tuple[str, object]]:
    """Probe every port in `ports` once. Returns {port: (outcome, extra)}."""
    pacer = _Pacer(pace_interval)
    results: dict[int, tuple[str, object]] = {}
    done = [0]
    total = len(ports)
    lock = threading.Lock()

    def work(port: int) -> None:
        pacer.wait()
        _, payload = udp_payloads.payload_for(port)
        res = _probe_once(ip, port, payload, timeout)
        with lock:
            results[port] = res
            done[0] += 1
            if progress and done[0] % 2000 == 0:
                progress(f"udp {ip}: {done[0]}/{total} probed")

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as pool:
        list(pool.map(work, ports))
    return results


def scan_udp(ip: str, ports: Optional[list[int]] = None, *,
             timeout: float = 1.2, retries: int = 2,
             workers: int = 256, deep: bool = True,
             progress=None) -> list[Port]:
    """Scan UDP ports on one host. Returns a Port for every probed port.

    Args:
      ports: list of UDP ports, or None for the full 1-65535 range.
      timeout: per-probe wait (seconds). 1.2s suits LAN + most Internet hosts.
      retries: retransmission rounds for silent ports (resolves rate-limited
               closed ports into honest 'closed'). 0 = single pass, fastest.
      workers: max concurrent probe threads.
      deep: also fire secondary security payloads (NTP monlist, etc.) at open
            ports to surface amplification / auth-bypass findings.
      progress: optional callable(str) for progress messages.
    """
    if ports is None:
        ports = ALL_UDP_PORTS
    if not ports:
        return []

    resolved: dict[int, Port] = {}
    unresolved = list(ports)
    host_emits_icmp = False
    pace_interval = 0.0   # round 0: go fast, bounded only by the thread pool

    for rnd in range(retries + 1):
        if not unresolved:
            break
        final = (rnd == retries)
        t0 = time.monotonic()
        outcomes = _run_round(ip, unresolved, timeout=timeout, workers=workers,
                              pace_interval=pace_interval, progress=progress)
        elapsed = max(1e-3, time.monotonic() - t0)

        refused_this_round = 0
        still_silent: list[int] = []
        for port, (outcome, extra) in outcomes.items():
            if outcome == "refused":
                refused_this_round += 1
                host_emits_icmp = True
            state, reason, retry = classify_outcome(
                outcome, errno=(extra if outcome == "error" else 0),
                final=final, host_emits_icmp=host_emits_icmp)
            if outcome == "timeout" and retry and not final:
                still_silent.append(port)
                continue
            port_obj = Port(number=port, protocol="udp",
                            state=state, state_reason=reason)
            if outcome == "data":
                _attach_intel(port_obj, port, extra)
            resolved[port] = port_obj

        unresolved = still_silent

        # ── Adaptive pacing for the NEXT round ───────────────────────────────
        # The host answered `refused_this_round` ports with ICMP in `elapsed`s —
        # that ratio IS its ICMP budget. Pace the retransmit so we never exceed
        # it; otherwise the host suppresses replies and closed ports masquerade
        # as open|filtered. No ICMP at all → stay fast (nothing to gain from
        # slowing a host that simply isn't talking).
        if host_emits_icmp and refused_this_round > 0:
            budget_pps = refused_this_round / elapsed
            pace_interval = min(1.0, max(0.002, 1.0 / budget_pps))
            log.debug("udp %s round %d: %d refused in %.2fs -> pace %.3fs/probe",
                      ip, rnd, refused_this_round, elapsed, pace_interval)
        if progress and unresolved:
            progress(f"udp {ip}: round {rnd + 1} done, "
                     f"{len(unresolved)} still silent")

    if deep:
        _deep_probes(ip, resolved, timeout=timeout)

    return sorted(resolved.values(), key=lambda p: p.number)


def _deep_probes(ip: str, resolved: dict[int, Port], *,
                 timeout: float) -> None:
    """Fire secondary security payloads at open ports (NTP monlist, etc.)."""
    for port, (proto, payload) in udp_payloads.SECONDARY_PAYLOADS.items():
        po = resolved.get(port)
        if po is None or po.state != "open":
            continue
        outcome, extra = _probe_once(ip, port, payload, timeout)
        if outcome == "data" and isinstance(extra, (bytes, bytearray)):
            intel = parse_udp_response(proto, bytes(extra))
            if intel:
                merged = dict(po.service_intel or {})
                merged[proto] = intel
                po.service_intel = merged


def _attach_intel(port_obj: Port, port: int, data: object) -> None:
    """Parse an open port's reply and attach service name + structured intel."""
    proto, _ = udp_payloads.payload_for(port)
    raw = bytes(data) if isinstance(data, (bytes, bytearray)) else b""
    intel = parse_udp_response(proto, raw)
    port_obj.service = None if proto == "unknown" else proto
    port_obj.service_intel = ({proto: intel} if proto != "unknown"
                              else {"udp": intel})
    if isinstance(intel, dict) and intel.get("finding"):
        port_obj.banner = str(intel["finding"])[:512]


def scan_udp_fast(ip: str, *, timeout: float = 1.2, retries: int = 2,
                  workers: int = 64, progress=None) -> list[Port]:
    """Curated high-value UDP triage (~40 ports with crafted payloads)."""
    return scan_udp(ip, udp_payloads.HIGH_VALUE_UDP_PORTS,
                    timeout=timeout, retries=retries, workers=workers,
                    deep=True, progress=progress)


def summarize_udp(ports: list[Port]) -> dict:
    """Collapse Port list into the legacy host.udp_services dict shape, keeping
    only ports that gave us real intel — back-compatible with existing output.
    """
    # Map new protocol labels back to keys the existing CLI/dashboard already
    # understands, so this stays a drop-in replacement.
    legacy = {"netbios-ns": "netbios"}
    out: dict = {}
    for p in ports:
        if p.state == "open" and p.service_intel:
            for proto, intel in p.service_intel.items():
                out[legacy.get(proto, proto)] = intel
    return out
