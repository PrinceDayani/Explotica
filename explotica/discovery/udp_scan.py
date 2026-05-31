"""Adaptive UDP scan engine — multi-host scheduler, RTT-aware, no admin needed.

What makes this state-of-the-art rather than "a working UDP scanner":

1. **Connected-socket state detection, zero privileges.** A ``connect()``-ed UDP
   socket surfaces the target's ICMP port-unreachable as a *socket error* on the
   next operation — ``ECONNREFUSED`` on Linux, ``WSAECONNRESET`` (10054) on
   Windows. So we get open / closed / open|filtered cross-platform, **without
   raw sockets or admin**. nmap needs Npcap/root to read ICMP; we don't.

2. **Multi-host scheduling (the throughput win).** UDP is bottlenecked by each
   target's ICMP rate limit (~1 closed-confirm/sec). A per-host scanner spends
   that budget one host at a time and idles the rest. This engine schedules a
   *pool* of (host, port) targets: each host carries its own token bucket, and a
   feeder hands ready targets — those whose host has a token right now — to a
   shared worker pool. While host A is throttled, the workers drain hosts B–Z.
   On a /24 that's a 50–250x wall-clock win over sequential per-host scans.

3. **Per-host RTT/RTO timing (RFC 6298).** Instead of a fixed timeout we measure
   round-trip time from the replies each host gives us and set that host's probe
   timeout to SRTT + 4·RTTVAR (clamped). Snappy on LAN, patient on far hosts.

4. **Protocol-correct payloads** (``udp_payloads``) so open ports actually
   answer, + **rich parsers** (``udp_parsers``) so we report intel + security
   findings, not just "open".

Output: ``Port`` objects (protocol="udp"). ``scan_udp`` returns a list for one
host; ``scan_udp_multi`` returns ``{ip: [Port, ...]}`` for many — both share the
same scheduler core.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, Optional

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


# ── Per-host RTT estimator + rate budget ──────────────────────────────────────
class HostState:
    """Per-host scheduling state: ICMP-rate budget + RFC-6298 RTT estimator.

    The RTT estimator is what lets us pick a per-host timeout instead of a fixed
    one. ``rate`` is the host's measured ICMP budget (packets/sec) used to pace
    retransmit rounds; ``None`` means "no throttle" (host hasn't shown a limit).
    """

    def __init__(self, ip: str, min_rto: float, max_rto: float,
                 default_timeout: float) -> None:
        self.ip = ip
        self.min_rto = min_rto
        self.max_rto = max_rto
        self.default_timeout = default_timeout
        self.srtt: Optional[float] = None
        self.rttvar: Optional[float] = None
        self.rto: float = default_timeout
        self.rate: Optional[float] = None       # pps budget; None = unthrottled
        self.host_emits_icmp = False
        self.resolved: dict[int, Port] = {}
        self._lock = threading.Lock()

    def observe_rtt(self, sample: float) -> None:
        """Fold an RTT sample into SRTT/RTTVAR and recompute RTO (RFC 6298)."""
        with self._lock:
            if self.srtt is None:
                self.srtt = sample
                self.rttvar = sample / 2.0
            else:
                self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
                self.srtt = 0.875 * self.srtt + 0.125 * sample
            rto = self.srtt + 4.0 * self.rttvar
            self.rto = max(self.min_rto, min(self.max_rto, rto))

    def current_timeout(self) -> float:
        # Until we have an RTT sample, use the conservative default.
        return self.rto if self.srtt is not None else self.default_timeout


class _TokenBucket:
    """Thread-safe token bucket. rate<=0 (or None) means unlimited."""

    def __init__(self, rate: Optional[float]) -> None:
        self.rate = rate or 0.0
        self.tokens = float("inf") if self.rate <= 0 else self.rate
        self.last = time.monotonic()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        if self.rate <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.rate, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


# ── Single connected-UDP probe ────────────────────────────────────────────────
def _probe_once(ip: str, port: int, payload: bytes,
                timeout: float) -> tuple[str, object, Optional[float]]:
    """One connected-UDP probe (blocking). Returns (outcome, extra, rtt).

    outcome ∈ {'data','refused','timeout','error'}; extra is reply bytes for
    'data', errno for 'error', else None; rtt is the measured round-trip in
    seconds when a reply (data OR ICMP refusal) came back, else None.

    The connected socket is what makes ICMP port-unreachable observable without
    raw sockets: the refusal surfaces as ConnectionResetError (Windows) /
    ConnectionRefusedError (Linux) on send() or recv().
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.monotonic()
    try:
        s.connect((ip, port))
        s.send(payload)
        data = s.recv(4096)
        return ("data", data, time.monotonic() - t0)
    except socket.timeout:
        return ("timeout", None, None)
    except (ConnectionResetError, ConnectionRefusedError):
        return ("refused", None, time.monotonic() - t0)
    except OSError as e:
        return ("error", e.errno or 0, None)
    finally:
        try:
            s.close()
        except Exception:
            pass


# ── The scheduler: one paced round across MANY hosts ──────────────────────────
def _run_round(states: dict[str, HostState],
               round_targets: dict[str, list[int]], *,
               workers: int, global_rate: float,
               progress: Optional[Callable[[str], None]],
               done_counter: list, total: int
               ) -> list[tuple[str, int, str, object, Optional[float]]]:
    """Probe every (host, port) in `round_targets` once, interleaved across hosts.

    Each host is paced by its own token bucket (``HostState.rate``); a global
    bucket optionally caps aggregate pps. A single feeder (this thread) submits
    ready targets to a shared worker pool, so a throttled host never stalls the
    others. Returns a flat list of (ip, port, outcome, extra, rtt).
    """
    queues: dict[str, deque] = {
        ip: deque(ports) for ip, ports in round_targets.items() if ports
    }
    host_buckets = {ip: _TokenBucket(states[ip].rate) for ip in queues}
    global_bucket = _TokenBucket(global_rate)
    slots = threading.Semaphore(workers)
    results: list = []
    results_lock = threading.Lock()

    def task(ip: str, port: int) -> None:
        try:
            _, payload = udp_payloads.payload_for(port)
            outcome, extra, rtt = _probe_once(
                ip, port, payload, states[ip].current_timeout())
            with results_lock:
                results.append((ip, port, outcome, extra, rtt))
                done_counter[0] += 1
                if progress and done_counter[0] % 2000 == 0:
                    progress(f"udp: {done_counter[0]}/{total} probed")
        finally:
            slots.release()

    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        # Feeder loop: round-robin hosts, submit a target only when its host has
        # a token AND the global cap allows AND a worker slot is free.
        while any(queues[ip] for ip in queues):
            progressed = False
            for ip in list(queues):
                q = queues[ip]
                if not q:
                    continue
                if not global_bucket.try_acquire():
                    break                              # global cap hit this tick
                if not host_buckets[ip].try_acquire():
                    continue                           # this host is throttled
                if not slots.acquire(blocking=False):
                    # No free worker right now; we already took the tokens, so
                    # just wait for a slot rather than dropping the target.
                    slots.acquire()
                port = q.popleft()
                pool.submit(task, ip, port)
                progressed = True
            if not progressed:
                time.sleep(0.004)                      # everyone throttled/full
    finally:
        pool.shutdown(wait=True)
    return results


def _scan_core(ips: list[str], ports: list[int], *,
               retries: int, workers: int, deep: bool,
               default_timeout: float, min_rto: float, max_rto: float,
               max_rate: float,
               progress: Optional[Callable[[str], None]]
               ) -> dict[str, list[Port]]:
    """Shared scheduler core for both scan_udp and scan_udp_multi."""
    states = {ip: HostState(ip, min_rto, max_rto, default_timeout) for ip in ips}
    # Round 0: probe every port on every host. Later rounds: only silent ports.
    pending: dict[str, list[int]] = {ip: list(ports) for ip in ips}
    total = len(ips) * len(ports)
    done_counter = [0]

    for rnd in range(retries + 1):
        active = {ip: p for ip, p in pending.items() if p}
        if not active:
            break
        final = (rnd == retries)
        t0 = time.monotonic()
        round_results = _run_round(
            states, active, workers=workers, global_rate=max_rate,
            progress=progress, done_counter=done_counter, total=total)
        elapsed = max(1e-3, time.monotonic() - t0)

        refused_per_host: dict[str, int] = {ip: 0 for ip in active}
        next_silent: dict[str, list[int]] = {ip: [] for ip in active}
        for ip, port, outcome, extra, rtt in round_results:
            hs = states[ip]
            if rtt is not None:
                hs.observe_rtt(rtt)
            if outcome == "refused":
                refused_per_host[ip] += 1
                hs.host_emits_icmp = True
            state, reason, retry = classify_outcome(
                outcome, errno=(extra if outcome == "error" else 0),
                final=final, host_emits_icmp=hs.host_emits_icmp)
            if outcome == "timeout" and retry and not final:
                next_silent[ip].append(port)
                continue
            port_obj = Port(number=port, protocol="udp",
                            state=state, state_reason=reason)
            if outcome == "data":
                _attach_intel(port_obj, port, extra)
            hs.resolved[port] = port_obj

        # ── Adapt each host's pacing for the next round ──────────────────────
        # A host that answered N ports with ICMP in `elapsed`s has budget ≈ N/elapsed.
        # Pace its retransmits to that, so closed ports aren't suppressed into
        # looking open|filtered. Hosts that never sent ICMP stay unthrottled.
        for ip in active:
            n = refused_per_host[ip]
            if states[ip].host_emits_icmp and n > 0:
                budget_pps = n / elapsed
                states[ip].rate = min(500.0, max(0.5, budget_pps))
            pending[ip] = next_silent[ip]

        if progress:
            remaining = sum(len(v) for v in pending.values())
            if remaining:
                progress(f"udp: round {rnd + 1} done, {remaining} still silent")

    if deep:
        _deep_probes_all(states, default_timeout)

    return {ip: sorted(hs.resolved.values(), key=lambda p: p.number)
            for ip, hs in states.items()}


def _deep_probes_all(states: dict[str, HostState], timeout: float) -> None:
    """Deep pass on open ports: secondary security payloads + second-hop
    enrichment chains (SNMP walk, SSDP device-XML fetch)."""
    for hs in states.values():
        # 1) Secondary security payloads (NTP monlist, etc.).
        for port, (proto, payload) in udp_payloads.SECONDARY_PAYLOADS.items():
            po = hs.resolved.get(port)
            if po is None or po.state != "open":
                continue
            outcome, extra, _ = _probe_once(hs.ip, port, payload, timeout)
            if outcome == "data" and isinstance(extra, (bytes, bytearray)):
                intel = parse_udp_response(proto, bytes(extra))
                if intel:
                    merged = dict(po.service_intel or {})
                    merged[proto] = intel
                    po.service_intel = merged
        # 2) Second-hop enrichment — the chains that beat nmap.
        try:
            from .udp_enrich import enrich_udp_ports
            enrich_udp_ports(hs.ip, list(hs.resolved.values()))
        except Exception as e:  # noqa: BLE001 — enrichment is best-effort
            log.debug("udp enrichment on %s failed: %s", hs.ip, e)


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


# ── Raw-ICMP turbo tier routing (Phase 71) ───────────────────────────────────
def _maybe_raw(ips: list[str], ports: list[int], *, prefer_raw: bool,
               timeout: float, retries: int, max_rate: float,
               progress) -> Optional[dict[str, list[Port]]]:
    """If raw mode is requested AND available, run it; else return None so the
    caller falls back to the privilege-free connected-socket engine."""
    if not prefer_raw:
        return None
    try:
        from .udp_scan_raw import raw_udp_available, raw_udp_scan
        if not raw_udp_available():
            log.info("prefer_raw set but raw scan unavailable (need scapy + "
                     "root/Npcap); using connected-socket engine")
            return None
        rate = int(max_rate) if max_rate and max_rate > 0 else 1500
        return raw_udp_scan(ips, ports, timeout=max(timeout, 3.0),
                            rate_pps=rate, retries=max(1, retries),
                            progress=progress)
    except Exception as e:  # noqa: BLE001 — never let raw path break the scan
        log.debug("raw udp path failed, falling back: %s", e)
        return None


# ── Public entry points ───────────────────────────────────────────────────────
def scan_udp(ip: str, ports: Optional[list[int]] = None, *,
             timeout: float = 1.2, retries: int = 2,
             workers: int = 256, deep: bool = True,
             min_rto: float = 0.25, max_rto: float = 3.0,
             max_rate: float = 0.0, prefer_raw: bool = False,
             progress=None) -> list[Port]:
    """Scan UDP ports on ONE host. Returns a Port for every probed port.

    Args:
      ports: list of UDP ports, or None for the full 1-65535 range.
      timeout: initial per-probe wait, before RTT is learned (seconds).
      retries: retransmission rounds for silent ports (resolves rate-limited
               closed ports into honest 'closed'). 0 = single pass, fastest.
      workers: max concurrent probe threads.
      deep: also fire secondary security payloads at open ports.
      min_rto/max_rto: clamp for the adaptive per-host timeout.
      max_rate: global packets/sec cap (0 = unlimited).
      progress: optional callable(str) for progress messages.
    """
    if ports is None:
        ports = ALL_UDP_PORTS
    if not ports:
        return []
    raw = _maybe_raw([ip], ports, prefer_raw=prefer_raw, timeout=timeout,
                     retries=retries, max_rate=max_rate, progress=progress)
    if raw is not None:
        return raw.get(ip, [])
    out = _scan_core([ip], ports, retries=retries, workers=workers, deep=deep,
                     default_timeout=timeout, min_rto=min_rto, max_rto=max_rto,
                     max_rate=max_rate, progress=progress)
    return out.get(ip, [])


def scan_udp_multi(ips: Iterable[str], ports: Optional[list[int]] = None, *,
                   timeout: float = 1.2, retries: int = 2,
                   workers: int = 512, deep: bool = True,
                   min_rto: float = 0.25, max_rto: float = 3.0,
                   max_rate: float = 0.0, prefer_raw: bool = False,
                   progress=None) -> dict[str, list[Port]]:
    """Scan UDP ports across MANY hosts, interleaved (the throughput path).

    Per-host ICMP rate limits overlap instead of serialize: while one host is
    throttled the shared worker pool drains the others. Returns {ip: [Port,...]}.

    prefer_raw routes to the raw-ICMP turbo tier when scapy + root/Npcap are
    available (true filtered vs closed), else falls back transparently.
    """
    ip_list = list(dict.fromkeys(ips))      # de-dupe, preserve order
    if not ip_list:
        return {}
    if ports is None:
        ports = ALL_UDP_PORTS
    if not ports:
        return {ip: [] for ip in ip_list}
    raw = _maybe_raw(ip_list, ports, prefer_raw=prefer_raw, timeout=timeout,
                     retries=retries, max_rate=max_rate, progress=progress)
    if raw is not None:
        return raw
    return _scan_core(ip_list, ports, retries=retries, workers=workers,
                      deep=deep, default_timeout=timeout, min_rto=min_rto,
                      max_rto=max_rto, max_rate=max_rate, progress=progress)


def scan_udp_fast(ip: str, *, timeout: float = 1.2, retries: int = 2,
                  workers: int = 64, prefer_raw: bool = False,
                  progress=None) -> list[Port]:
    """Curated high-value UDP triage (~40 ports with crafted payloads)."""
    return scan_udp(ip, udp_payloads.HIGH_VALUE_UDP_PORTS,
                    timeout=timeout, retries=retries, workers=workers,
                    deep=True, prefer_raw=prefer_raw, progress=progress)


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
