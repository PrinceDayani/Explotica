"""Raw-ICMP UDP scan — the high-accuracy 'turbo tier' (scapy + Npcap/root).

The connected-socket engine in ``udp_scan`` is the privilege-free default. This
module is the optional upgrade that closes its one accuracy gap, exactly the way
``syn_scan`` upgrades the TCP connect scan:

WHY IT EXISTS
-------------
The connected-socket trick learns a port's state from a *socket error*, and the
OS throws away the ICMP detail when it does that:

  * On **Windows every** ICMP unreachable collapses to ``WSAECONNRESET`` (10054),
    so an admin-prohibited port (ICMP 3/13 = *filtered*) is indistinguishable
    from a genuinely closed one (ICMP 3/3). It gets misreported as ``closed``.
  * A per-probe socket also closes on timeout, so a *late* ICMP — common under
    aggressive rate-limiting — is lost.

Reading ICMP straight off the wire with a persistent pcap sniffer fixes both:
we see the exact ICMP type/code (real ``filtered`` vs ``closed``) and we catch
ICMP that arrives after the matching send. It also decouples sending from
receiving, so we can fire faster (masscan-style) instead of one socket per probe.

Stays inert and import-safe when scapy/Npcap aren't present; callers fall back to
the connected-socket engine automatically.
"""

from __future__ import annotations

import logging
import os
import random
import time
from typing import Iterable, Optional

from ..core.models import Port
from . import udp_payloads
from .udp_parsers import parse_udp_response

log = logging.getLogger(__name__)


# ── Capability gate (mirrors syn_scan.syn_scan_available) ─────────────────────
def raw_udp_available() -> bool:
    """True when raw-socket UDP scanning is usable (root/admin + scapy)."""
    if os.name == "nt":
        # Windows needs Npcap; we don't probe for it here — let scapy try.
        try:
            import scapy.all  # noqa: F401
            return True
        except Exception:
            return False
    try:
        if os.geteuid() != 0:
            return False
    except AttributeError:
        return False
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


# ════════════════════════════════════════════════════════════════════════════
#  ICMP-code → state classifier  (the accuracy core — pure + testable)
# ════════════════════════════════════════════════════════════════════════════
# This is the whole reason raw mode is more accurate than connected sockets:
# we get to see the exact ICMP type/code and map it ourselves, instead of
# letting the OS flatten it into one errno. The canonical mapping (RFC 792 +
# nmap's interpretation):
#
#   type 3 (Destination Unreachable):
#       code 3  -> port unreachable      => CLOSED  (host alive, no service)
#       code 1  -> host unreachable      => filtered
#       code 2  -> protocol unreachable  => filtered
#       code 9  -> net admin-prohibited  => filtered
#       code 10 -> host admin-prohibited => filtered
#       code 13 -> comm admin-prohibited => filtered  (a firewall said no)
#       other                            => filtered  (conservative)
#   any other ICMP type                  => filtered
#
# The one judgement call: code 3 is the ONLY code that proves "closed". Every
# other unreachable means *something* blocked us — that's "filtered", not
# "closed". Conflating them (as Windows' 10054 does) is the bug we're fixing.
def icmp_unreachable_state(icmp_type: int, icmp_code: int) -> tuple[str, str]:
    """Map an ICMPv4 (type, code) to (port_state, reason)."""
    if icmp_type == 3:
        if icmp_code == 3:
            return ("closed", "ICMP port-unreachable (3/3)")
        labels = {1: "host-unreachable", 2: "protocol-unreachable",
                  9: "net-admin-prohibited", 10: "host-admin-prohibited",
                  13: "comm-admin-prohibited"}
        return ("filtered",
                f"ICMP {labels.get(icmp_code, 'unreachable')} (3/{icmp_code})")
    return ("filtered", f"ICMP type {icmp_type}")


def icmpv6_unreachable_state(icmp_code: int) -> tuple[str, str]:
    """Map an ICMPv6 Destination-Unreachable code (type 1) to (state, reason).

    RFC 4443: code 4 = port unreachable = CLOSED; every other code (no route,
    admin prohibited, address unreachable, …) = filtered.
    """
    if icmp_code == 4:
        return ("closed", "ICMPv6 port-unreachable (1/4)")
    labels = {0: "no-route", 1: "admin-prohibited", 2: "beyond-scope",
              3: "address-unreachable", 5: "src-addr-policy", 6: "reject-route"}
    return ("filtered",
            f"ICMPv6 {labels.get(icmp_code, 'unreachable')} (1/{icmp_code})")
# ════════════════════════════════════════════════════════════════════════════


def raw_udp_scan(targets: Iterable[str], ports: list[int], *,
                 timeout: float = 4.0, rate_pps: int = 1500,
                 retries: int = 1, evasion=None,
                 progress=None) -> dict[str, list[Port]]:
    """Stateless raw UDP scan of many hosts × many ports.

    Fires UDP probes (protocol-correct payloads) while a background sniffer
    catches UDP replies (=> open) and ICMP unreachables (=> closed/filtered by
    code). Ports with no response are open|filtered. Returns {ip: [Port, ...]}.

    Falls back to an empty dict (caller should use the connected-socket engine)
    when raw scanning isn't available.
    """
    targets = list(dict.fromkeys(targets))
    ports = list(ports)
    if not raw_udp_available():
        log.warning("raw UDP scan requires root/admin + scapy — not available")
        return {}
    if not targets or not ports:
        return {ip: [] for ip in targets}

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy").setLevel(logging.ERROR)
    from scapy.all import IP, IPv6, UDP, Raw, AsyncSniffer, send, conf  # noqa
    conf.verb = 0

    target_set = set(targets)
    port_set = set(ports)
    has_v6 = any(":" in ip for ip in targets)
    # State table: default everything to open|filtered; replies overwrite it.
    states: dict[tuple[str, int], tuple[str, str]] = {
        (ip, p): ("open|filtered", "no response") for ip in targets for p in ports
    }
    reply_bytes: dict[tuple[str, int], bytes] = {}

    def on_pkt(pkt) -> None:
        try:
            _handle_packet(pkt, target_set, port_set, states, reply_bytes)
        except Exception:
            pass

    # icmp6 added to the BPF so ICMPv6 port-unreachables are captured too.
    bpf = "icmp or icmp6 or udp" if has_v6 else "icmp or udp"
    sniffer = AsyncSniffer(filter=bpf, store=False, prn=on_pkt)
    sniffer.start()

    # Evasion knobs (raw tier can do all four).
    ev_srcport = getattr(evasion, "source_port", None)
    ev_datalen = getattr(evasion, "data_length", 0) or 0
    ev_decoys = tuple(getattr(evasion, "decoys", ()) or ())
    ev_fragment = bool(getattr(evasion, "fragment", False))
    if ev_decoys or ev_fragment:
        try:
            from scapy.all import fragment as _fragment  # noqa
        except Exception:
            _fragment = None
    else:
        _fragment = None

    src_port = ev_srcport or random.randint(20000, 60000)
    inter = 1.0 / rate_pps if rate_pps > 0 else 0.0
    sent = 0
    total = len(targets) * len(ports) * max(1, retries)

    def _emit(l3, p, payload):
        pkt = l3 / UDP(sport=src_port, dport=p) / Raw(load=payload)
        if ev_fragment and _fragment is not None and ":" not in l3.dst:
            for frag in _fragment(pkt, fragsize=8):
                send(frag, verbose=False)
        else:
            send(pkt, verbose=False)

    for _ in range(max(1, retries)):
        for ip in targets:
            l3 = IPv6(dst=ip) if ":" in ip else IP(dst=ip)
            for p in ports:
                _, payload = udp_payloads.payload_for(p)
                if ev_datalen > 0:
                    payload = payload + os.urandom(ev_datalen)
                try:
                    # Decoys first: spoofed-source packets interleaved with ours
                    # so the target can't tell which source is the real scanner.
                    for decoy in ev_decoys:
                        try:
                            d3 = IPv6(src=decoy, dst=ip) if ":" in ip \
                                else IP(src=decoy, dst=ip)
                            send(d3 / UDP(sport=src_port, dport=p)
                                 / Raw(load=payload), verbose=False)
                        except Exception:
                            pass
                    _emit(l3, p, payload)
                except Exception as e:
                    log.debug("raw udp send %s:%d failed: %s", ip, p, e)
                sent += 1
                if progress and sent % 2000 == 0:
                    progress(f"raw-udp: sent {sent}/{total}")
                if inter:
                    time.sleep(inter)

    # Drain: wait for late ICMP / replies after the last send.
    time.sleep(timeout)
    sniffer.stop()

    out: dict[str, list[Port]] = {ip: [] for ip in targets}
    for (ip, p), (state, reason) in states.items():
        po = Port(number=p, protocol="udp", state=state, state_reason=reason)
        if state == "open":
            _attach_intel(po, p, reply_bytes.get((ip, p), b""))
        out[ip].append(po)
    for ip in out:
        out[ip].sort(key=lambda x: x.number)
    return out


def _handle_packet(pkt, target_set, port_set, states, reply_bytes) -> None:
    """Sniffer callback body — split out so it stays unit-reviewable.

    Handles four reply shapes: UDP reply (v4/v6) => open, ICMPv4 unreachable and
    ICMPv6 destination-unreachable => closed/filtered by code.
    """
    # A UDP reply from a target's service port == that port is OPEN.
    if (pkt.haslayer("UDP")
            and not pkt.haslayer("ICMP")
            and not pkt.haslayer("ICMPv6DestUnreach")):
        src = pkt["IPv6"].src if pkt.haslayer("IPv6") else (
            pkt["IP"].src if pkt.haslayer("IP") else None)
        if src is None:
            return
        sport = int(pkt["UDP"].sport)
        if src in target_set and sport in port_set:
            key = (src, sport)
            states[key] = ("open", "udp reply received")
            try:
                reply_bytes[key] = bytes(pkt["UDP"].payload)
            except Exception:
                pass
        return
    # ICMPv4 unreachable — quoted inner packet is IPerror / UDPerror.
    if pkt.haslayer("ICMP"):
        icmp = pkt["ICMP"]
        if int(icmp.type) == 3 and pkt.haslayer("IPerror") \
                and pkt.haslayer("UDPerror"):
            key = (pkt["IPerror"].dst, int(pkt["UDPerror"].dport))
            _record_unreachable(states, target_set, port_set, key,
                                icmp_unreachable_state(int(icmp.type),
                                                       int(icmp.code)))
        return
    # ICMPv6 destination-unreachable — quoted inner is IPerror6 / UDPerror.
    if pkt.haslayer("ICMPv6DestUnreach"):
        code = int(pkt["ICMPv6DestUnreach"].code)
        if pkt.haslayer("IPerror6") and pkt.haslayer("UDPerror"):
            key = (pkt["IPerror6"].dst, int(pkt["UDPerror"].dport))
            _record_unreachable(states, target_set, port_set, key,
                                icmpv6_unreachable_state(code))


def _record_unreachable(states, target_set, port_set, key, verdict) -> None:
    """Apply an ICMP-derived verdict, never overwriting a confirmed-open port."""
    if key[0] in target_set and key[1] in port_set:
        if states.get(key, (None,))[0] != "open":
            states[key] = verdict


def _attach_intel(port_obj: Port, port: int, data: bytes) -> None:
    """Parse an open port's reply and attach service name + structured intel."""
    proto, _ = udp_payloads.payload_for(port)
    intel = parse_udp_response(proto, data or b"")
    port_obj.service = None if proto == "unknown" else proto
    port_obj.service_intel = ({proto: intel} if proto != "unknown"
                              else {"udp": intel})
    if isinstance(intel, dict) and intel.get("finding"):
        port_obj.banner = str(intel["finding"])[:512]
