"""Network-fabric intelligence: DHCP discovery + traceroute hop chains.

DHCP DISCOVER broadcast: reveals the DHCP server, offered IP, lease length,
DNS servers, NTP servers, domain name, gateway — all advertised in OFFER.

Traceroute: for each live host, learn the intermediate hops. Each hop is
a separate device (almost always a router) that could itself be scanned.
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Optional

log = logging.getLogger(__name__)


def _import_scapy():
    try:
        # Silence scapy WARNING-level logger before import
        import logging as _logging
        _logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)
        _logging.getLogger("scapy").setLevel(_logging.ERROR)
        from scapy.all import (Ether, IP, UDP, BOOTP, DHCP, srp1,
                                 traceroute as scapy_traceroute, conf, get_if_hwaddr)
        conf.verb = 0
        return {
            "Ether": Ether, "IP": IP, "UDP": UDP, "BOOTP": BOOTP, "DHCP": DHCP,
            "srp1": srp1, "traceroute": scapy_traceroute,
            "get_if_hwaddr": get_if_hwaddr,
        }
    except ImportError as e:
        raise RuntimeError("scapy required for netfabric") from e


# ── DHCP discovery ────────────────────────────────────────────────────────
def dhcp_discover(interface: Optional[str] = None,
                  timeout: float = 5.0) -> Optional[dict]:
    """Broadcast a DHCPDISCOVER and parse the first OFFER received.

    Returns the DHCP server's offered parameters: yiaddr (offered IP),
    siaddr (DHCP server), giaddr (gateway), and DHCP options 1, 3, 6,
    15, 51 (subnet mask, router, DNS, domain name, lease time).

    Requires root + raw socket capability.
    """
    s = _import_scapy()
    try:
        if interface:
            hwaddr = s["get_if_hwaddr"](interface)
        else:
            hwaddr = "00:11:22:33:44:55"  # fallback random
    except Exception:
        hwaddr = "00:11:22:33:44:55"
    chaddr_bytes = bytes.fromhex(hwaddr.replace(":", ""))

    pkt = (
        s["Ether"](dst="ff:ff:ff:ff:ff:ff", src=hwaddr) /
        s["IP"](src="0.0.0.0", dst="255.255.255.255") /
        s["UDP"](sport=68, dport=67) /
        s["BOOTP"](chaddr=chaddr_bytes, xid=0xabcdef00) /
        s["DHCP"](options=[("message-type", "discover"), "end"])
    )

    try:
        ans = s["srp1"](pkt, timeout=timeout, verbose=False, iface=interface)
    except Exception as e:
        log.debug("DHCP discover failed: %s", e)
        return None

    if ans is None:
        return None

    result: dict = {"responded": True}
    if ans.haslayer("BOOTP"):
        bootp = ans["BOOTP"]
        result["offered_ip"] = bootp.yiaddr
        result["server_ip"] = bootp.siaddr
        result["gateway_relay"] = bootp.giaddr

    if ans.haslayer("DHCP"):
        dhcp = ans["DHCP"]
        options = {}
        for opt in dhcp.options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                name, val = opt[0], opt[1:]
                val = val[0] if len(val) == 1 else val
                if isinstance(val, bytes):
                    try:
                        val = val.decode("ascii", errors="replace")
                    except Exception:
                        val = val.hex()
                options[str(name)] = val
        result["options"] = options
    return result


# ── Traceroute ────────────────────────────────────────────────────────────
def traceroute_to(target: str, max_hops: int = 20,
                  timeout: float = 2.0) -> Optional[list[dict]]:
    """Send ICMP echoes with increasing TTL, capture each hop IP."""
    s = _import_scapy()
    from scapy.all import IP, ICMP, sr1
    hops: list[dict] = []
    final_reached = False
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=False)
        if reply is None:
            hops.append({"ttl": ttl, "ip": None, "rtt_ms": None})
            continue
        # Capture src + RTT
        rtt = getattr(reply, "time", None)
        hops.append({
            "ttl": ttl,
            "ip": reply.src,
            "rtt_ms": round((reply.time - pkt.sent_time) * 1000, 2)
                if hasattr(reply, "time") and hasattr(pkt, "sent_time") else None,
        })
        if reply.src == target:
            final_reached = True
            break
    return hops


def traceroute_many(targets: list[str], max_hops: int = 12,
                    timeout: float = 1.0,
                    workers: int = 8) -> dict[str, list[dict]]:
    """Parallel traceroute across targets.

    Each target's TTL sweep runs in its own thread. max_hops capped to 12
    since most LANs have <5 hops and we want to bound worst-case latency.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    out: dict[str, list[dict]] = {}
    targets = targets[:20]  # cap target count

    def run(t):
        try:
            return (t, traceroute_to(t, max_hops=max_hops, timeout=timeout))
        except Exception as e:
            log.debug("traceroute %s failed: %s", t, e)
            return (t, None)

    with ThreadPoolExecutor(max_workers=min(workers, len(targets) or 1)) as pool:
        for f in as_completed([pool.submit(run, t) for t in targets]):
            t, hops = f.result()
            if hops:
                out[t] = hops
    return out
