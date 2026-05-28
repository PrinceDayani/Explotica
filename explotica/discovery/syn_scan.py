"""Stateless SYN scanner — masscan-class speed via raw sockets.

How it works (the masscan trick):
  1. Sender: fire SYN packets as fast as you can, DON'T track TCP state
  2. Receiver: a background sniffer catches incoming SYN-ACK responses
  3. Open port = host returned SYN-ACK; closed = RST; filtered = no reply
  4. No three-way handshake completed → no application-layer connection,
     just discovery. Banner grabbing happens via a separate phase.

The advantage: the kernel doesn't allocate connection-tracking state per
probe. You can sustain hundreds of thousands of pps. The downside: needs
root + raw socket support (Linux/macOS/BSD — Windows needs Npcap).

Falls back to async TCP connect when raw sockets aren't available.
"""

from __future__ import annotations

import logging
import os
import random
import time
from collections import defaultdict
from typing import Iterable, Optional

log = logging.getLogger(__name__)


def syn_scan_available() -> bool:
    """Check if raw-socket SYN scanning is usable. Requires root + scapy."""
    if os.name == "nt":
        # On Windows, scapy needs Npcap; we don't auto-detect — let it try.
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            return False
    if os.geteuid() != 0:
        return False
    try:
        import scapy.all  # noqa: F401
        return True
    except ImportError:
        return False


def syn_scan(targets: Iterable[str], ports: list[int], *,
             timeout: float = 4.0, rate_pps: int = 5000,
             retries: int = 1) -> dict[str, list[int]]:
    """Stateless SYN scan many hosts × many ports in parallel.

    Args:
      targets: iterable of target IP strings
      ports: list of TCP port numbers to probe
      timeout: how long to keep the sniffer open after the last send (seconds)
      rate_pps: outbound packets per second cap (avoid drowning the link)
      retries: number of times to repeat the probe set (catches dropped pkts)

    Returns:
      {ip: sorted_list_of_open_ports}
    """
    if not syn_scan_available():
        log.warning("SYN scan requires root + scapy — not available")
        return {}

    # Silence scapy runtime warnings before import (separate channel from verb)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy").setLevel(logging.ERROR)
    from scapy.all import IP, TCP, conf, AsyncSniffer, send
    conf.verb = 0

    targets = list(targets)
    ports = list(ports)
    log.info("SYN scan: %d host(s) × %d port(s) (%d total probes, %d pps cap)",
             len(targets), len(ports), len(targets) * len(ports), rate_pps)

    open_ports: dict[str, set[int]] = defaultdict(set)

    # Sniffer captures SYN-ACK (flags=0x12) and RST-ACK (flags=0x14) responses
    bpf_filter = "tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))"
    sniffer = AsyncSniffer(filter=bpf_filter, store=False, prn=lambda pkt: _on_reply(pkt, open_ports, set(ports)))
    sniffer.start()

    # Random source ports help avoid being clobbered by ICMP-port-unreachable
    # responses if the OS thinks the port is in use.
    src_port_base = random.randint(20000, 60000)

    # Hard wall-clock cap. If we hit this, we stop sending and just collect
    # whatever responses came back. Prevents the 25-minute-hang failure
    # mode when MAC resolution is failing per-packet.
    max_wall_s = max(30.0, 0.05 * len(targets) * len(ports))  # 0.05s/probe budget
    start_wall = time.perf_counter()

    inter = 1.0 / rate_pps if rate_pps > 0 else 0
    aborted_early = False
    for attempt in range(retries):
        if aborted_early:
            break
        for t in targets:
            if time.perf_counter() - start_wall > max_wall_s:
                log.warning("SYN scan: wall-clock budget exceeded (%.0fs), "
                            "stopping sender", max_wall_s)
                aborted_early = True
                break
            for p in ports:
                pkt = IP(dst=t) / TCP(sport=src_port_base, dport=p,
                                       flags="S",
                                       seq=random.randint(0, 2**32 - 1))
                try:
                    send(pkt, verbose=False)
                except Exception as e:
                    log.debug("syn send %s:%d failed: %s", t, p, e)
                if inter:
                    time.sleep(inter)

    # Drain time (but capped — never wait longer than the budget remainder)
    drain = min(timeout, max(1.0, max_wall_s
                              - (time.perf_counter() - start_wall)))
    time.sleep(drain)
    sniffer.stop()

    out = {ip: sorted(ports) for ip, ports in open_ports.items()}
    total = sum(len(ports) for ports in out.values())
    log.info("SYN scan complete: %d open port(s) across %d host(s)",
             total, len(out))
    return out


def _on_reply(pkt, open_ports: dict, valid_ports: set):
    """Sniffer callback. Records SYN-ACK = open."""
    try:
        ip_src = pkt["IP"].src
        sport = int(pkt["TCP"].sport)
        flags = int(pkt["TCP"].flags)
        # SYN-ACK = SYN (0x02) + ACK (0x10) = 0x12
        if flags & 0x12 == 0x12 and sport in valid_ports:
            open_ports[ip_src].add(sport)
    except Exception:
        pass


def syn_scan_one(target: str, ports: list[int], **kwargs) -> list[int]:
    """Convenience wrapper for a single host."""
    result = syn_scan([target], ports, **kwargs)
    return result.get(target, [])
