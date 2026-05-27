"""Host discovery — Layer 2 (ARP) on LANs, Layer 3 (ICMP) for routed targets."""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from typing import Iterable

from .models import Host

log = logging.getLogger(__name__)


def _import_scapy():
    """Lazy import — scapy is heavy and may not be installed on dev box."""
    try:
        # Silence scapy's runtime WARNING channel BEFORE importing — otherwise
        # the L2 MAC-resolution fallback messages drown out scan output.
        import logging as _logging
        _logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)
        _logging.getLogger("scapy").setLevel(_logging.ERROR)

        from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, conf
        conf.verb = 0
        return {"ARP": ARP, "Ether": Ether, "srp": srp,
                "IP": IP, "ICMP": ICMP, "sr1": sr1}
    except ImportError as e:
        raise RuntimeError(
            "scapy is required. Install: pip install -r requirements.txt"
        ) from e


def expand_targets(target: str) -> list[str]:
    """Accept CIDR ('192.168.1.0/24'), range, or single IP. Return list of IPs."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError:
        return [target]


def arp_scan(cidr: str, timeout: float = 2.0) -> list[Host]:
    """ARP sweep — fastest LAN discovery. Returns (ip, mac) pairs.

    Requires Administrator + Npcap on Windows. Raises if scapy not available.
    """
    s = _import_scapy()
    pkt = s["Ether"](dst="ff:ff:ff:ff:ff:ff") / s["ARP"](pdst=cidr)
    start = time.perf_counter()
    answered, _ = s["srp"](pkt, timeout=timeout, verbose=False)
    elapsed_ms = (time.perf_counter() - start) * 1000

    hosts: list[Host] = []
    for _, recv in answered:
        hosts.append(Host(
            ip=recv.psrc,
            mac=recv.hwsrc.lower(),
            is_up=True,
            response_ms=round(elapsed_ms, 1),
        ))
    log.info("ARP scan: %d host(s) on %s", len(hosts), cidr)
    return hosts


def icmp_ping(ip: str, timeout: float = 1.0) -> Host | None:
    """Single ICMP echo. Returns Host (with TTL) if alive, else None."""
    s = _import_scapy()
    pkt = s["IP"](dst=ip) / s["ICMP"]()
    start = time.perf_counter()
    reply = s["sr1"](pkt, timeout=timeout, verbose=False)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if reply is not None:
        ttl = int(reply.ttl) if hasattr(reply, "ttl") else None
        h = Host(ip=ip, is_up=True, response_ms=round(elapsed_ms, 1))
        h.ttl = ttl
        return h
    return None


def quick_ttl(ip: str, timeout: float = 0.5) -> int | None:
    """Cheap single ICMP echo just to grab TTL. Returns None on no response."""
    try:
        s = _import_scapy()
    except RuntimeError:
        return None
    try:
        pkt = s["IP"](dst=ip) / s["ICMP"]()
        reply = s["sr1"](pkt, timeout=timeout, verbose=False)
        if reply is not None and hasattr(reply, "ttl"):
            return int(reply.ttl)
    except Exception:
        pass
    return None


def icmp_sweep(targets: Iterable[str], timeout: float = 1.0,
               workers: int = 64) -> list[Host]:
    """Concurrent ICMP sweep for routed/Layer-3 ranges where ARP can't reach."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    found: list[Host] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(icmp_ping, ip, timeout): ip for ip in targets}
        for f in as_completed(futs):
            h = f.result()
            if h:
                found.append(h)
    return found


def resolve_hostname(ip: str, timeout: float = 1.0) -> str | None:
    """Reverse DNS — best-effort, returns None on failure."""
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(None)
