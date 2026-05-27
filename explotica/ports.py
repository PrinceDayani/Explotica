"""TCP connect scanning — no raw sockets, no admin needed."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import Port

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 113, 135, 139, 143, 161, 199, 389,
    427, 443, 444, 445, 465, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
    1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,
    6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100,
    9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

COMMON_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "smb", 587: "smtp-submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


def probe_tcp(ip: str, port: int, timeout: float = 0.8) -> Port | None:
    """One-shot TCP connect. Returns Port if open, None if closed/filtered."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) == 0:
            return Port(
                number=port,
                protocol="tcp",
                state="open",
                service=COMMON_SERVICE_NAMES.get(port),
            )
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def scan_ports(ip: str, ports: list[int] | None = None,
               timeout: float = 0.8, workers: int = 200) -> list[Port]:
    """Scan many ports on one host in parallel. Returns only OPEN ports."""
    ports = ports or TOP_100_PORTS
    found: list[Port] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe_tcp, ip, p, timeout): p for p in ports}
        for f in as_completed(futs):
            res = f.result()
            if res is not None:
                found.append(res)
    found.sort(key=lambda p: p.number)
    return found
