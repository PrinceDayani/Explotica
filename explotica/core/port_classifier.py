"""Port classifier — single source of truth for "what kind of service is this?"

Phase 57 motivation: 5 different modules (banners.py, scanner.py, aio.py,
web_fuzz.py, and several enrichment modules) each had their own HTTP_PORTS
/ HTTPS_PORTS / TLS_PORTS / SMB_PORTS sets, all with different members.
The same port (e.g. 8000) was treated as HTTP by one module and as
"unknown" by another, producing inconsistent enrichment.

Single primitives, used everywhere:
    is_http(port)         — speaks HTTP (plaintext)
    is_https(port)        — speaks HTTP over TLS
    is_http_like(port)    — either of the above
    is_tls(port)          — does TLS (HTTPS, SMTPS, IMAPS, LDAPS, ...)
    is_smb(port)          — Microsoft SMB
    is_dns(port)
    is_database(port)
    is_remote_admin(port) — SSH / RDP / VNC / WinRM / Telnet

Critical design: every primitive takes a `Port` object (not a port number).
This lets us combine TWO sources of truth:
  1. Port NUMBER — IANA / common-deployment hint
  2. Port.service — what the banner CONTENT identified (Phase 56 evidence)

The content evidence ALWAYS wins. SSH on port 80 → is_http() returns False.
HTTP on port 31337 → is_http() returns True. This eliminates the
"port-number-keyed bias" the user identified.
"""

from __future__ import annotations

from typing import Union

from .models import Port


# ── Port-number hint sets (UNIFIED — replaces the 4+ scattered copies) ─
# These are the SAME sets that used to live in banners.py / scanner.py /
# aio.py / web_fuzz.py — now they live in ONE place.
# Comprehensive coverage based on nmap-services + common deployment patterns.

HTTP_HINT_PORTS = frozenset({
    80, 81, 280, 591, 593, 631, 808, 1080, 2080, 2480, 3000, 3030, 3128,
    3333, 4000, 4080, 4567, 4848, 5000, 5050, 5080, 6000, 6080, 6660,
    7000, 7080, 7547, 8000, 8001, 8008, 8042, 8060, 8080, 8081, 8082,
    8083, 8086, 8087, 8088, 8089, 8090, 8118, 8123, 8181, 8200, 8222,
    8333, 8400, 8500, 8530, 8800, 8866, 8880, 8888, 8983, 9000, 9001,
    9050, 9080, 9090, 9091, 9092, 9200, 9300, 9418, 9500, 9800, 9900,
    9999, 10000, 11371, 15672, 16080, 17988, 28017, 50000, 55672, 60000,
})

# TLS-by-default ports (TLS terminates here; some serve HTTPS, others serve
# IMAPS / LDAPS / POP3S / SMTPS / FTPS / RDP-TLS / etc.)
TLS_HINT_PORTS = frozenset({
    443, 444, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 1311,
    2083, 2087, 2096, 2484, 3269, 3389, 4443, 5061, 5223, 5269, 5986,
    6443, 6679, 6697, 8243, 8443, 8531, 8883, 9090, 9091, 9443, 10443,
    11214, 11215, 16993, 18091, 18092, 27443, 31415,
})

HTTPS_HINT_PORTS = frozenset({
    443, 2083, 2087, 2096, 4443, 6443, 8243, 8443, 8531, 9443, 10443,
    16993, 18091, 18092, 31415,
})

SMB_HINT_PORTS = frozenset({139, 445})
DNS_HINT_PORTS = frozenset({53, 853, 5353, 5355})
DATABASE_HINT_PORTS = frozenset({
    1433, 1434,  # MSSQL
    1521,  # Oracle
    3050,  # Interbase
    3306,  # MySQL/MariaDB
    5432,  # PostgreSQL
    6379,  # Redis
    7000, 7001, 9042, 9160, 9300, 9200,  # Cassandra / Elasticsearch
    11211, 11214, 11215,  # Memcached
    27017, 27018, 27019, 28017,  # MongoDB
    2483, 2484,  # Oracle TNS
    7474, 7687,  # Neo4j
    8086, 8087,  # InfluxDB
    8123, 9000,  # ClickHouse
    8983,  # Solr
    9092,  # Kafka
})

REMOTE_ADMIN_PORTS = frozenset({
    22,    # SSH
    23,    # Telnet
    3389,  # RDP
    5900, 5901, 5902, 5903, 5800,  # VNC
    5985, 5986,  # WinRM
    2222,  # Common alt-SSH
    902,   # VMware
    4444, 4899,  # Radmin / pcAnywhere
    10250, 10255,  # Kubelet
})

EMAIL_PORTS = frozenset({25, 465, 587, 110, 995, 143, 993})

# Content-based service names that count as HTTP/HTTPS for cascade routing.
HTTP_SERVICE_NAMES = frozenset({"http", "http-alt", "http-proxy", "https"})
TLS_SERVICE_NAMES = frozenset({"https", "tls", "ssl", "imaps", "pop3s",
                                 "smtps", "ftps", "ldaps"})


# ── Helpers — accept Port object OR raw int (back-compat) ─────────────
def _port_number(port: Union[Port, int]) -> int:
    """Accept either a Port object or a raw int — eases gradual migration."""
    if isinstance(port, int):
        return port
    return port.number


def _port_service(port: Union[Port, int]) -> str:
    """Service name from Port object (content-evidenced); empty if just int.
    iana_guess=True entries are NOT trusted as evidence — only banner/fp."""
    if isinstance(port, int):
        return ""
    if getattr(port, "iana_guess", False):
        return ""
    return port.service or ""


# ── Public classifier primitives ──────────────────────────────────────
def is_http(port: Union[Port, int]) -> bool:
    """True if this port speaks plaintext HTTP. Content wins over hints."""
    svc = _port_service(port)
    if svc in HTTP_SERVICE_NAMES and svc != "https":
        return True
    if svc and svc != "http":
        return False  # we KNOW it's something else (e.g. SSH on 80)
    return _port_number(port) in HTTP_HINT_PORTS


def is_https(port: Union[Port, int]) -> bool:
    """True if this port speaks HTTP over TLS."""
    svc = _port_service(port)
    if svc == "https":
        return True
    if svc and svc != "https":
        return False
    return _port_number(port) in HTTPS_HINT_PORTS


def is_http_like(port: Union[Port, int]) -> bool:
    """HTTP OR HTTPS — for callers that crawl/audit either flavor."""
    return is_http(port) or is_https(port)


def is_tls(port: Union[Port, int]) -> bool:
    """True if this port terminates TLS (HTTPS, IMAPS, LDAPS, SMTPS, etc.)."""
    svc = _port_service(port)
    if svc in TLS_SERVICE_NAMES:
        return True
    return _port_number(port) in TLS_HINT_PORTS


def is_smb(port: Union[Port, int]) -> bool:
    svc = _port_service(port)
    if svc in ("smb", "netbios-ssn", "microsoft-ds"):
        return True
    return _port_number(port) in SMB_HINT_PORTS


def is_dns(port: Union[Port, int]) -> bool:
    svc = _port_service(port)
    if svc in ("dns", "domain", "mdns", "llmnr"):
        return True
    return _port_number(port) in DNS_HINT_PORTS


def is_database(port: Union[Port, int]) -> bool:
    svc = _port_service(port)
    if svc in ("mysql", "postgres", "postgresql", "mssql", "oracle",
                "mongodb", "redis", "elasticsearch", "cassandra", "memcached",
                "couchdb", "influxdb", "clickhouse", "neo4j"):
        return True
    return _port_number(port) in DATABASE_HINT_PORTS


def is_remote_admin(port: Union[Port, int]) -> bool:
    svc = _port_service(port)
    if svc in ("ssh", "telnet", "rdp", "vnc", "winrm"):
        return True
    return _port_number(port) in REMOTE_ADMIN_PORTS


def is_email(port: Union[Port, int]) -> bool:
    svc = _port_service(port)
    if svc in ("smtp", "smtps", "smtp-submission",
                "pop3", "pop3s", "imap", "imaps"):
        return True
    return _port_number(port) in EMAIL_PORTS


# ── Convenience for "is this port worth talking to" ────────────────────
def is_open(port: Union[Port, int]) -> bool:
    """True if the Port object has state=='open'. Accepts int for back-compat
    (returns True — assumes the caller already filtered)."""
    if isinstance(port, int):
        return True
    return port.state == "open"
