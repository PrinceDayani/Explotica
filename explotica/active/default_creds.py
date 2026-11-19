"""Default credential testing — opt-in checks against known credentials.

EACH check sends EXACTLY ONE login attempt with a well-known default pair.
No brute force. No password spraying. Intended for authorized assessment
of internal infrastructure where default creds are a known finding type.

OPT-IN ONLY — gated by --check-default-creds flag because account
lockouts on production systems are a real concern.
"""

from __future__ import annotations

import base64
import logging
import socket
import ssl
import struct
from typing import Optional

log = logging.getLogger(__name__)


# ── FTP anonymous ─────────────────────────────────────────────────────────
def check_ftp_anonymous(host: str, port: int = 21,
                        timeout: float = 4.0) -> Optional[dict]:
    """Try anonymous FTP login. Returns dict on success."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        greeting = sock.recv(512)
        if not greeting.startswith(b"220"):
            sock.close()
            return None
        sock.sendall(b"USER anonymous\r\n")
        r1 = sock.recv(512)
        sock.sendall(b"PASS anonymous@\r\n")
        r2 = sock.recv(512)
        sock.sendall(b"QUIT\r\n")
        sock.close()
        if r2.startswith(b"230"):  # Login successful
            return {
                "service": "ftp",
                "credentials": "anonymous:anonymous@",
                "auth": "allowed",
                "severity": "HIGH",
                "note": "Anonymous FTP login permitted",
            }
    except (socket.timeout, OSError):
        pass
    return None


# ── HTTP Basic Auth common defaults ───────────────────────────────────────
HTTP_BASIC_DEFAULTS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("root", ""),
    ("administrator", "administrator"),
    ("guest", "guest"),
    ("user", "user"),
    ("test", "test"),
]


def check_http_basic(host: str, port: int, *, tls: bool = False,
                     path: str = "/", timeout: float = 4.0) -> Optional[dict]:
    """If the path requires HTTP Basic Auth, try common default credentials."""
    # First probe to see if auth is required
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(4096)
        sock.close()
    except (socket.timeout, OSError, ssl.SSLError):
        return None

    if b"401" not in data[:50] or b"WWW-Authenticate" not in data:
        return None
    if b"Basic" not in data:
        return None

    # 401 + Basic challenge — try defaults
    for user, pw in HTTP_BASIC_DEFAULTS:
        creds_b64 = base64.b64encode(f"{user}:{pw}".encode()).decode()
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if tls:
                ctx = ssl._create_unverified_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(
                f"GET {path} HTTP/1.0\r\n"
                f"Host: {host}\r\n"
                f"Authorization: Basic {creds_b64}\r\n\r\n".encode()
            )
            resp = sock.recv(2048)
            sock.close()
        except (socket.timeout, OSError, ssl.SSLError):
            continue
        first_line = resp.split(b"\r\n", 1)[0]
        if b"200" in first_line or b"302" in first_line or b"301" in first_line:
            return {
                "service": "http-basic",
                "path": path,
                "credentials": f"{user}:{pw}",
                "status_line": first_line.decode("ascii", "ignore"),
                "severity": "CRITICAL",
                "note": "HTTP Basic Auth accepts default credentials",
            }
    return None


# ── MySQL ─────────────────────────────────────────────────────────────────
def check_mysql_empty_root(host: str, port: int = 3306,
                           timeout: float = 4.0,
                           users=("root", "mysql")) -> Optional[dict]:
    """Actively test empty-password login for common MySQL accounts.

    Uses the native mysql_protocol client to complete a real
    HandshakeResponse41 (mysql_native_password / caching_sha2_password, incl.
    plugin-switch) and reads the server's OK/ERR. A returned OK means the
    account authenticates with an empty password — a real, confirmed finding,
    not a guess. ERR 1045 (access-denied) means not vulnerable.
    """
    from ..protocols.mysql_protocol import MySQLConnection

    conn = MySQLConnection(host, port, timeout=timeout)
    if not conn.connect():
        return None  # not reachable / not MySQL
    server_version = (conn.handshake or {}).get("server_version", "")
    try:
        for user in users:
            # Re-handshake per attempt: a failed login closes the auth state.
            if not conn.handshake:
                if not conn.connect():
                    break
            if conn.login(user, "", database=""):
                return {
                    "service": "mysql",
                    "credentials": f"{user}:(empty)",
                    "severity": "CRITICAL",
                    "confirmed": True,
                    "server_version": server_version,
                    "note": f"MySQL account '{user}' authenticates with an "
                            "empty password (confirmed login).",
                }
            # Reconnect for the next user (socket is now in a failed state).
            conn.close()
            conn = MySQLConnection(host, port, timeout=timeout)
            if not conn.connect():
                break
    finally:
        conn.close()
    return {
        "service": "mysql",
        "credentials": "root/mysql:(empty)",
        "severity": "INFO",
        "confirmed": False,
        "server_version": server_version,
        "note": "MySQL reachable; empty-password login for common accounts "
                "was rejected.",
    }


# ── Redis (no auth) ───────────────────────────────────────────────────────
def check_redis_no_auth(host: str, port: int = 6379,
                        timeout: float = 4.0) -> Optional[dict]:
    """Send INFO — if it returns without NOAUTH, Redis has no password."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"*1\r\n$4\r\nINFO\r\n")
        data = sock.recv(4096)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if b"NOAUTH" in data:
        return None
    if b"redis_version" in data:
        return {
            "service": "redis",
            "credentials": "(none)",
            "severity": "CRITICAL",
            "note": "Redis allows unauthenticated INFO command — full access",
        }
    return None


# ── MongoDB (no auth) ─────────────────────────────────────────────────────
def check_mongo_no_auth(host: str, port: int = 27017,
                        timeout: float = 4.0) -> Optional[dict]:
    """Send listDatabases; if it returns without auth error, no auth required."""
    bson = (b"\x17\x00\x00\x00"
            b"\x10listDatabases\x00"
            b"\x01\x00\x00\x00"
            b"\x00")
    coll = b"admin.$cmd\x00"
    body = struct.pack("<I", 0) + coll + struct.pack("<II", 0, 1) + bson
    msg = struct.pack("<IIII", 16 + len(body), 1, 0, 2004) + body
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(msg)
        data = sock.recv(8192)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data or b"Unauthorized" in data or b"requires authentication" in data:
        return None
    if b"admin" in data or b"config" in data:
        return {
            "service": "mongodb",
            "credentials": "(none)",
            "severity": "CRITICAL",
            "note": "MongoDB listDatabases succeeded without auth",
        }
    return None


# ── memcached (no auth) ───────────────────────────────────────────────────
def check_memcached_no_auth(host: str, port: int = 11211,
                            timeout: float = 4.0) -> Optional[dict]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"stats\r\n")
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if b"STAT" in data:
        return {
            "service": "memcached",
            "credentials": "(none — no SASL auth)",
            "severity": "HIGH",
            "note": "memcached stats accessible — no SASL auth configured",
        }
    return None


# ── SNMP default community strings ────────────────────────────────────────
SNMP_DEFAULT_COMMUNITIES = ["public", "private", "community", "cisco",
                            "manager", "admin", "default", "snmpd"]


def check_snmp_defaults(host: str, timeout: float = 3.0) -> Optional[dict]:
    """Probe SNMP with each default community string."""
    from ..discovery.udp_probes import probe_snmp
    for comm in SNMP_DEFAULT_COMMUNITIES:
        r = probe_snmp(host, community=comm, timeout=timeout)
        if r and r.get("sysDescr"):
            return {
                "service": "snmp",
                "credentials": f"community={comm}",
                "severity": "HIGH",
                "note": f"SNMP responds to community '{comm}'",
                "sysDescr": r["sysDescr"][:200],
            }
    return None


# ── Dispatch ─────────────────────────────────────────────────────────────
DEFAULT_CRED_CHECKS: dict[int, list] = {
    21: [check_ftp_anonymous],
    80: [check_http_basic],
    443: [lambda h, p, t: check_http_basic(h, p, tls=True, timeout=t)],
    3306: [check_mysql_empty_root],
    6379: [check_redis_no_auth],
    11211: [check_memcached_no_auth],
    27017: [check_mongo_no_auth],
    8080: [check_http_basic],
    8443: [lambda h, p, t: check_http_basic(h, p, tls=True, timeout=t)],
}


def check_port_defaults(host: str, port: int,
                        timeout: float = 4.0) -> list[dict]:
    """Run any default-cred checks registered for this port."""
    findings: list[dict] = []
    checkers = DEFAULT_CRED_CHECKS.get(port, [])
    for fn in checkers:
        try:
            r = fn(host, port, timeout)
            if r:
                findings.append(r)
        except Exception as e:
            log.debug("default-cred check on %s:%d crashed: %s",
                      host, port, e)
    return findings


def check_host_defaults(host_ip: str, ports: list[int],
                        timeout: float = 4.0) -> list[dict]:
    """Run default-cred checks for all open ports on a host."""
    findings: list[dict] = []
    # SNMP UDP separately
    snmp = check_snmp_defaults(host_ip, timeout=timeout)
    if snmp:
        findings.append(snmp)
    for p in ports:
        findings.extend(check_port_defaults(host_ip, p, timeout))
    return findings
