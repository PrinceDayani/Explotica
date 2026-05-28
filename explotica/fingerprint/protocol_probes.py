"""Protocol-specific probes for ports that don't volunteer info passively.

Each probe sends a single carefully-crafted payload and parses the response
into useful identification + version data.

Probes return a string that gets merged into Port.banner. They also try to
infer (vendor, product, version) and return that for CPE lookup.
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Callable, Optional

log = logging.getLogger(__name__)


# Each handler returns (banner_str, vendor, product, version) or None
ProbeResult = Optional[tuple[str, Optional[str], Optional[str], Optional[str]]]


# ── HP JetDirect / PJL (port 9100) ────────────────────────────────────────
def probe_jetdirect(host: str, port: int = 9100, timeout: float = 3.0) -> ProbeResult:
    """Send PJL INFO ID to a network printer."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # PJL escape sequence + INFO ID
        sock.sendall(b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n")
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("JetDirect probe %s:%d failed: %s", host, port, e)
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").strip()
    # Output format: '@PJL INFO ID\r\n"HP LaserJet M227-fdw"\r\n\x0c\x1b%-12345X'
    info_line = next((line for line in text.splitlines() if '"' in line), None)
    if info_line:
        model = info_line.strip().strip('"')
        return (f"JetDirect: {model}", "hp", "jetdirect", None)
    return (f"PJL responsive: {text[:100]}", "hp", "jetdirect", None)


# ── RTSP (ports 554, 8554) ────────────────────────────────────────────────
def probe_rtsp(host: str, port: int = 554, timeout: float = 3.0) -> ProbeResult:
    """RTSP OPTIONS request — reveals Server header + supported methods."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        req = (f"OPTIONS rtsp://{host}:{port} RTSP/1.0\r\n"
               f"CSeq: 1\r\n"
               f"User-Agent: explotica/0.7.0\r\n\r\n").encode()
        sock.sendall(req)
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("RTSP probe %s:%d failed: %s", host, port, e)
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    server = None
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    label = f"RTSP {server}" if server else f"RTSP responsive ({text[:80]})"
    # Common RTSP cameras: Hikvision, Dahua, Axis, Foscam
    vendor = product = None
    if server:
        sv = server.lower()
        if "hikvision" in sv:
            vendor, product = "hikvision", "ip_camera"
        elif "dahua" in sv:
            vendor, product = "dahua", "ip_camera"
        elif "axis" in sv:
            vendor, product = "axis", "ip_camera"
    return (label, vendor, product, None)


# ── rsync (port 873) ──────────────────────────────────────────────────────
def probe_rsync(host: str, port: int = 873, timeout: float = 3.0) -> ProbeResult:
    """After greeting, send protocol version + list to get module list."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        greet = sock.recv(256)  # e.g. '@RSYNCD: 31.0 md5 md4 lz4\n'
        # Mirror the announced protocol back to negotiate, then ask for modules
        sock.sendall(b"@RSYNCD: 31.0\n")
        sock.sendall(b"#list\n")
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"@RSYNCD: EXIT" in data or len(data) > 8192:
                    break
            except socket.timeout:
                break
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("rsync probe %s:%d failed: %s", host, port, e)
        return None
    text = (greet.decode("utf-8", "replace").strip()
            + " | modules: "
            + data.decode("utf-8", "replace").strip())
    return (text[:280], "samba", "rsync", None)


# ── Redis (port 6379) ─────────────────────────────────────────────────────
def probe_redis(host: str, port: int = 6379, timeout: float = 3.0) -> ProbeResult:
    """INFO command → returns server version, OS, role, memory layout."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"*1\r\n$4\r\nINFO\r\n")  # RESP-encoded "INFO"
        data = sock.recv(8192)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    if "NOAUTH" in text:
        return ("Redis: AUTH required", "redis", "redis", None)
    version = None
    for line in text.splitlines():
        if line.startswith("redis_version:"):
            version = line.split(":", 1)[1].strip()
            break
    label = f"Redis v{version}" if version else "Redis responsive (no AUTH)"
    return (label, "redis", "redis", version)


# ── memcached (port 11211) ────────────────────────────────────────────────
def probe_memcached(host: str, port: int = 11211, timeout: float = 3.0) -> ProbeResult:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"stats\r\n")
        data = sock.recv(4096)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data or b"STAT" not in data:
        return None
    text = data.decode("utf-8", errors="replace")
    version = None
    for line in text.splitlines():
        if line.startswith("STAT version "):
            version = line.split(" ")[-1].strip()
            break
    return (f"memcached v{version or 'unknown'} (no auth)",
            "memcached", "memcached", version)


# ── MongoDB (port 27017) ──────────────────────────────────────────────────
def probe_mongodb(host: str, port: int = 27017, timeout: float = 3.0) -> ProbeResult:
    """Send a 'isMaster' OP_QUERY; returns server version + topology."""
    try:
        # OP_QUERY wire protocol — flags=0, fullCollectionName='admin.$cmd',
        # numberToSkip=0, numberToReturn=1, query={isMaster:1}
        query_bson = (
            b"\x14\x00\x00\x00"          # document length 20
            b"\x10isMaster\x00"            # int32 field 'isMaster'
            b"\x01\x00\x00\x00"          # value 1
            b"\x00"                       # terminating null
        )
        coll = b"admin.$cmd\x00"
        body = (
            struct.pack("<I", 0)            # flags
            + coll
            + struct.pack("<II", 0, 1)       # skip, return
            + query_bson
        )
        # Message header: msgLen, requestID, responseTo, opCode=2004 (OP_QUERY)
        msg = (
            struct.pack("<IIII", 16 + len(body), 1, 0, 2004)
            + body
        )
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(msg)
        data = sock.recv(8192)
        sock.close()
    except (socket.timeout, OSError, struct.error):
        return None
    if not data:
        return None
    # Extract any embedded string runs as a coarse approximation
    text = data.decode("utf-8", errors="replace")
    # Look for version markers like 'maxWireVersion' or printable strings
    version = None
    if b"version" in data:
        # Find an ASCII version string after 'version' field
        i = data.find(b"version") + 7
        # version stored as cstring length+bytes; rough extract
        for j in range(i, min(i + 50, len(data))):
            if 0x30 <= data[j] <= 0x39:  # digit
                end = j
                while end < len(data) and (
                    0x30 <= data[end] <= 0x39 or data[end] in (0x2e,)
                ):
                    end += 1
                if end > j + 2:
                    version = data[j:end].decode("ascii", "ignore")
                    break
    label = f"MongoDB v{version}" if version else "MongoDB responsive (no auth)"
    return (label, "mongodb", "mongodb", version)


# ── PostgreSQL (port 5432) ────────────────────────────────────────────────
def probe_postgres(host: str, port: int = 5432, timeout: float = 3.0) -> ProbeResult:
    """Send a StartupMessage; the error response usually identifies the server."""
    try:
        # Minimal StartupMessage with bogus user — server will reject but
        # respond with an error packet that often includes version.
        proto = struct.pack(">I", 0x00030000)  # protocol 3.0
        params = b"user\x00explotica\x00database\x00explotica\x00\x00"
        msg = struct.pack(">I", 4 + 4 + len(params)) + proto + params
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(msg)
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data:
        return None
    # Error response starts with 'E' (0x45)
    if data[:1] in (b"E", b"R"):
        text = data.decode("utf-8", errors="replace")
        if "FATAL" in text or "authentication" in text.lower():
            return ("PostgreSQL responsive (auth required)",
                    "postgresql", "postgresql", None)
    return ("PostgreSQL responsive", "postgresql", "postgresql", None)


# ── MySQL / MariaDB (port 3306) ───────────────────────────────────────────
def probe_mysql(host: str, port: int = 3306, timeout: float = 3.0) -> ProbeResult:
    """Read the server's initial handshake packet — it includes version."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        data = sock.recv(1024)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data or len(data) < 16:
        return None
    # First 4 bytes are packet length + sequence. Then 1 byte protocol version.
    # Then null-terminated server version string.
    try:
        idx = 5  # skip packet header (4) + protocol version byte (1)
        end = data.index(b"\x00", idx)
        version_str = data[idx:end].decode("ascii", "ignore")
    except (ValueError, IndexError):
        return ("MySQL/MariaDB handshake responsive", "mysql", "mysql", None)
    vendor = product = "mysql"
    if "MariaDB" in version_str:
        vendor, product = "mariadb", "mariadb"
    # Strip the suffix to get a clean numeric version
    clean = version_str.split("-")[0]
    return (f"MySQL/MariaDB v{version_str}", vendor, product, clean)


# ── IPP / Printers (port 631) ─────────────────────────────────────────────
def probe_ipp(host: str, port: int = 631, timeout: float = 3.0) -> ProbeResult:
    """CUPS / IPP — try HTTP first since CUPS exposes a web UI here too."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(
            f"GET / HTTP/1.0\r\nHost: {host}\r\n"
            f"User-Agent: explotica/0.7.0\r\n\r\n".encode()
        )
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    server = None
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    if server and "cups" in server.lower():
        return (f"IPP/CUPS: {server}", "cups", "cups", None)
    return (f"IPP responsive ({server or 'no Server header'})",
            "cups", "cups", None)


# ── SIP (port 5060) ───────────────────────────────────────────────────────
def probe_sip(host: str, port: int = 5060, timeout: float = 3.0) -> ProbeResult:
    """SIP OPTIONS request."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # Minimal SIP OPTIONS request
        msg = (
            f"OPTIONS sip:{host}:{port} SIP/2.0\r\n"
            f"Via: SIP/2.0/TCP {host};branch=z9hG4bK-explotica\r\n"
            f"From: <sip:explotica@{host}>;tag=1\r\n"
            f"To: <sip:test@{host}>\r\n"
            f"Call-ID: explotica-{port}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode()
        sock.sendall(msg)
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    server = None
    for line in text.splitlines():
        if line.lower().startswith(("server:", "user-agent:")):
            server = line.split(":", 1)[1].strip()
            break
    return (f"SIP: {server or 'responsive'}", None, "sip", None)


# ── Elasticsearch (port 9200) ─────────────────────────────────────────────
def probe_elasticsearch(host: str, port: int = 9200, timeout: float = 3.0) -> ProbeResult:
    """GET / returns Elasticsearch's self-identification JSON."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(
            f"GET / HTTP/1.0\r\nHost: {host}\r\n"
            f"User-Agent: explotica/0.7.0\r\n\r\n".encode()
        )
        data = b""
        while len(data) < 4096:
            try:
                chunk = sock.recv(2048)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    if "elasticsearch" not in text.lower() and "tagline" not in text.lower():
        return None
    # Extract version from JSON-ish content
    import re
    m = re.search(r'"number"\s*:\s*"([^"]+)"', text)
    version = m.group(1) if m else None
    label = f"Elasticsearch v{version}" if version else "Elasticsearch responsive"
    return (label, "elastic", "elasticsearch", version)


# ── WSD (Web Services Discovery, port 5357 TCP) ──────────────────────────
def probe_wsd(host: str, port: int = 5357, timeout: float = 3.0) -> ProbeResult:
    """5357 is the WSD HTTP transport — try an HTTP GET to look for WSD endpoints."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(
            f"GET / HTTP/1.0\r\nHost: {host}\r\n"
            f"User-Agent: explotica/0.7.0\r\n\r\n".encode()
        )
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    server = None
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    return (f"WSD: {server or 'responsive'}", None, "wsd", None)


# ── Dispatch table ────────────────────────────────────────────────────────
PROBES: dict[int, Callable] = {
    554:   probe_rtsp,
    631:   probe_ipp,
    873:   probe_rsync,
    1521:  None,           # Oracle TNS — too brittle without proper lib
    3306:  probe_mysql,
    5060:  probe_sip,
    5357:  probe_wsd,
    5432:  probe_postgres,
    6379:  probe_redis,
    8554:  probe_rtsp,     # Alt-RTSP
    9100:  probe_jetdirect,
    9200:  probe_elasticsearch,
    11211: probe_memcached,
    27017: probe_mongodb,
}


def unmask_port(host: str, port: int, timeout: float = 3.0) -> ProbeResult:
    """Try to identify an unfingerprinted port via protocol-specific probe."""
    handler = PROBES.get(port)
    if handler is None:
        return None
    try:
        return handler(host, port, timeout=timeout)
    except Exception as e:
        log.debug("probe %s on %s:%d crashed: %s", handler.__name__,
                  host, port, e)
        return None


def unmask_ports() -> set[int]:
    return set(PROBES.keys())
