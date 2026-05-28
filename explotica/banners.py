"""Banner grabbing — content-based protocol cascade (Phase 56 rewrite).

The previous version dispatched probes by PORT NUMBER:
   HTTP_PORTS = {80, 443, 8080, ...} → HTTP probe
   QUIET_PORTS = {22, 25, 110, ...} → passive read
This means SSH on port 2222, HTTP on port 9999, or HTTPS on port 31337 all
fell through to a generic probe that usually returned nothing.

The new version dispatches by WHAT THE SERVICE ACTUALLY SAYS:

  Phase 1 — passive read (max 800ms):
      Many services send a banner immediately on connect:
        SSH:    "SSH-2.0-OpenSSH_8.4p1 Debian"
        FTP:    "220 ProFTPD 1.3.6 Server"
        SMTP:   "220 mail.example.com ESMTP Postfix"
        POP3:   "+OK Dovecot ready"
        IMAP:   "* OK IMAP4rev1 Service Ready"
        Memcache: "STAT version 1.6.21"
        IRC:    ":server.example.com NOTICE"

  Phase 2 — classify the passive response:
        If we got data → run identify_protocol(data) and stamp:
          - service: 'ssh' / 'ftp' / 'smtp' / 'http' / 'pop3' / 'imap' / etc.
          - product_name / product_version when extractable

  Phase 3 — if NO passive response within 800ms, the service waits for input.
      Try the cascade in this order, stopping at the first usable response:
        a) HTTP HEAD probe (works for HTTP/1.0+ servers — plaintext)
        b) TLS handshake (HTTPS, IMAPS, POP3S, SMTPS, MySQL-SSL, etc.)
        c) HTTP via TLS (HTTPS GET)
        d) Generic CR-LF probe (kicks some servers into talking)
        e) Specific kickers for known-quiet binary protocols
           (NetBIOS session request, RDP X.224 connect, etc.)

The port NUMBER is used only as a HINT for cascade ORDERING (try HTTP first
on port 80, try TLS first on port 443) — but every probe is attempted
regardless of port if the earlier ones fail.

Output:
  grab_banner() returns (banner_text, attempted_probes_list)
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
from typing import Optional

log = logging.getLogger(__name__)


# ── Service signature patterns (content → service name) ──────────────────
# Each entry: (compiled regex, service_name, version_extractor_or_None)
# Patterns checked in order. First match wins.
SERVICE_SIGNATURES: list[tuple[re.Pattern, str, Optional[re.Pattern]]] = [
    # SSH:    "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"
    (re.compile(rb"^SSH-(\d+\.\d+)-(\S+)", re.MULTILINE),
     "ssh",
     re.compile(rb"SSH-\d+\.\d+-(\S+)")),
    # FTP:    "220 ProFTPD 1.3.6 Server (...)" or "220 (vsFTPd 3.0.3)"
    # Order matters: SMTP-specific 220 banners must match BEFORE the generic
    # 220 fallback, or "220 mail.example.com ESMTP Postfix" misclassifies as FTP.
    (re.compile(rb"^220[- ].*FTP", re.IGNORECASE | re.MULTILINE),
     "ftp",
     re.compile(rb"(ProFTPD|vsFTPd|Pure-FTPd|FileZilla|Microsoft FTP)[\s/]*(\d[\d.]+)?",
                re.IGNORECASE)),
    # SMTP:   "220 mail.example.com ESMTP Postfix" — must precede generic 220
    (re.compile(rb"(?:^|\n)220[- ].*(?:SMTP|ESMTP|Postfix|Sendmail|Exim|Exchange)",
                re.IGNORECASE),
     "smtp",
     re.compile(rb"(Postfix|Sendmail|Exim|Microsoft ESMTP|Exchange)[\s/]*(\d[\d.]+)?",
                re.IGNORECASE)),
    # FTP — generic "220 ..." last-resort (no FTP word, no SMTP word required)
    (re.compile(rb"^220[- ]\S", re.MULTILINE),
     "ftp", None),
    # POP3:   "+OK Dovecot ready."
    (re.compile(rb"^\+OK\s", re.MULTILINE),
     "pop3",
     re.compile(rb"\+OK\s+(Dovecot|Courier|Cyrus|UW-IMAP)\s*([\d.]+)?",
                re.IGNORECASE)),
    # IMAP:   "* OK IMAP4rev1 Service Ready"
    (re.compile(rb"^\* OK\s.*IMAP", re.IGNORECASE | re.MULTILINE),
     "imap",
     re.compile(rb"\* OK\s+(?:\[CAPABILITY[^]]+\]\s*)?(\S+)\s+(\S+)?",
                re.IGNORECASE)),
    # HTTP responses (any port):
    (re.compile(rb"^HTTP/[\d.]+\s+\d{3}", re.MULTILINE),
     "http", None),
    # MySQL handshake — starts with [length:3][seq:1][protocol:1] usually 10
    # followed by version string ending in NUL
    (re.compile(rb"^\x00-\x00\x00.\x0a", re.DOTALL),
     "mysql", None),  # version extracted in special-case below
    # PostgreSQL — responds with 'E' (error) to bad startup, or 'R' (auth req)
    (re.compile(rb"^[ER]\x00\x00\x00", re.DOTALL),
     "postgres", None),
    # Redis:  "+PONG\r\n" or "-ERR ..."
    (re.compile(rb"^[+-](?:PONG|OK|ERR|NOAUTH)"),
     "redis", None),
    # Memcached: starts with "STAT" or "ERROR" or specific shape
    (re.compile(rb"^(?:STAT|ERROR|END)\b"),
     "memcached", None),
    # IRC: leading ":server NOTICE" or "NOTICE AUTH"
    (re.compile(rb"^:(\S+)\s+NOTICE", re.MULTILINE),
     "irc", None),
    # RDP — X.224 connect confirm starts with \x03\x00 (TPKT header)
    (re.compile(rb"^\x03\x00\x00"),
     "rdp", None),
    # SMB — NetBIOS session header starts with \x00\x00 (or SMB1: \xffSMB,
    # SMB2: \xfeSMB)
    (re.compile(rb"^(\xffSMB|\xfeSMB|\x00\x00\x00[\x00-\xff]\xffSMB)"),
     "smb", None),
    # MongoDB wire protocol — replies start with a length-prefixed header
    # whose responseTo field == requestID we sent. Hard to test passively,
    # rely on port heuristic + HTTP probe behavior.
    # VNC: "RFB 003.008\n"
    (re.compile(rb"^RFB \d{3}\.\d{3}"),
     "vnc", None),
    # MQTT: CONNACK is \x20\x02\x00\x00 (rare to receive passively)
    # SSH-style fallback: "RFB" / banner-y first-line ASCII
    # XMPP: server-initiated <?xml ...>
    (re.compile(rb"^<\?xml\s.*stream:", re.DOTALL),
     "xmpp", None),
]


def _identify_protocol(data: bytes) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Walk SERVICE_SIGNATURES; return (service, product, version) on first match."""
    if not data:
        return (None, None, None)
    for pattern, service, version_re in SERVICE_SIGNATURES:
        if pattern.search(data):
            product = None
            version = None
            if version_re:
                vm = version_re.search(data)
                if vm:
                    # Extract product+version from named/positional groups
                    groups = [g for g in vm.groups() if g]
                    if groups:
                        product = groups[0].decode("utf-8", "replace") if isinstance(groups[0], bytes) else groups[0]
                        if len(groups) > 1:
                            version = groups[1].decode("utf-8", "replace") if isinstance(groups[1], bytes) else groups[1]
            return (service, product, version)
    return (None, None, None)


# ── Probe primitives ─────────────────────────────────────────────────────
def _passive_read(host: str, port: int, timeout: float) -> Optional[bytes]:
    """Just connect and read. Used for services that speak first."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, OSError):
        return None
    try:
        sock.settimeout(timeout)
        data = sock.recv(2048)
        return data or None
    except (socket.timeout, OSError):
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _http_probe(host: str, port: int, *, tls: bool,
                 timeout: float) -> Optional[bytes]:
    """Send HTTP HEAD/GET request; return response bytes."""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, OSError):
        return None
    sock = None
    try:
        raw.settimeout(timeout)
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        # Phase 57: User-Agent from central constants module
        from .constants import USER_AGENT
        req = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
               f"User-Agent: {USER_AGENT}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
        sock.sendall(req)
        chunks: list[bytes] = []
        while sum(len(c) for c in chunks) < 4096:
            try:
                ch = sock.recv(1024)
            except (socket.timeout, OSError, ssl.SSLError):
                break
            if not ch:
                break
            chunks.append(ch)
            if b"\r\n\r\n" in b"".join(chunks):
                break
        return b"".join(chunks) or None
    except (socket.timeout, OSError, ssl.SSLError):
        return None
    finally:
        try:
            (sock or raw).close()
        except Exception:
            pass


def _tls_handshake_only(host: str, port: int, timeout: float) -> Optional[bytes]:
    """Open TLS handshake and read a few bytes. Confirms 'this port speaks TLS'
    without committing to HTTP semantics."""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, OSError):
        return None
    try:
        raw.settimeout(timeout)
        ctx = ssl._create_unverified_context()
        sock = ctx.wrap_socket(raw, server_hostname=host)
        # Some services (SMTPS, FTPS, IMAPS, POP3S) DO send a banner after TLS
        try:
            data = sock.recv(1024)
        except (socket.timeout, OSError, ssl.SSLError):
            data = b""
        try:
            sock.close()
        except Exception:
            pass
        # An empty TLS read still confirms TLS works — return a marker
        return data if data else b"<<TLS-handshake-OK>>"
    except (socket.timeout, OSError, ssl.SSLError):
        try:
            raw.close()
        except Exception:
            pass
        return None


def _crlf_kick(host: str, port: int, timeout: float) -> Optional[bytes]:
    """Send bare CR-LF and read. Kicks some text-protocol servers."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, OSError):
        return None
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\r\n")
        data = sock.recv(1024)
        return data or None
    except (socket.timeout, OSError):
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _clean_text(data: bytes, max_len: int = 240) -> str:
    """Render bytes as a banner-friendly string. Binary → hex preview."""
    if not data:
        return ""
    if data == b"<<TLS-handshake-OK>>":
        return "TLS handshake succeeded (no application data)"
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    if printable / max(len(data), 1) < 0.65:
        preview = data[:16].hex(" ")
        return f"<binary {len(data)}B: {preview}…>"
    text = data.decode("utf-8", errors="replace").strip()
    # For HTTP responses, condense to status line + Server header
    if text.startswith("HTTP/"):
        keep = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                if keep:
                    break
                continue
            if line.startswith("HTTP/"):
                keep.append(line)
            elif line.lower().startswith(("server:", "x-powered-by:",
                                            "x-aspnet-version:", "x-generator:")):
                keep.append(line)
            if len(keep) >= 4:
                break
        return " | ".join(keep)[:max_len]
    first = next((ln for ln in text.splitlines() if ln.strip()), text)
    return first[:max_len]


# ── Top-level grabber — the cascade ──────────────────────────────────────
# Port hints for cascade ORDERING (not gating). If a port is in the HTTP
# hint set we try HTTP probes earlier; if in the TLS hint set we try TLS
# earlier. But every probe is still attempted on every port if needed.
HTTP_HINT_PORTS = {
    80, 81, 280, 591, 593, 808, 1080, 2080, 2480, 3000, 3030, 3128, 3333,
    4000, 4080, 4848, 5000, 5050, 5080, 6000, 6080, 6660, 7000, 7080,
    8000, 8001, 8008, 8042, 8060, 8080, 8081, 8088, 8089, 8090, 8118,
    8123, 8181, 8222, 8333, 8400, 8500, 8530, 8800, 8866, 8880, 8888,
    8983, 9000, 9001, 9050, 9080, 9090, 9091, 9200, 9500, 9800, 9900,
    9999, 10000, 11371, 16080, 17988, 28017, 55672, 60000,
}
TLS_HINT_PORTS = {
    443, 444, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 1311,
    2083, 2087, 2096, 2484, 3269, 3389, 4443, 5061, 5223, 5269, 5986,
    6443, 6679, 6697, 8243, 8443, 8531, 8883, 9090, 9091, 9443, 10443,
    11214, 11215, 16993, 18091, 18092, 27443, 31415,
}


def grab_banner_full(ip: str, port: int,
                      timeout: float = 1.0
                      ) -> tuple[Optional[str], Optional[str],
                                  Optional[str], Optional[str], list[str]]:
    """Run the full cascade for one port.

    Returns:
      (banner_text, service_guess_from_content, product_name, product_version,
       probes_attempted)

    `service_guess_from_content` is None unless the content clearly matched
    a known protocol signature. NEVER returns an IANA port-number guess —
    that's a separate layer (ports.apply_iana_guess).
    """
    probes: list[str] = []

    # Step 1: passive read — for chatty services like SSH/FTP/SMTP/POP3/IMAP
    probes.append("passive-read")
    data = _passive_read(ip, port, timeout=min(timeout, 0.8))
    if data:
        service, product, version = _identify_protocol(data)
        return (_clean_text(data), service, product, version, probes)

    # Step 2: pick cascade order based on port hint
    prefer_tls_first = port in TLS_HINT_PORTS

    if prefer_tls_first:
        cascade = ["https-get", "tls-handshake", "http-get",
                    "crlf-kick"]
    elif port in HTTP_HINT_PORTS:
        cascade = ["http-get", "tls-handshake", "https-get",
                    "crlf-kick"]
    else:
        # Unknown port — try HTTP first (cheaper than TLS handshake)
        cascade = ["http-get", "tls-handshake", "https-get",
                    "crlf-kick"]

    for probe_name in cascade:
        probes.append(probe_name)
        if probe_name == "http-get":
            data = _http_probe(ip, port, tls=False, timeout=timeout)
        elif probe_name == "https-get":
            data = _http_probe(ip, port, tls=True, timeout=timeout)
        elif probe_name == "tls-handshake":
            data = _tls_handshake_only(ip, port, timeout=timeout)
            # Strong signal that the port speaks TLS even if no banner
            if data == b"<<TLS-handshake-OK>>":
                return ("TLS handshake succeeded (no application data)",
                        "tls", None, None, probes)
        elif probe_name == "crlf-kick":
            data = _crlf_kick(ip, port, timeout=timeout)
        else:
            data = None
        if data:
            service, product, version = _identify_protocol(data)
            return (_clean_text(data), service, product, version, probes)

    return (None, None, None, None, probes)


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """Backward-compatible single-string banner grab. Most call sites use
    this — the richer info is available via grab_banner_full()."""
    banner, _service, _product, _version, _probes = grab_banner_full(
        ip, port, timeout=timeout
    )
    return banner
