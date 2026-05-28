"""Active service fingerprinting (--deep flag).

For each open port that the passive banner-grabber couldn't pin down, send
ONE targeted probe to extract product+version info. These probes are quiet
(one TCP connection, one small payload) but they DO touch the target — that's
why this lives behind --deep instead of running by default.

Each probe should:
  - return a string that can be passed back through banner parsing, OR
  - directly set port.product_* fields, OR
  - return None on failure

Style: never raise — recon code MUST keep going past per-port failures.
"""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Optional

from ..core.models import Port

log = logging.getLogger(__name__)

# Ports this module knows how to probe.
DEEP_PROBE_PORTS = {21, 22, 23, 25, 80, 81, 110, 143, 443, 445, 587,
                    993, 995, 3306, 5432, 5900, 6379, 8000, 8008,
                    8080, 8081, 8443, 9000, 11211, 27017}


# ── HTTP: GET fallback when HEAD didn't reveal Server: header ─────────────
def http_get_probe(host: str, port: int, tls: bool, timeout: float = 2.0) -> Optional[str]:
    """Send GET / and capture Server / X-Powered-By headers.

    HEAD is the polite default in banners.py, but some servers (especially
    IoT devices) reject HEAD or omit the Server header on it. GET is louder
    but reliably populates response headers.
    """
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        from ..core.constants import USER_AGENT
        req = (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
               f"User-Agent: {USER_AGENT}\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
        sock.sendall(req)
        chunks: list[bytes] = []
        # Pull only enough to see headers (~4KB max)
        while len(b"".join(chunks)) < 4096:
            try:
                ch = sock.recv(1024)
            except (socket.timeout, OSError, ssl.SSLError):
                break
            if not ch:
                break
            chunks.append(ch)
            if b"\r\n\r\n" in b"".join(chunks):
                break
        sock.close()
    except (socket.timeout, OSError, ssl.SSLError) as e:
        log.debug("http_get_probe %s:%d: %s", host, port, e)
        try:
            raw.close()
        except Exception:
            pass
        return None

    data = b"".join(chunks)
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    keep: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            break  # end of headers
        if line.startswith("HTTP/") or line.lower().startswith(
            ("server:", "x-powered-by:", "x-aspnet-version:", "x-generator:")
        ):
            keep.append(line)
    return " | ".join(keep)[:280] if keep else None


# ── FTP SYST — "215 UNIX Type: L8" etc. ───────────────────────────────────
def ftp_syst_probe(host: str, port: int = 21, timeout: float = 2.5) -> Optional[str]:
    """After the FTP greeting, send SYST and capture the response.

    Reveals the OS family ("UNIX Type: L8", "Windows_NT") for fingerprinting.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        greeting = sock.recv(1024)  # consume the greeting (220 ...)
        sock.sendall(b"SYST\r\n")
        resp = sock.recv(512)
        sock.close()
        text = (greeting + b"\n" + resp).decode("utf-8", errors="replace").strip()
        return text[:280] if text else None
    except (socket.timeout, OSError) as e:
        log.debug("ftp_syst %s:%d: %s", host, port, e)
        return None


# ── HTTPS cert peek — subject CN often leaks product identity ─────────────
def https_cert_probe(host: str, port: int = 443, timeout: float = 2.5) -> Optional[str]:
    """Grab the leaf cert's subject + issuer + SANs.

    Useful for identifying device families (e.g. 'Synology Inc.' in issuer,
    'pfsense' in CN). Doesn't validate the cert — we want the raw fields.
    """
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl._create_unverified_context()
        sock = ctx.wrap_socket(raw, server_hostname=host)
        cert = sock.getpeercert()
        sock.close()
    except (socket.timeout, OSError, ssl.SSLError) as e:
        log.debug("https_cert %s:%d: %s", host, port, e)
        return None
    if not cert:
        return None
    parts: list[str] = []
    for k in ("subject", "issuer"):
        if k in cert:
            flat = ", ".join(
                "=".join(item) for tup in cert[k] for item in tup
            )
            parts.append(f"{k}: {flat}")
    sans = cert.get("subjectAltName", [])
    if sans:
        parts.append("SAN: " + ",".join(v for _, v in sans))
    return " | ".join(parts)[:280]


# ── SMB negotiate (port 445) — OS hint from NTLM Type 2 ──────────────────
def smb_negotiate_probe(host: str, port: int = 445, timeout: float = 3.0) -> Optional[str]:
    """Send an SMB negotiate-protocol packet to learn server OS.

    This is a minimal SMB1 NEGOTIATE PROTOCOL request that even modern SMB2/3
    servers respond to with their max-supported dialect. The response payload
    typically includes ServerName / OS strings in the security blob.

    Pure-python implementation — no impacket dep needed.
    """
    # SMB1 NEGOTIATE PROTOCOL (offering NT LM 0.12 + SMB2 dialects)
    pkt = bytes.fromhex(
        "000000d4ff534d4272000000001853c8000000000000000000000000ffff"
        "0000000000b100025043204e4554574f524b2050524f4752414d20312e30"
        "00024c414e4d414e312e3000024c414e4d414e322e3100024c414e4d414e"
        "322e310002534d422033202e3000024e54204c4d20302e313200025357"
        "32000253616d626100025357305700"
    )
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(pkt)
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("smb_negotiate %s:%d: %s", host, port, e)
        return None
    if not data:
        return None
    # Look for printable runs ≥ 6 chars — that's where ServerName / OS hide.
    text_bits: list[str] = []
    cur: list[int] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= 6:
                text_bits.append(bytes(cur).decode("ascii", errors="ignore"))
            cur = []
    if len(cur) >= 6:
        text_bits.append(bytes(cur).decode("ascii", errors="ignore"))
    if not text_bits:
        return f"<SMB binary {len(data)}B>"
    return " | ".join(text_bits)[:280]


# ── Dispatch ──────────────────────────────────────────────────────────────
def deep_probe(host: str, port: Port, timeout: float = 2.5) -> Optional[str]:
    """Choose the right probe based on port number. Returns a fresh banner
    string to merge into Port.banner, or None."""
    n = port.number
    if n in (80, 81, 8000, 8008, 8080, 8081, 3000, 5000, 8888):
        return http_get_probe(host, n, tls=False, timeout=timeout)
    if n in (443, 8443):
        cert = https_cert_probe(host, n, timeout=timeout)
        body = http_get_probe(host, n, tls=True, timeout=timeout)
        if cert and body:
            return f"{cert} || {body}"
        return cert or body
    if n == 21:
        return ftp_syst_probe(host, n, timeout=timeout)
    if n == 445:
        return smb_negotiate_probe(host, n, timeout=timeout)
    return None


def deepen_host(host_ip: str, ports: list[Port],
                timeout: float = 2.5, workers: int = 8) -> None:
    """For each port we know how to probe, run the active probe IN PARALLEL
    and merge its output into port.banner if we learned something new."""
    from concurrent.futures import ThreadPoolExecutor

    # Phase 56: deep active probes only on OPEN ports — sending a TLS
    # ClientHello to a filtered port just wastes 2.5s per attempt.
    targets = [p for p in ports
                if p.number in DEEP_PROBE_PORTS and p.state == "open"]
    if not targets:
        return

    def probe_one(p: Port) -> None:
        try:
            extra = deep_probe(host_ip, p, timeout=timeout)
        except Exception as e:
            log.debug("deep_probe crash %s:%d: %s", host_ip, p.number, e)
            return
        if not extra:
            return
        # Merge: keep passive banner if it existed, append active findings.
        p.banner = (
            f"{p.banner} || deep: {extra}" if p.banner else f"deep: {extra}"
        )[:512]

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        list(pool.map(probe_one, targets))
