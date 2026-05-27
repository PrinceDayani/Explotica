"""Banner grabbing — pull service identity from open ports.

Strategy:
- For services that speak first (SSH, FTP, SMTP, POP3, IMAP): just read.
- For HTTP/HTTPS-likely ports: send HEAD request.
- For everything else: small generic probe then read.
"""

from __future__ import annotations

import socket
import ssl

HTTP_PORTS = {80, 81, 8000, 8008, 8080, 8081, 3000, 5000, 8888}
HTTPS_PORTS = {443, 8443}
QUIET_PORTS = {22, 21, 25, 110, 143, 587, 993, 995}  # banner sent unprompted


def _http_probe(host: str, port: int, tls: bool, timeout: float) -> str | None:
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = ssl.create_default_context().wrap_socket(
            raw, server_hostname=host
        ) if tls else raw
        # We disable cert verification for scanning — pragma: best-effort recon
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(raw, server_hostname=host)
        req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: explotica/0.1\r\n\r\n"
        sock.sendall(req.encode())
        data = sock.recv(2048)
        sock.close()
        return _clean(data)
    except (socket.timeout, OSError, ssl.SSLError):
        try:
            raw.close()
        except Exception:
            pass
        return None


def _passive_read(host: str, port: int, timeout: float) -> str | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        data = sock.recv(1024)
        sock.close()
        return _clean(data)
    except (socket.timeout, OSError):
        return None


def _generic_probe(host: str, port: int, timeout: float) -> str | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"\r\n\r\n")
        data = sock.recv(1024)
        sock.close()
        return _clean(data)
    except (socket.timeout, OSError):
        return None


def _clean(data: bytes) -> str | None:
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").strip()
    # collapse to first non-empty line, cap length
    first = next((line for line in text.splitlines() if line.strip()), text)
    return first[:200] if first else None


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str | None:
    """Dispatch by port heuristic."""
    if port in HTTP_PORTS:
        return _http_probe(ip, port, tls=False, timeout=timeout)
    if port in HTTPS_PORTS:
        return _http_probe(ip, port, tls=True, timeout=timeout)
    if port in QUIET_PORTS:
        return _passive_read(ip, port, timeout=timeout)
    # Fallback: try passive first (cheap), then generic probe.
    return _passive_read(ip, port, timeout) or _generic_probe(ip, port, timeout)
