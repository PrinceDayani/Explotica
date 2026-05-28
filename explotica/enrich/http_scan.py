"""HTTP deep analysis — headers, technology stack, common paths, security audit.

For each HTTP/HTTPS port, extracts:
  - All response headers (Server, X-Powered-By, X-Frame-Options, CSP, HSTS, etc.)
  - Technology stack via header + body heuristics (wappalyzer-style mini)
  - Common-path probe results (/robots.txt, /sitemap.xml, /.git/, /admin, etc.)
  - HTML title + meta tags
  - Security header audit (presence/strength)
  - WAF detection (Cloudflare, Akamai headers)

Pure-Python; stdlib only.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import urllib.parse
from typing import Optional

log = logging.getLogger(__name__)


# Common paths to probe — high signal-to-noise ratio
COMMON_PATHS: list[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.env",
    "/admin",
    "/admin/",
    "/login",
    "/wp-login.php",
    "/wp-admin/",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/api",
    "/api/v1",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/server-status",
    "/phpinfo.php",
    "/.DS_Store",
    "/manager/html",       # Tomcat
    "/console",            # Jenkins/J2EE
    "/actuator",           # Spring Boot
    "/actuator/health",
    "/metrics",            # Prometheus/Grafana
]


# Technology fingerprints — regex against headers (value or full line) or body.
# (name, header_regex_pairs, body_regex_pairs)
TECH_FINGERPRINTS: list[tuple[str, list[tuple[str, str]], list[str]]] = [
    ("WordPress", [],
     [r"wp-content/", r"wp-includes/", r"<meta name=\"generator\" content=\"WordPress"]),
    ("Drupal", [("X-Generator", r"Drupal")],
     [r"sites/default/files", r"Drupal\.settings"]),
    ("Joomla", [],
     [r"/media/system/js/", r"<meta name=\"generator\" content=\"Joomla"]),
    ("Apache", [("Server", r"Apache(/[\d.]+)?")], []),
    ("nginx", [("Server", r"nginx(/[\d.]+)?")], []),
    ("IIS", [("Server", r"Microsoft-IIS/[\d.]+")], []),
    ("PHP", [("X-Powered-By", r"PHP")], []),
    ("ASP.NET", [("X-Powered-By", r"ASP\.NET"), ("X-AspNet-Version", r".+")], []),
    ("Express (Node.js)", [("X-Powered-By", r"Express")], []),
    ("Django", [("X-Frame-Options", r".*"), ("Set-Cookie", r"csrftoken=")],
     [r"csrfmiddlewaretoken"]),
    ("Flask / Werkzeug", [("Server", r"Werkzeug")], []),
    ("Gunicorn", [("Server", r"gunicorn")], []),
    ("Tornado", [("Server", r"TornadoServer")], []),
    ("Tomcat", [], [r"<title>Apache Tomcat", r"/manager/"]),
    ("Jenkins", [("X-Jenkins", r".+")], [r"<title>.*Jenkins"]),
    ("GitLab", [("X-Gitlab-Meta", r".+")], [r"gitlab-static"]),
    ("Grafana", [], [r"<title>Grafana", r"window\.grafanaBootData"]),
    ("Kibana", [("kbn-name", r".+")], [r"<title>Kibana"]),
    ("Cloudflare (CDN/WAF)", [("Server", r"cloudflare"), ("CF-RAY", r".+")], []),
    ("Akamai (CDN)", [("X-Akamai-", r".+")], []),
    ("Cloudfront (CDN)", [("Via", r"CloudFront"), ("X-Amz-Cf-Id", r".+")], []),
    ("React", [],
     [r"<div id=\"root\"", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"]),
    ("Vue.js", [], [r"<div id=\"app\"", r"window\.__VUE_OPTIONS_API__"]),
    ("Angular", [], [r"ng-version", r"<app-root"]),
    ("jQuery", [], [r"jquery(-[\d.]+)?(\.min)?\.js", r"window\.jQuery"]),
    ("Bootstrap", [], [r"bootstrap(\.min)?\.css", r"\"bootstrap\":"]),
    ("Synology DSM", [("X-Synology-DSM", r".+")],
     [r"<title>DSM", r"synology", r"DiskStation"]),
    ("Mikrotik RouterOS", [], [r"router_name", r"RouterOS"]),
    ("Ubiquiti Unifi", [], [r"unifi", r"UBIQUITI"]),
    ("pfSense", [], [r"pfSense", r"<title>pfSense"]),
    ("OpenWrt", [], [r"OpenWrt", r"LuCI"]),
    ("Hikvision (camera)", [], [r"Hikvision", r"webSdkAPI"]),
    ("Dahua (camera)", [], [r"Dahua", r"DahuaTechnology"]),
    ("Axis (camera)", [], [r"AXIS", r"axis-cgi"]),
    ("CUPS (printer)", [("Server", r"CUPS")], [r"<title>Home - CUPS"]),
    ("Foscam (camera)", [], [r"Foscam", r"foscamApp"]),
]

# Security headers we audit
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Referrer policy",
    "Permissions-Policy": "Permissions policy",
    "X-XSS-Protection": "Legacy XSS filter (deprecated)",
}


def _send_request(host: str, port: int, path: str, *, tls: bool,
                  method: str = "GET", timeout: float = 3.0,
                  max_bytes: int = 16384) -> Optional[tuple[int, dict, bytes]]:
    """Single HTTP request. Returns (status_code, headers_dict, body_bytes) or None.

    Hand-rolled because we want full control: no redirect following, raw bytes,
    no library that might rewrite/normalize headers.
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
        # Phase 57: User-Agent from central constants
        from ..core.constants import USER_AGENT
        req = (
            f"{method} {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        sock.sendall(req)
        chunks: list[bytes] = []
        total = 0
        while total < max_bytes:
            try:
                ch = sock.recv(4096)
            except (socket.timeout, OSError, ssl.SSLError):
                break
            if not ch:
                break
            chunks.append(ch)
            total += len(ch)
        sock.close()
    except (socket.timeout, OSError, ssl.SSLError) as e:
        log.debug("http req %s:%d%s: %s", host, port, path, e)
        try:
            raw.close()
        except Exception:
            pass
        return None

    data = b"".join(chunks)
    if not data:
        return None
    # Split headers/body at the first blank line
    sep = b"\r\n\r\n"
    if sep in data:
        head, body = data.split(sep, 1)
    else:
        head, body = data, b""
    head_text = head.decode("utf-8", errors="replace")
    lines = head_text.split("\r\n")
    if not lines:
        return None
    # Parse status line
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError):
        status = 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()
    return (status, headers, body)


def _detect_tech(headers: dict, body: str) -> list[str]:
    """Run technology fingerprints against headers + body."""
    hits: list[str] = []
    for name, header_pats, body_pats in TECH_FINGERPRINTS:
        matched = False
        for hkey, hregex in header_pats:
            for actual_key, actual_val in headers.items():
                if actual_key.lower() == hkey.lower() and re.search(
                    hregex, actual_val, re.I
                ):
                    matched = True
                    break
                # Some fingerprints use a key-only check
                if actual_key.lower().startswith(hkey.lower().rstrip("-")) and hkey.endswith("-"):
                    matched = True
                    break
            if matched:
                break
        if not matched:
            for bp in body_pats:
                if re.search(bp, body, re.I | re.S):
                    matched = True
                    break
        if matched:
            hits.append(name)
    return hits


def _audit_security_headers(headers: dict) -> dict:
    """Return {header_name: present_bool, ...} + missing list."""
    present: dict[str, str | bool] = {}
    missing: list[str] = []
    lower = {k.lower(): v for k, v in headers.items()}
    for h, label in SECURITY_HEADERS.items():
        v = lower.get(h.lower())
        if v is not None:
            present[h] = v
        else:
            missing.append(f"{h} ({label})")
    return {"present": present, "missing": missing}


def _extract_title(body_text: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None


def scan_http(host: str, port: int, *, tls: bool, timeout: float = 3.0,
              probe_paths: bool = True) -> Optional[dict]:
    """Full HTTP intel for one host:port.

    Returns a dict with: status, headers, title, tech_stack, security_headers,
      paths_found, waf_detected, issues
    """
    main = _send_request(host, port, "/", tls=tls, method="GET",
                         timeout=timeout)
    if main is None:
        return None
    status, headers, body = main
    body_text = body[:8192].decode("utf-8", errors="replace")

    tech = _detect_tech(headers, body_text)
    sec = _audit_security_headers(headers)
    title = _extract_title(body_text)

    # Server / X-Powered-By for quick reference
    server = headers.get("Server") or headers.get("server")
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by")

    # WAF detection — coarse
    waf = None
    if any(k.lower().startswith("cf-") for k in headers):
        waf = "Cloudflare"
    elif "x-amz-cf-id" in {k.lower() for k in headers}:
        waf = "CloudFront"
    elif headers.get("Server", "").lower().startswith("akamai"):
        waf = "Akamai"
    elif "x-sucuri-id" in {k.lower() for k in headers}:
        waf = "Sucuri"

    paths_found: list[dict] = []
    if probe_paths:
        for p in COMMON_PATHS:
            resp = _send_request(host, port, p, tls=tls, method="GET",
                                 timeout=timeout, max_bytes=2048)
            if resp is None:
                continue
            st, hdrs, b = resp
            if st in (200, 401, 403):
                # 401/403 still useful — confirms the path exists
                ctype = hdrs.get("Content-Type") or hdrs.get("content-type") or ""
                clen = hdrs.get("Content-Length") or len(b)
                paths_found.append({
                    "path": p,
                    "status": st,
                    "content_type": ctype[:60],
                    "size": int(clen) if str(clen).isdigit() else len(b),
                })

    issues: list[str] = []
    if sec["missing"]:
        issues.append(
            f"Missing security headers: {', '.join(h.split(' ')[0] for h in sec['missing'][:5])}"
        )
    if any(p["status"] == 200 and p["path"] in ("/.env", "/.git/HEAD",
                                                  "/server-status",
                                                  "/phpinfo.php",
                                                  "/.DS_Store")
           for p in paths_found):
        issues.append("Sensitive path(s) accessible — see paths_found")
    if any(p["path"] in ("/wp-login.php", "/wp-admin/") and p["status"] == 200
           for p in paths_found):
        issues.append("WordPress admin reachable")

    return {
        "status": status,
        "server": server,
        "x_powered_by": powered,
        "title": title,
        "headers": dict(headers),
        "tech_stack": tech,
        "security_headers": sec,
        "paths_found": paths_found,
        "waf": waf,
        "issues": issues,
    }
