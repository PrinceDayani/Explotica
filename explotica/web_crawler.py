"""Polite web crawler — same-origin link discovery + JS endpoint extraction.

Starts at `/`, follows links found in HTML, recurses up to depth=1 (default)
with a hard page cap. For each page, extracts:
  - <a href=...> links
  - <form action=...> form targets
  - <script src=...> JS source URLs (then fetches and regex-mines them)
  - <link href=...> stylesheet/manifest URLs
  - Inline-script API endpoint patterns

The goal is finding HIDDEN endpoints the path-probe can't predict:
  /api/users, /v2/health, /internal/metrics, etc.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import urllib.parse
from typing import Optional

log = logging.getLogger(__name__)

# Regex patterns to mine JS source for API-looking endpoints
_JS_ENDPOINT_PATTERNS = [
    re.compile(r"""["'](/api/[\w/.\-]+)["']"""),
    re.compile(r"""["'](/v\d+/[\w/.\-]+)["']"""),
    re.compile(r"""["'](/graphql)["']"""),
    re.compile(r"""["'](/(rest|services|internal)/[\w/.\-]+)["']"""),
    re.compile(r"""url\s*[:=]\s*["']([/\w.\-]+)["']"""),
    re.compile(r"""fetch\s*\(\s*["']([/\w.\-]+)["']"""),
    re.compile(r"""axios\.\w+\s*\(\s*["']([/\w.\-]+)["']"""),
]

_HTML_LINK_PATTERNS = [
    re.compile(r"""<a\s[^>]*href\s*=\s*["']([^"'#?]+)""", re.I),
    re.compile(r"""<form\s[^>]*action\s*=\s*["']([^"'#?]+)""", re.I),
    re.compile(r"""<script\s[^>]*src\s*=\s*["']([^"'#?]+)""", re.I),
    re.compile(r"""<link\s[^>]*href\s*=\s*["']([^"'#?]+)""", re.I),
]


def _fetch(url: str, timeout: float = 4.0,
           max_bytes: int = 256_000) -> Optional[tuple[int, dict, bytes]]:
    """Fetch a URL with raw socket — handle http and https, no follow."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        if parsed.scheme == "https":
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        req = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: explotica/0.1\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        sock.sendall(req)
        chunks: list[bytes] = []
        total = 0
        while total < max_bytes:
            try:
                ch = sock.recv(8192)
            except (socket.timeout, OSError, ssl.SSLError):
                break
            if not ch:
                break
            chunks.append(ch)
            total += len(ch)
        sock.close()
    except (socket.timeout, OSError, ssl.SSLError) as e:
        log.debug("crawler fetch %s failed: %s", url, e)
        try:
            raw.close()
        except Exception:
            pass
        return None

    data = b"".join(chunks)
    if not data:
        return None
    sep = b"\r\n\r\n"
    if sep in data:
        head, body = data.split(sep, 1)
    else:
        head, body = data, b""
    head_text = head.decode("utf-8", errors="replace")
    lines = head_text.split("\r\n")
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


def _extract_links(body_text: str) -> set[str]:
    """Return all link URLs found via the HTML patterns above."""
    out: set[str] = set()
    for pat in _HTML_LINK_PATTERNS:
        for m in pat.finditer(body_text):
            href = m.group(1).strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                out.add(href)
    return out


def _extract_js_endpoints(body_text: str) -> set[str]:
    """Mine JS source for endpoint-like strings."""
    out: set[str] = set()
    for pat in _JS_ENDPOINT_PATTERNS:
        for m in pat.finditer(body_text):
            try:
                out.add(m.group(1))
            except IndexError:
                continue
    return out


def _same_origin(base: str, candidate: str) -> Optional[str]:
    """Resolve `candidate` against `base`. Return absolute URL only if same origin."""
    abs_url = urllib.parse.urljoin(base, candidate)
    bp = urllib.parse.urlparse(base)
    ap = urllib.parse.urlparse(abs_url)
    if ap.scheme not in ("http", "https"):
        return None
    if (ap.hostname, ap.port or (443 if ap.scheme == "https" else 80)) != \
       (bp.hostname, bp.port or (443 if bp.scheme == "https" else 80)):
        return None
    return abs_url


def crawl(host: str, port: int, *, tls: bool,
          max_pages: int = 12, depth: int = 1,
          timeout: float = 4.0) -> Optional[dict]:
    """Crawl a web service, return dict of findings."""
    scheme = "https" if tls else "http"
    base = f"{scheme}://{host}:{port}"
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(base + "/", 0)]
    pages_fetched: list[dict] = []
    js_files_fetched: set[str] = set()
    api_endpoints: set[str] = set()
    forms: list[dict] = []

    while queue and len(pages_fetched) < max_pages:
        url, d = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        resp = _fetch(url, timeout=timeout)
        if resp is None:
            continue
        status, headers, body = resp
        body_text = body[:128_000].decode("utf-8", errors="replace")

        page_info = {
            "url": url,
            "status": status,
            "size": len(body),
            "content_type": headers.get("Content-Type",
                                         headers.get("content-type", "")),
        }
        # Title extraction
        m = re.search(r"<title[^>]*>([^<]+)</title>", body_text, re.I)
        if m:
            page_info["title"] = m.group(1).strip()[:120]
        pages_fetched.append(page_info)

        # Extract links
        links = _extract_links(body_text)
        api_endpoints.update(_extract_js_endpoints(body_text))

        # Forms — capture action + method
        for fm in re.finditer(
            r"""<form\s[^>]*?(?:action\s*=\s*["']([^"']+)["'])?[^>]*?>""",
            body_text, re.I
        ):
            action = fm.group(1)
            if action:
                forms.append({"page": url, "action": action})

        # Recurse: each link, if same-origin and within depth budget
        if d < depth:
            for link in links:
                abs_url = _same_origin(url, link)
                if not abs_url or abs_url in seen:
                    continue
                # Fetch .js files separately to mine endpoints, don't recurse into them
                if abs_url.endswith((".js", ".js?")):
                    if abs_url in js_files_fetched:
                        continue
                    js_files_fetched.add(abs_url)
                    js_resp = _fetch(abs_url, timeout=timeout)
                    if js_resp:
                        _, _, jb = js_resp
                        jtext = jb[:200_000].decode("utf-8", errors="replace")
                        api_endpoints.update(_extract_js_endpoints(jtext))
                    continue
                queue.append((abs_url, d + 1))

    return {
        "pages_crawled": pages_fetched,
        "forms": forms,
        "api_endpoints_found": sorted(api_endpoints)[:50],
        "js_files_fetched": sorted(js_files_fetched)[:20],
        "total_pages": len(pages_fetched),
    }
