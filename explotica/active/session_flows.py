"""Stateful session engine — CSRF-rotation handling + multi-step flows.

Phase 73D. Two related limitations:
  - "No CSRF token rotation handling — login automation works but breaks on
    apps that rotate tokens."
  - "No multi-step session flows (cart -> checkout) — fuzzer is single-form
    scope."

Both need the same missing primitive: a session that carries cookies AND
re-extracts the anti-CSRF token from every response, re-injecting the freshest
token into each subsequent request. With that, a scripted flow
(login -> add-to-cart -> checkout) can run even when the server hands out a new
token on every page.

Honesty: the cookie jar, token extraction, and flow state machine are pure and
offline-unit-tested via an injectable transport. A real socket/TLS transport is
provided for live use, but the engine never claims a step succeeded unless the
(real or mocked) transport returned the expected status.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin

log = logging.getLogger(__name__)

# Transport contract: (method, url, headers, body) -> (status, headers, body).
Transport = Callable[[str, str, dict, bytes], "tuple[int, dict, bytes]"]


# ── cookie jar ────────────────────────────────────────────────────────────
class CookieJar:
    """A minimal cookie jar: ingest Set-Cookie, emit a Cookie header."""

    def __init__(self):
        self._cookies: dict[str, str] = {}

    def update(self, headers: dict) -> None:
        for key, val in headers.items():
            if key.lower() != "set-cookie":
                continue
            for raw in (val if isinstance(val, list) else [val]):
                first = raw.split(";", 1)[0].strip()
                if "=" in first:
                    name, _, value = first.partition("=")
                    self._cookies[name.strip()] = value.strip()

    def header(self) -> Optional[str]:
        if not self._cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    def get(self, name: str) -> Optional[str]:
        return self._cookies.get(name)

    def __len__(self):
        return len(self._cookies)


# ── anti-CSRF token extraction ────────────────────────────────────────────
# Field/param names commonly used for anti-CSRF tokens across frameworks.
CSRF_FIELD_NAMES = [
    "csrf_token", "csrftoken", "csrfmiddlewaretoken", "_token",
    "_csrf", "__RequestVerificationToken", "authenticity_token",
    "csrf", "xsrf_token", "_csrf_token", "anti-forgery-token",
]
CSRF_COOKIE_NAMES = ["XSRF-TOKEN", "csrftoken", "CSRF-TOKEN", "_csrf"]

_HIDDEN_INPUT_RE = re.compile(
    r'<input[^>]*type=["\']?hidden["\']?[^>]*>', re.IGNORECASE)
_NAME_RE = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)
_VALUE_RE = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)
_META_CSRF_RE = re.compile(
    r'<meta[^>]+name=["\'](?:csrf-token|_csrf)["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE)


def extract_tokens(html, headers: Optional[dict] = None,
                   jar: Optional[CookieJar] = None) -> dict:
    """Extract anti-CSRF tokens from an HTML body, meta tags, and cookies.

    Returns {field_name: token_value}. Re-running after each response is what
    makes rotation transparent.
    """
    if isinstance(html, (bytes, bytearray)):
        html = html.decode("utf-8", "replace")
    tokens: dict[str, str] = {}

    # Hidden form inputs whose name looks like a CSRF token.
    for tag in _HIDDEN_INPUT_RE.findall(html or ""):
        nm = _NAME_RE.search(tag)
        vl = _VALUE_RE.search(tag)
        if not nm:
            continue
        name = nm.group(1)
        if name.lower() in {n.lower() for n in CSRF_FIELD_NAMES}:
            tokens[name] = vl.group(1) if vl else ""

    # <meta name="csrf-token" content="...">
    m = _META_CSRF_RE.search(html or "")
    if m:
        tokens.setdefault("csrf-token", m.group(1))

    # Cookie-borne tokens (Angular/Laravel XSRF-TOKEN pattern).
    if jar is not None:
        for cname in CSRF_COOKIE_NAMES:
            cval = jar.get(cname)
            if cval:
                tokens.setdefault(cname, cval)
    return tokens


# ── session ────────────────────────────────────────────────────────────────
class Session:
    """Carries cookies + the freshest anti-CSRF tokens across requests."""

    def __init__(self, transport: Transport, *, base_url: str = ""):
        self.transport = transport
        self.base_url = base_url
        self.jar = CookieJar()
        self.tokens: dict[str, str] = {}
        self.history: list[dict] = []

    def request(self, method: str, url: str, *,
                data: Optional[dict] = None,
                headers: Optional[dict] = None,
                inject_csrf: bool = True) -> dict:
        full = urljoin(self.base_url, url) if self.base_url else url
        hdrs = dict(headers or {})
        cookie = self.jar.header()
        if cookie:
            hdrs["Cookie"] = cookie

        body = b""
        form = dict(data or {})
        if inject_csrf and self.tokens and method.upper() in ("POST", "PUT",
                                                              "PATCH"):
            # Inject the freshest token under whatever field name the app uses.
            for name, value in self.tokens.items():
                # Only override a form field whose name matches a CSRF field;
                # also send the cookie-token value back as a header (double
                # submit pattern) where applicable.
                if name in {n for n in CSRF_FIELD_NAMES}:
                    form[name] = value
                if name in CSRF_COOKIE_NAMES:
                    hdrs.setdefault("X-CSRF-Token", value)
                    hdrs.setdefault("X-XSRF-TOKEN", value)
        if form:
            from urllib.parse import urlencode
            body = urlencode(form).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")

        status, resp_headers, resp_body = self.transport(
            method.upper(), full, hdrs, body)

        # Update state AFTER the response — this re-captures rotated tokens.
        self.jar.update(resp_headers)
        fresh = extract_tokens(resp_body, resp_headers, self.jar)
        rotated = bool(fresh) and fresh != self.tokens
        if fresh:
            self.tokens.update(fresh)

        record = {"method": method.upper(), "url": full, "status": status,
                  "token_rotated": rotated,
                  "tokens_after": dict(self.tokens)}
        self.history.append(record)
        return {"status": status, "headers": resp_headers, "body": resp_body,
                **record}


# ── multi-step flow engine ────────────────────────────────────────────────
@dataclass
class FlowStep:
    name: str
    method: str
    url: str
    data: dict = field(default_factory=dict)
    expect_status: tuple = (200, 201, 204, 301, 302, 303)
    # Capture values from the response body for use in later steps:
    # {var_name: regex-with-one-group}
    extract: dict = field(default_factory=dict)


def _interpolate(value, captured: dict):
    """Replace {{var}} references in step data with captured values."""
    if isinstance(value, str):
        for k, v in captured.items():
            value = value.replace("{{" + k + "}}", str(v))
    return value


def run_flow(steps: list[FlowStep], transport: Transport, *,
             base_url: str = "") -> dict:
    """Execute a multi-step flow, threading cookies, rotated CSRF tokens, and
    captured variables across steps.

    Returns a per-step report. A step `ok` iff the transport returned an
    expected status — never assumed.
    """
    session = Session(transport, base_url=base_url)
    captured: dict[str, str] = {}
    results: list[dict] = []
    all_ok = True

    for step in steps:
        data = {k: _interpolate(v, captured) for k, v in step.data.items()}
        url = _interpolate(step.url, captured)
        resp = session.request(step.method, url, data=data)
        ok = resp["status"] in step.expect_status
        all_ok = all_ok and ok

        body_text = resp["body"]
        if isinstance(body_text, (bytes, bytearray)):
            body_text = body_text.decode("utf-8", "replace")
        for var, pattern in step.extract.items():
            m = re.search(pattern, body_text)
            if m:
                captured[var] = m.group(1) if m.groups() else m.group(0)

        results.append({
            "step": step.name, "method": step.method.upper(), "url": resp["url"],
            "status": resp["status"], "ok": ok,
            "token_rotated": resp["token_rotated"],
            "captured": dict(captured),
        })
        if not ok:
            log.debug("flow step %s failed (status %s) — halting",
                      step.name, resp["status"])
            break

    return {"completed": all_ok and len(results) == len(steps),
            "steps": results, "final_cookies": len(session.jar),
            "captured": captured}


# ── real socket transport (live use) ──────────────────────────────────────
def socket_transport(method: str, url: str, headers: dict,
                     body: bytes, *, timeout: float = 8.0
                     ) -> "tuple[int, dict, bytes]":
    """A real HTTP/1.1 transport over sockets with TLS support.

    Used for live flows. Kept dependency-free; redirects are NOT auto-followed
    (the flow engine decides), so 302s surface as real statuses.
    """
    import socket
    import ssl
    from urllib.parse import urlparse
    p = urlparse(url)
    tls = p.scheme == "https"
    port = p.port or (443 if tls else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    from ..core.constants import USER_AGENT
    lines = [f"{method} {path} HTTP/1.1", f"Host: {p.hostname}",
             f"User-Agent: {USER_AGENT}", "Accept: */*", "Connection: close"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b"")
    try:
        sock = socket.create_connection((p.hostname, port), timeout=timeout)
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=p.hostname)
        sock.sendall(raw)
        chunks = []
        while True:
            ch = sock.recv(16384)
            if not ch:
                break
            chunks.append(ch)
        sock.close()
    except (OSError, ssl.SSLError) as e:
        log.debug("socket_transport %s %s failed: %s", method, url, e)
        return (-1, {}, b"")
    data = b"".join(chunks)
    head, _, resp_body = data.partition(b"\r\n\r\n")
    head_lines = head.decode("latin-1", "replace").split("\r\n")
    try:
        status = int(head_lines[0].split(" ")[1])
    except (IndexError, ValueError):
        status = 0
    resp_headers: dict = {}
    for line in head_lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip(), v.strip()
            if k.lower() == "set-cookie":
                resp_headers.setdefault("Set-Cookie", [])
                if isinstance(resp_headers["Set-Cookie"], list):
                    resp_headers["Set-Cookie"].append(v)
            else:
                resp_headers[k] = v
    return (status, resp_headers, resp_body)
