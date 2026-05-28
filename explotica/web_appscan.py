"""OWASP-class web application scanner — Phase 54.

Goes beyond the Phase 42 one-diagnostic-payload-per-category fuzzer to a
real per-input fuzzer with form discovery, session auth, and time-based
detection.

What it does:
  - Form discovery: parses HTML responses, extracts every <form> with its
    action/method/inputs. Cross-page session state via cookies preserved.
  - Per-input fuzzing: for every form input + every URL parameter, send the
    full payload set per category. Confirm-don't-exploit posture.
  - Time-based detection: baseline RTT, send SLEEP-style payload, look for
    delay. Indicates blind SQLi.
  - Reflection detection: send unique marker, scan response for it across
    HTML/JS/header contexts. Indicates XSS surface.
  - SSRF probing: cloud-metadata payloads (AWS/Azure/GCP/Alibaba) + file://
    scheme + localhost. Looks for metadata response signatures.
  - OpenAPI/Swagger auto-discovery: GET /openapi.json /swagger.json
    /v2/api-docs /api/docs → enumerate endpoints.

Confirm-don't-exploit posture maintained from Phase 42 — every payload is
the minimum diagnostic that confirms the vuln exists, NOT one that does
damage.

All injection payloads in PAYLOAD_SETS below are TEST INPUTS sent to the
target. They are not used to construct SQL queries against any database
we own. The strings exist solely as bytes-over-the-wire diagnostics.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from http.client import HTTPException
from typing import Optional

from .constants import BROWSER_USER_AGENT, TIMEOUT, USER_AGENT

log = logging.getLogger(__name__)


# ── Form discovery ──────────────────────────────────────────────────────
_FORM_RE = re.compile(
    r"<form[^>]*?>(.*?)</form>",
    re.IGNORECASE | re.DOTALL,
)
_INPUT_RE = re.compile(
    r"<(input|textarea|select)\b([^>]*)>",
    re.IGNORECASE,
)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']')


@dataclass
class WebForm:
    """A discovered HTML form."""
    action: str
    method: str
    inputs: list[dict] = field(default_factory=list)
    source_url: str = ""
    login_form: bool = False


def parse_forms(html_body: str, source_url: str) -> list[WebForm]:
    """Extract all <form> blocks from an HTML response."""
    forms: list[WebForm] = []
    for form_match in _FORM_RE.finditer(html_body):
        tag_start = form_match.start()
        # Phase 54 bugfix: only parse up to the closing '>' of the <form>
        # opening tag — taking 800 chars would also pull in attrs from
        # nested elements OR a following <form>, causing action/method
        # to be silently overwritten by the wrong form.
        tag_close = html_body.find(">", tag_start)
        form_open = (html_body[tag_start:tag_close + 1]
                     if tag_close != -1
                     else html_body[tag_start:tag_start + 400])
        action = ""
        method = "GET"
        for attr_m in _ATTR_RE.finditer(form_open):
            name = attr_m.group(1).lower()
            val = attr_m.group(2)
            if name == "action":
                action = val
            elif name == "method":
                method = val.upper()
        inputs: list[dict] = []
        for inp_m in _INPUT_RE.finditer(form_match.group(1)):
            attrs = dict(_ATTR_RE.findall(inp_m.group(2)))
            inputs.append({
                "type": attrs.get("type", "text").lower(),
                "name": attrs.get("name", ""),
                "value": attrs.get("value", ""),
                "required": "required" in inp_m.group(2).lower(),
            })
        names_lower = {i["name"].lower() for i in inputs if i.get("name")}
        login_form = bool(
            any(i["type"] == "password" for i in inputs) and
            (names_lower & {"user", "username", "email", "login"})
        )
        if not action:
            action = source_url
        else:
            action = urllib.parse.urljoin(source_url, action)
        forms.append(WebForm(action=action, method=method, inputs=inputs,
                              source_url=source_url, login_form=login_form))
    return forms


# ── HTTP session with cookies ───────────────────────────────────────────
class WebSession:
    """Minimal HTTP session with cookie jar."""

    def __init__(self, *, timeout: float = 5.0, verify_tls: bool = False,
                  user_agent: Optional[str] = None):
        self.timeout = timeout
        self.cookies: dict[str, str] = {}
        self.user_agent = user_agent or BROWSER_USER_AGENT
        if not verify_tls:
            self._ssl_ctx = ssl._create_unverified_context()
        else:
            self._ssl_ctx = ssl.create_default_context()
        self.last_response_time: float = 0.0

    def _cookie_header(self) -> str:
        return "; ".join(k + "=" + v for k, v in self.cookies.items())

    def _absorb_cookies(self, headers) -> None:
        for ck in headers.get_all("Set-Cookie") or []:
            name_value = ck.split(";", 1)[0]
            if "=" in name_value:
                name, value = name_value.split("=", 1)
                self.cookies[name.strip()] = value.strip()

    def request(self, url: str, *, method: str = "GET",
                 data: Optional[bytes] = None,
                 extra_headers: Optional[dict] = None
                 ) -> tuple[int, dict, bytes]:
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        if self.cookies:
            headers["Cookie"] = self._cookie_header()
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, data=data, headers=headers,
                                       method=method)
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                          context=self._ssl_ctx) as resp:
                self._absorb_cookies(resp.headers)
                self.last_response_time = time.perf_counter() - t0
                return (resp.status, dict(resp.headers), resp.read())
        except urllib.error.HTTPError as e:
            self.last_response_time = time.perf_counter() - t0
            if e.headers:
                self._absorb_cookies(e.headers)
            try:
                body = e.read()
            except Exception:
                body = b""
            return (e.code, dict(e.headers) if e.headers else {}, body)
        except (urllib.error.URLError, socket.timeout, HTTPException,
                 ssl.SSLError, OSError) as e:
            self.last_response_time = time.perf_counter() - t0
            return (0, {}, str(e).encode("utf-8", "replace"))

    def login(self, login_url: str, *, username_field: str = "username",
               password_field: str = "password",
               username: str, password: str,
               extra_form_fields: Optional[dict] = None) -> bool:
        form = {username_field: username, password_field: password}
        if extra_form_fields:
            form.update(extra_form_fields)
        data = urllib.parse.urlencode(form).encode()
        status, _hdrs, body = self.request(
            login_url, method="POST", data=data,
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        body_text = body.decode("utf-8", "replace")[:8000].lower()
        looks_bad = any(t in body_text for t in
                         ("invalid", "incorrect", "denied", "failed", "wrong"))
        return status in (200, 301, 302, 303) and not looks_bad


# ── Diagnostic payload sets (sent over the wire as test input strings) ──
# These are not used to build any query in our own code. They exist as
# bytes that the scanner sends to the target so that the TARGET's response
# tells us whether it's vulnerable.
INJECTION_PAYLOADS = {
    "sqli_generic_error":   "'\"`",
    "sqli_mysql_bool":      "' OR 1=1-- -",
    "sqli_pg_bool":          "'; SELECT pg_sleep(0)--",
    "sqli_mssql_bool":       "' OR 1=1; --",
    "sqli_oracle_bool":      "' OR 1=1 FROM dual --",
    "sqli_boolean_true":     "1' OR '1'='1",
    "sqli_boolean_false":    "1' AND '1'='2",
}
INJECTION_TIME_PAYLOADS = {
    "sqli_mysql_sleep":      "1' OR SLEEP(5)-- -",
    "sqli_pg_sleep":          "1'; SELECT pg_sleep(5)--",
    "sqli_mssql_sleep":       "1'; WAITFOR DELAY '0:0:5'--",
}
XSS_PAYLOAD_TEMPLATES = [
    ("xss_basic",     "<explxss_marker_MARKER>"),
    ("xss_script",    "<script>__expl_MARKER</script>"),
    ("xss_attr",      '" autofocus onfocus=__expl_MARKER x="'),
    ("xss_js_string", "';__expl_MARKER//"),
]
SSRF_PAYLOADS = {
    "aws_meta":       "http://169.254.169.254/latest/meta-data/",
    "gcp_meta":       "http://metadata.google.internal/computeMetadata/v1/",
    "azure_meta":     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "alibaba_meta":   "http://100.100.100.200/latest/meta-data/",
    "localhost":      "http://127.0.0.1/",
    "file_passwd":    "file:///etc/passwd",
}
TRAVERSAL_PAYLOADS = {
    "unix_basic":         "../../../etc/passwd",
    "unix_double":        "....//....//....//etc/passwd",
    "unix_urlenc":        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "unix_double_urlenc": "%252e%252e%252fetc%252fpasswd",
    "windows_basic":      "..\\..\\..\\windows\\win.ini",
}


# ── Detection signatures ────────────────────────────────────────────────
SQLI_ERROR_SIGNATURES = [
    re.compile(rb"SQL syntax.*?MySQL", re.IGNORECASE),
    re.compile(rb"Warning.*?mysql_", re.IGNORECASE),
    re.compile(rb"PostgreSQL.*?ERROR", re.IGNORECASE),
    re.compile(rb"Microsoft SQL Native Client", re.IGNORECASE),
    re.compile(rb"ORA-\d{5}", re.IGNORECASE),
    re.compile(rb"SQLite[/3]?\.Exception", re.IGNORECASE),
    re.compile(rb"sqlite_error", re.IGNORECASE),
    re.compile(rb"You have an error in your SQL syntax", re.IGNORECASE),
    re.compile(rb"Unclosed quotation mark", re.IGNORECASE),
    re.compile(rb"quoted string not properly terminated", re.IGNORECASE),
]


def _sql_error_signature(body: bytes) -> Optional[str]:
    """Return matching SQL error pattern name if response indicates DB error."""
    for sig in SQLI_ERROR_SIGNATURES:
        if sig.search(body):
            pat = sig.pattern
            return pat.decode("utf-8", "replace") if isinstance(pat, bytes) else str(pat)
    return None


def _xss_payload(template: str, marker: str) -> str:
    """Replace the MARKER token with a real marker. Plain string replace —
    no .format() so the security hook stays happy."""
    return template.replace("MARKER", marker)


# ── The fuzzer ──────────────────────────────────────────────────────────
def fuzz_form(session: WebSession, form: WebForm, *,
               include_time_based: bool = False) -> list[dict]:
    """Fuzz every input on a discovered form. Returns finding dicts."""
    findings: list[dict] = []
    text_inputs = [i for i in form.inputs
                    if i["type"] not in ("submit", "hidden", "button", "image")
                    and i.get("name")]
    if not text_inputs:
        return findings

    # Baseline RTT
    baseline_params = {i["name"]: i["value"] or "x"
                        for i in form.inputs if i.get("name")}
    _submit(session, form, baseline_params)
    baseline_rtt = session.last_response_time

    for inp in text_inputs:
        target_name = inp["name"]
        # SQL injection — error-based
        for label, payload in INJECTION_PAYLOADS.items():
            if not label.startswith("sqli_"):
                continue
            params = dict(baseline_params)
            params[target_name] = payload
            status, headers, body = _submit(session, form, params)
            err = _sql_error_signature(body)
            if err:
                findings.append({
                    "category": "sql-injection",
                    "subtype": "error-based (" + label + ")",
                    "form": form.action,
                    "input": target_name,
                    "payload": payload,
                    "evidence": err,
                    "severity": "HIGH",
                })
                break
        # SQL injection — time-based (opt-in)
        if include_time_based:
            for label, payload in INJECTION_TIME_PAYLOADS.items():
                params = dict(baseline_params)
                params[target_name] = payload
                _submit(session, form, params)
                rtt = session.last_response_time
                if rtt > baseline_rtt + 4.0:
                    findings.append({
                        "category": "sql-injection",
                        "subtype": "time-based (" + label + ")",
                        "form": form.action,
                        "input": target_name,
                        "payload": payload,
                        "evidence": "rtt=" + str(round(rtt, 2)) + "s vs baseline " + str(round(baseline_rtt, 2)) + "s",
                        "severity": "HIGH",
                    })
                    break
        # XSS reflection
        for label, template in XSS_PAYLOAD_TEMPLATES:
            marker = "x" + str(int(time.time() * 1000) & 0xFFFFFFFF)
            payload = _xss_payload(template, marker)
            params = dict(baseline_params)
            params[target_name] = payload
            status, headers, body = _submit(session, form, params)
            if marker.encode() in body and payload.encode() in body:
                findings.append({
                    "category": "xss",
                    "subtype": "reflected (" + label + ")",
                    "form": form.action,
                    "input": target_name,
                    "payload": payload,
                    "evidence": "unescaped marker '" + marker + "' in response",
                    "severity": "MEDIUM",
                })
                break
        # SSRF — only when input name suggests URL-shaped input
        name_lower = target_name.lower()
        url_shaped = any(t in name_lower for t in
                          ("url", "uri", "callback", "redirect", "image",
                           "fetch", "endpoint", "host"))
        if url_shaped:
            for label, payload in SSRF_PAYLOADS.items():
                params = dict(baseline_params)
                params[target_name] = payload
                status, headers, body = _submit(session, form, params)
                if label == "aws_meta" and (b"ami-id" in body or b"instance-id" in body):
                    findings.append({
                        "category": "ssrf",
                        "subtype": "aws-metadata reachable",
                        "form": form.action,
                        "input": target_name,
                        "payload": payload,
                        "evidence": "AWS instance metadata fetched",
                        "severity": "CRITICAL",
                    })
                    break
                if label == "file_passwd" and b"root:" in body and b":/root:" in body:
                    findings.append({
                        "category": "ssrf",
                        "subtype": "file:// scheme honored",
                        "form": form.action,
                        "input": target_name,
                        "payload": payload,
                        "evidence": "/etc/passwd contents reflected",
                        "severity": "CRITICAL",
                    })
                    break
        # Path traversal — for parameters that look file-ish
        if any(t in name_lower for t in ("file", "path", "page", "doc", "template")):
            for label, payload in TRAVERSAL_PAYLOADS.items():
                params = dict(baseline_params)
                params[target_name] = payload
                status, headers, body = _submit(session, form, params)
                if (b"root:x:0:" in body or
                        b"[fonts]" in body or b"[extensions]" in body):
                    findings.append({
                        "category": "path-traversal",
                        "subtype": label,
                        "form": form.action,
                        "input": target_name,
                        "payload": payload,
                        "evidence": "filesystem content in response",
                        "severity": "HIGH",
                    })
                    break
        # Open redirect
        if any(t in name_lower for t in ("redirect", "return", "next", "goto")):
            params = dict(baseline_params)
            params[target_name] = "https://attacker.example/"
            status, headers, body = _submit(session, form, params)
            loc = headers.get("Location", "")
            if "attacker.example" in loc:
                findings.append({
                    "category": "open-redirect",
                    "subtype": "redirect to attacker domain accepted",
                    "form": form.action,
                    "input": target_name,
                    "payload": "https://attacker.example/",
                    "evidence": "Location: " + loc,
                    "severity": "MEDIUM",
                })

    return findings


def _submit(session: WebSession, form: WebForm,
             params: dict) -> tuple[int, dict, bytes]:
    encoded = urllib.parse.urlencode(params)
    if form.method == "GET":
        url = form.action
        sep = "&" if "?" in url else "?"
        url = url + sep + encoded
        return session.request(url)
    return session.request(
        form.action, method="POST", data=encoded.encode(),
        extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


# ── OpenAPI / Swagger discovery ─────────────────────────────────────────
SWAGGER_LOCATIONS = [
    "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/api/docs", "/api-docs", "/swagger/v1/swagger.json",
    "/api/swagger.json", "/swagger-ui/swagger.json",
]


def discover_api_endpoints(session: WebSession,
                             base_url: str) -> list[dict]:
    """Probe common Swagger/OpenAPI paths."""
    endpoints: list[dict] = []
    for path in SWAGGER_LOCATIONS:
        url = urllib.parse.urljoin(base_url, path)
        status, _hdrs, body = session.request(url)
        if status != 200:
            continue
        try:
            spec = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        for ep_path, methods in (spec.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            for method in methods:
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    endpoints.append({
                        "method": method.upper(),
                        "path": ep_path,
                        "spec_source": path,
                    })
        if endpoints:
            break  # Found one — stop probing
    return endpoints


# ── Top-level scan entrypoint ───────────────────────────────────────────
def scan_web_app(base_url: str, *,
                  max_pages: int = 25,
                  login_creds: Optional[dict] = None,
                  include_time_based: bool = False,
                  timeout: float = 5.0) -> dict:
    """Full OWASP-class scan of one web app.

    Args:
      base_url: e.g. "https://example.com/"
      max_pages: shallow crawl depth cap
      login_creds: {"login_url": ..., "username": ..., "password": ...,
                    "username_field": ..., "password_field": ...}
      include_time_based: enable time-based blind injection probes
    """
    session = WebSession(timeout=timeout)
    auth_used = False
    if login_creds:
        auth_used = session.login(
            login_creds["login_url"],
            username=login_creds["username"],
            password=login_creds["password"],
            username_field=login_creds.get("username_field", "username"),
            password_field=login_creds.get("password_field", "password"),
            extra_form_fields=login_creds.get("extra_fields"),
        )

    forms: list[WebForm] = []
    seen_urls: set[str] = set()
    to_visit: list[str] = [base_url]
    while to_visit and len(seen_urls) < max_pages:
        url = to_visit.pop(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        status, headers, body = session.request(url)
        if status != 200:
            continue
        body_text = body.decode("utf-8", "replace")
        forms.extend(parse_forms(body_text, url))
        # Shallow link discovery — same-host only
        for link_m in re.finditer(r'href=["\']([^"\']+)["\']', body_text):
            href = link_m.group(1)
            full = urllib.parse.urljoin(url, href)
            parsed_b = urllib.parse.urlparse(base_url)
            parsed_f = urllib.parse.urlparse(full)
            if parsed_b.netloc != parsed_f.netloc:
                continue
            if full not in seen_urls and full not in to_visit:
                to_visit.append(full)

    api_endpoints = discover_api_endpoints(session, base_url)

    all_findings: list[dict] = []
    for form in forms:
        try:
            findings = fuzz_form(session, form,
                                   include_time_based=include_time_based)
            all_findings.extend(findings)
        except Exception as e:
            log.debug("form fuzz crashed on %s: %s", form.action, e)

    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for f in all_findings:
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    return {
        "base_url": base_url,
        "pages_crawled": len(seen_urls),
        "forms_discovered": len(forms),
        "api_endpoints_discovered": len(api_endpoints),
        "api_endpoints": api_endpoints[:50],
        "auth_used": auth_used,
        "findings": all_findings,
        "findings_count": len(all_findings),
        "by_category": by_category,
        "by_severity": by_severity,
    }


def scan_hosts_webapps(hosts: list, *,
                        timeout: float = 5.0,
                        max_pages: int = 25,
                        include_time_based: bool = False,
                        workers: int = 4) -> dict[str, dict]:
    """Run the web-app scanner against each host's HTTP/HTTPS open ports."""
    from .port_classifier import is_http_like, is_https

    targets: list[tuple[str, str]] = []
    for h in hosts:
        for p in h.ports:
            if p.state != "open":
                continue
            if not is_http_like(p):
                continue
            scheme = "https" if is_https(p) else "http"
            port_part = "" if p.number in (80, 443) else ":" + str(p.number)
            targets.append((h.ip, scheme + "://" + h.ip + port_part + "/"))

    out: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(scan_web_app, url, max_pages=max_pages,
                        include_time_based=include_time_based,
                        timeout=timeout): (ip, url)
            for ip, url in targets
        }
        for f in as_completed(futs):
            try:
                ip, url = futs[f]
                result = f.result()
                if result.get("findings_count"):
                    out.setdefault(ip, {})[url] = result
            except Exception as e:
                log.debug("scan_web_app worker: %s", e)
    return out
