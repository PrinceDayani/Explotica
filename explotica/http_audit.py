"""Deep HTTP application-layer audits.

  - OPTIONS methods enumeration (per URL): reveals DELETE/PUT/PATCH/WebDAV
  - CORS misconfiguration test (Origin reflection)
  - GraphQL introspection schema dump
  - WordPress user enumeration via REST API
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
from typing import Optional

log = logging.getLogger(__name__)


def _send_http(host: str, port: int, *, tls: bool, method: str,
               path: str = "/", headers: Optional[dict] = None,
               body: Optional[bytes] = None,
               timeout: float = 3.0,
               max_bytes: int = 32768) -> Optional[tuple[int, dict, bytes]]:
    """Send a single HTTP/1.0 request. Returns (status, headers, body) or None."""
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
        hlines = [f"{method} {path} HTTP/1.0",
                  f"Host: {host}",
                  "User-Agent: explotica/0.1",
                  "Connection: close"]
        if headers:
            for k, v in headers.items():
                hlines.append(f"{k}: {v}")
        if body:
            hlines.append(f"Content-Length: {len(body)}")
        req = ("\r\n".join(hlines) + "\r\n\r\n").encode()
        if body:
            req += body
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
        log.debug("http audit %s:%d %s %s failed: %s",
                  host, port, method, path, e)
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
        head, body_out = data.split(sep, 1)
    else:
        head, body_out = data, b""
    head_text = head.decode("utf-8", errors="replace")
    lines = head_text.split("\r\n")
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError):
        status = 0
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        hdrs[k.strip()] = v.strip()
    return (status, hdrs, body_out)


# ── OPTIONS methods enumeration ──────────────────────────────────────────
def audit_methods(host: str, port: int, *, tls: bool,
                  paths: Optional[list[str]] = None,
                  timeout: float = 3.0) -> dict:
    """OPTIONS-probe a list of URLs to enumerate allowed HTTP methods."""
    paths = paths or ["/"]
    findings: dict = {"by_path": {}}
    interesting_methods = {"DELETE", "PUT", "PATCH", "TRACE",
                           "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK"}
    for path in paths[:10]:
        resp = _send_http(host, port, tls=tls, method="OPTIONS",
                          path=path, timeout=timeout)
        if resp is None:
            continue
        status, hdrs, _ = resp
        allow = hdrs.get("Allow") or hdrs.get("allow") or ""
        public = hdrs.get("Public") or hdrs.get("public") or ""
        dav = hdrs.get("DAV") or hdrs.get("dav") or ""
        all_methods = set()
        for src in (allow, public):
            for m in re.split(r"[,\s]+", src):
                if m:
                    all_methods.add(m.strip().upper())
        risky = sorted(all_methods & interesting_methods)
        findings["by_path"][path] = {
            "status": status,
            "methods": sorted(all_methods),
            "risky_methods": risky,
            "dav": dav.strip() if dav else None,
        }
    risk = sorted({m for v in findings["by_path"].values() for m in v["risky_methods"]})
    findings["risky_methods_summary"] = risk
    return findings


# ── CORS misconfiguration ────────────────────────────────────────────────
def check_cors(host: str, port: int, *, tls: bool,
               timeout: float = 3.0) -> dict:
    """Send Origin: https://evil.example.com, check ACAO + ACAC headers."""
    evil = "https://evil.example.com"
    resp = _send_http(host, port, tls=tls, method="GET", path="/",
                      headers={"Origin": evil}, timeout=timeout)
    if resp is None:
        return {"tested": False}
    status, hdrs, _ = resp
    acao = (hdrs.get("Access-Control-Allow-Origin")
            or hdrs.get("access-control-allow-origin") or "").strip()
    acac = (hdrs.get("Access-Control-Allow-Credentials")
            or hdrs.get("access-control-allow-credentials") or "").strip()
    findings = {
        "tested": True,
        "origin_sent": evil,
        "access_control_allow_origin": acao,
        "access_control_allow_credentials": acac,
        "reflects_arbitrary_origin": acao == evil,
        "allows_credentials": acac.lower() == "true",
    }
    if findings["reflects_arbitrary_origin"] and findings["allows_credentials"]:
        findings["severity"] = "CRITICAL"
        findings["note"] = "CORS reflects Origin AND allows credentials — attacker site can read authenticated responses"
    elif findings["reflects_arbitrary_origin"]:
        findings["severity"] = "HIGH"
        findings["note"] = "CORS reflects arbitrary Origin (no credentials)"
    elif acao == "*":
        findings["severity"] = "LOW"
        findings["note"] = "Wildcard CORS (acceptable for public APIs without credentials)"
    return findings


# ── GraphQL introspection ────────────────────────────────────────────────
def graphql_introspect(host: str, port: int, *, tls: bool,
                       paths: Optional[list[str]] = None,
                       timeout: float = 4.0) -> Optional[dict]:
    """Try to fetch the GraphQL schema via the standard introspection query."""
    paths = paths or ["/graphql", "/api/graphql", "/v1/graphql"]
    intro_query = json.dumps({
        "query": "query IntrospectionQuery { __schema { types { name kind description fields { name } } } }"
    }).encode()
    headers = {"Content-Type": "application/json"}
    for path in paths:
        resp = _send_http(host, port, tls=tls, method="POST", path=path,
                          headers=headers, body=intro_query, timeout=timeout)
        if resp is None:
            continue
        status, _, body = resp
        if status != 200 or b"__schema" not in body:
            continue
        text = body.decode("utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        types = data.get("data", {}).get("__schema", {}).get("types", [])
        if not types:
            continue
        # Top-level object types (skip GraphQL meta-types)
        names = [
            t["name"] for t in types
            if t.get("name") and not t["name"].startswith("__")
            and t.get("kind") == "OBJECT"
        ]
        return {
            "endpoint": path,
            "introspection_enabled": True,
            "type_count": len(types),
            "object_types": sorted(names)[:30],
            "severity": "HIGH",
            "note": "GraphQL introspection enabled — full schema readable",
        }
    return None


# ── WordPress user enumeration ───────────────────────────────────────────
def wordpress_user_enum(host: str, port: int, *, tls: bool,
                        timeout: float = 4.0) -> Optional[dict]:
    """GET /wp-json/wp/v2/users -> array of WP user objects (id, name, slug)."""
    for path in ("/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users"):
        resp = _send_http(host, port, tls=tls, method="GET", path=path,
                          timeout=timeout)
        if resp is None:
            continue
        status, _, body = resp
        if status != 200 or not body.startswith(b"["):
            continue
        try:
            data = json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, list) or not data:
            continue
        users = []
        for u in data[:50]:
            if isinstance(u, dict):
                users.append({
                    "id": u.get("id"),
                    "name": u.get("name"),
                    "slug": u.get("slug"),
                })
        if users:
            return {
                "endpoint": path,
                "users": users,
                "count": len(users),
                "severity": "MEDIUM",
                "note": f"WordPress REST API exposes {len(users)} user(s) (login names + display names)",
            }
    return None


# ── Aggregate dispatcher ─────────────────────────────────────────────────
def audit_http(host: str, port: int, *, tls: bool,
               crawled_paths: Optional[list[str]] = None,
               timeout: float = 4.0) -> Optional[dict]:
    """Run all four audits against one HTTP(S) port; return aggregated dict."""
    paths_for_methods = ["/"]
    if crawled_paths:
        paths_for_methods.extend(crawled_paths[:8])

    result: dict = {}
    try:
        result["methods"] = audit_methods(host, port, tls=tls,
                                           paths=paths_for_methods,
                                           timeout=timeout)
    except Exception as e:
        log.debug("methods audit failed: %s", e)
    try:
        result["cors"] = check_cors(host, port, tls=tls, timeout=timeout)
    except Exception as e:
        log.debug("cors check failed: %s", e)
    try:
        gql = graphql_introspect(host, port, tls=tls, timeout=timeout)
        if gql:
            result["graphql"] = gql
    except Exception as e:
        log.debug("graphql introspect failed: %s", e)
    try:
        wp = wordpress_user_enum(host, port, tls=tls, timeout=timeout)
        if wp:
            result["wordpress"] = wp
    except Exception as e:
        log.debug("wp user enum failed: %s", e)
    return result if result else None
