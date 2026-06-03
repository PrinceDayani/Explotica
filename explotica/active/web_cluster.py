"""Web-cluster orchestrator — ties Phase 73 audits to live HTTP ports.

Runs the opt-in advanced web audits (JWT cracking, GraphQL depth/cost/field,
DOM XSS, passive IDOR reference detection) against a host's HTTP(S) ports and
returns a structured per-port report. Each sub-audit lives in its own module;
this module is just the glue + the live HTTP I/O.

Honesty: every sub-audit already separates pure analysis from live execution.
This orchestrator only adds the network fetches and aggregates real results —
it surfaces "skipped"/"not found" rather than inventing findings, and DOM XSS
is skipped (with a reason) when Playwright is absent.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from ..enrich.http_audit import _send_http

log = logging.getLogger(__name__)

# A fuller GraphQL introspection query than http_audit's minimal probe — we
# need field return types to build the schema graph for cycle detection.
_FULL_INTROSPECTION = json.dumps({"query": """
query IntrospectionQuery {
  __schema {
    types {
      name kind
      fields(includeDeprecated: true) {
        name
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
    }
  }
}"""}).encode()


def _fetch(host: str, port: int, tls: bool, path: str = "/",
           timeout: float = 4.0):
    return _send_http(host, port, tls=tls, method="GET", path=path,
                      timeout=timeout)


def audit_jwts_on_port(host: str, port: int, tls: bool, *,
                       wordlist: Optional[list] = None,
                       timeout: float = 4.0) -> list[dict]:
    """Fetch the root page, extract JWTs, and run the offline JWT audit."""
    from .web_security import analyze_response  # reuses the JWT regex
    from . import jwt_audit
    resp = _fetch(host, port, tls, "/", timeout)
    if not resp:
        return []
    status, headers, body = resp
    analysis = analyze_response(headers, body, url_was_https=tls)
    out = []
    for jwt_entry in analysis.get("jwts", []):
        token = None
        # web_security stored a preview; re-find the full token from the body.
        import re
        m = re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
                      body.decode("utf-8", "replace"))
        token = m.group(0) if m else None
        if not token:
            continue
        audit = jwt_audit.audit_jwt(token, wordlist=wordlist)
        if audit and (audit.get("cracked_secret") or audit.get("findings")):
            out.append({"port": port, "token_preview": token[:48] + "…",
                        **audit})
    return out


def audit_graphql_on_port(host: str, port: int, tls: bool, *,
                          paths: Optional[list] = None,
                          timeout: float = 5.0) -> Optional[dict]:
    """Find a GraphQL endpoint, pull the full schema, run the depth/cost audit."""
    from . import graphql_audit
    paths = paths or ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
    for path in paths:
        resp = _send_http(host, port, tls=tls, method="POST", path=path,
                          headers={"Content-Type": "application/json"},
                          body=_FULL_INTROSPECTION, timeout=timeout)
        if not resp:
            continue
        status, _, body = resp
        if status != 200 or b"__schema" not in body:
            continue
        try:
            schema = json.loads(body.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            continue
        audit = graphql_audit.audit_schema(schema)
        audit["endpoint"] = path
        audit["port"] = port
        return audit
    return None


def detect_idor_refs(urls: list[str]) -> list[dict]:
    """Passive IDOR surface: type object references in discovered URLs.

    Confirmation needs two authenticated sessions (idor_audit.audit_idor); this
    just surfaces the candidates an analyst should test.
    """
    from . import idor_audit
    refs: list[dict] = []
    seen = set()
    for url in urls:
        for ref in idor_audit.detect_object_refs(url):
            key = (ref["location"], ref["param"], ref["value"])
            if key in seen:
                continue
            seen.add(key)
            ref["url"] = url
            refs.append(ref)
    return refs


def run_web_cluster(host: str, ports_tls: list[tuple], *,
                    discovered_urls: Optional[list] = None,
                    jwt_crack: bool = False, graphql_audit: bool = False,
                    dom_xss: bool = False, idor_passive: bool = False,
                    wordlist: Optional[list] = None,
                    timeout: float = 4.0) -> dict:
    """Run the enabled web-cluster audits across a host's HTTP(S) ports.

    ports_tls: list of (port, is_tls) tuples for open HTTP-ish ports.
    """
    result: dict = {"jwt": [], "graphql": [], "dom_xss": [], "idor_refs": []}

    for port, tls in ports_tls:
        if jwt_crack:
            try:
                result["jwt"].extend(audit_jwts_on_port(
                    host, port, tls, wordlist=wordlist, timeout=timeout))
            except Exception as e:
                log.debug("jwt audit %s:%d failed: %s", host, port, e)
        if graphql_audit:
            try:
                g = audit_graphql_on_port(host, port, tls, timeout=timeout)
                if g:
                    result["graphql"].append(g)
            except Exception as e:
                log.debug("graphql audit %s:%d failed: %s", host, port, e)
        if dom_xss:
            from . import dom_xss as domx
            scheme = "https" if tls else "http"
            if not domx.playwright_available():
                result["dom_xss_skipped"] = ("Playwright not installed — "
                                             "install to enable DOM XSS scan")
            else:
                try:
                    r = domx.scan_dom_xss(f"{scheme}://{host}:{port}/")
                    if r and r.get("findings"):
                        result["dom_xss"].append(r)
                except Exception as e:
                    log.debug("dom xss %s:%d failed: %s", host, port, e)

    if idor_passive and discovered_urls:
        result["idor_refs"] = detect_idor_refs(discovered_urls)

    # prune empties for compactness
    return {k: v for k, v in result.items() if v}
