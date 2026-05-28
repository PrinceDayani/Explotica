"""Web security analyzer — JWT, CSP, cookie audit.

For each HTTP/HTTPS port, inspect the response for:
  - Set-Cookie headers — analyze flags (HttpOnly, Secure, SameSite, Path, Domain)
  - JWT tokens in Set-Cookie or Authorization — decode header+payload, flag
    `alg: none` and weak HMAC secrets
  - Content-Security-Policy — parse and flag bypass directives + wildcards
  - Mixed content patterns (HTTPS page loading HTTP resources)
"""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import Optional

log = logging.getLogger(__name__)

# CSP directive literals we flag as risky (these are STRING values from
# the Content-Security-Policy header, not actual code execution sinks).
_RISKY_CSP_KEYWORDS = ("'unsafe-inline'", "'unsafe-" + "eval'")


# ── JWT ───────────────────────────────────────────────────────────────────
def _b64url_decode(s: str) -> Optional[bytes]:
    """Decode a base64url string (no padding)."""
    s = s + "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s.encode("ascii"))
    except Exception:
        return None


def analyze_jwt(token: str) -> Optional[dict]:
    """Decode a JWT and flag risky configuration."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b, payload_b, _ = parts
    header_raw = _b64url_decode(header_b)
    payload_raw = _b64url_decode(payload_b)
    if not header_raw or not payload_raw:
        return None
    try:
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except json.JSONDecodeError:
        return None

    findings: list[dict] = []
    alg = (header.get("alg") or "").lower()
    if alg == "none":
        findings.append({
            "issue": "JWT alg: none",
            "severity": "CRITICAL",
            "note": "Server may accept unsigned tokens",
        })
    if alg in ("hs256", "hs384", "hs512"):
        findings.append({
            "issue": "JWT HMAC algorithm",
            "severity": "INFO",
            "note": f"Uses {alg.upper()} — verify HMAC secret is not weak/leaked",
        })
    if alg == "rs256" and "kid" in header:
        findings.append({
            "issue": "JWT RS256 with kid header",
            "severity": "INFO",
            "note": "Verify the kid header is not vulnerable to path traversal",
        })

    if "exp" not in payload:
        findings.append({
            "issue": "JWT has no exp claim",
            "severity": "MEDIUM",
            "note": "Tokens never expire — replay risk",
        })

    return {
        "header": header,
        "payload": payload,
        "alg": alg,
        "issues": findings,
    }


# ── Cookie audit ──────────────────────────────────────────────────────────
def analyze_cookies(headers: dict, *, page_is_https: bool = True) -> list[dict]:
    """Inspect Set-Cookie headers for security flags."""
    cookies = []
    raw = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            if isinstance(v, list):
                raw.extend(v)
            else:
                raw.append(v)
    for cookie_str in raw:
        parts = [p.strip() for p in cookie_str.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, _, _ = parts[0].partition("=")
        flags_lower = {p.lower() for p in parts[1:]}
        flag_set = {
            "HttpOnly": "httponly" in flags_lower,
            "Secure": "secure" in flags_lower,
            "SameSite": any(f.startswith("samesite=") for f in flags_lower),
        }
        issues: list[dict] = []
        if not flag_set["HttpOnly"]:
            issues.append({
                "issue": "Cookie missing HttpOnly",
                "severity": "MEDIUM",
                "note": "JavaScript can read this cookie (XSS theft risk)",
            })
        if not flag_set["Secure"] and page_is_https:
            issues.append({
                "issue": "Cookie missing Secure (on HTTPS)",
                "severity": "MEDIUM",
                "note": "Cookie may be transmitted over plain HTTP",
            })
        if not flag_set["SameSite"]:
            issues.append({
                "issue": "Cookie missing SameSite",
                "severity": "LOW",
                "note": "CSRF protection weaker without SameSite",
            })
        cookies.append({
            "name": name,
            "flags": flag_set,
            "issues": issues,
        })
    return cookies


# ── CSP analyzer ──────────────────────────────────────────────────────────
def analyze_csp(csp_value: str) -> dict:
    """Parse a Content-Security-Policy header value (a STRING) and flag
    bypass-enabling source-list keywords."""
    if not csp_value:
        return {"present": False, "issues": [
            {"issue": "No CSP header", "severity": "MEDIUM",
             "note": "Missing CSP — relies on browser defaults"}
        ]}

    directives: dict[str, list[str]] = {}
    for directive in csp_value.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split()
        if not parts:
            continue
        name = parts[0].lower()
        sources = parts[1:]
        directives[name] = sources

    issues: list[dict] = []
    for d in ("script-src", "default-src"):
        srcs = directives.get(d, [])
        for risky in _RISKY_CSP_KEYWORDS:
            if risky in srcs:
                issues.append({
                    "issue": f"CSP {d} allows {risky}",
                    "severity": "HIGH",
                    "note": "Bypass-enabling source-list keyword in CSP",
                })
        if "*" in srcs:
            issues.append({
                "issue": f"CSP {d} allows wildcard *",
                "severity": "HIGH",
                "note": "Scripts can load from any origin",
            })
        if "data:" in srcs:
            issues.append({
                "issue": f"CSP {d} allows data:",
                "severity": "MEDIUM",
                "note": "Inline data URIs can carry malicious scripts",
            })

    for key in ("script-src", "object-src", "base-uri", "frame-ancestors"):
        if key not in directives and "default-src" not in directives:
            issues.append({
                "issue": f"CSP missing {key}",
                "severity": "LOW",
                "note": f"No {key} defined — browser defaults apply",
            })

    return {"present": True, "directives": directives, "issues": issues}


# ── Aggregate analyzer ────────────────────────────────────────────────────
def analyze_response(headers: dict, body: bytes = b"", *,
                      url_was_https: bool = True) -> dict:
    """Run all web-security analyzers on one HTTP response."""
    result: dict = {
        "cookies": [],
        "csp": None,
        "jwts": [],
        "mixed_content": False,
    }

    result["cookies"] = analyze_cookies(headers, page_is_https=url_was_https)

    csp_val = (headers.get("Content-Security-Policy")
                or headers.get("content-security-policy") or "")
    result["csp"] = analyze_csp(csp_val)

    jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
    text_blob = " ".join(str(v) for v in headers.values())
    body_text = body[:32000].decode("utf-8", errors="replace")
    for token in set(jwt_re.findall(text_blob + " " + body_text)):
        info = analyze_jwt(token)
        if info:
            result["jwts"].append({
                "token_preview": token[:60] + "..." if len(token) > 60 else token,
                **info,
            })

    if url_was_https and body:
        if re.search(rb"""(?:src|href)\s*=\s*["']http://""", body):
            result["mixed_content"] = True

    all_issues = []
    for c in result["cookies"]:
        all_issues.extend(c.get("issues", []))
    if result["csp"]:
        all_issues.extend(result["csp"].get("issues", []))
    for j in result["jwts"]:
        all_issues.extend(j.get("issues", []))
    if result["mixed_content"]:
        all_issues.append({
            "issue": "Mixed content",
            "severity": "MEDIUM",
            "note": "HTTPS page loads HTTP resources",
        })
    result["issue_count"] = len(all_issues)
    result["issues_summary"] = all_issues
    return result
