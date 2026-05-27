"""Subdomain takeover detection.

A subdomain takeover happens when a DNS record (typically a CNAME) points
to a third-party service (S3 bucket, GitHub Pages, Heroku app, etc.) that
no longer exists. An attacker can claim that resource name and serve
content under the victim's subdomain.

Detection:
  1. For each subdomain, resolve CNAME
  2. If CNAME points to a known-takeoverable service, HTTP-GET the subdomain
  3. Look for the service's "not found" fingerprint string in the response
  4. Match → likely takeover candidate

Fingerprint database adapted from public projects (subjack, can-i-take-over-xyz)
under permissive licenses.
"""

from __future__ import annotations

import logging
import socket
import ssl
import re
from typing import Optional

log = logging.getLogger(__name__)


# Each entry: cname_substring_to_match, fingerprint_in_response_body
TAKEOVER_FINGERPRINTS: list[dict] = [
    {
        "service": "GitHub Pages",
        "cname_contains": ["github.io"],
        "fingerprints": [b"There isn't a GitHub Pages site here",
                         b"404 - File not found"],
        "severity": "HIGH",
    },
    {
        "service": "Heroku",
        "cname_contains": ["herokuapp.com", "herokudns.com"],
        "fingerprints": [b"No such app", b"herokucdn.com/error-pages/no-such-app"],
        "severity": "HIGH",
    },
    {
        "service": "AWS S3 bucket",
        "cname_contains": ["s3.amazonaws.com", "s3-website"],
        "fingerprints": [b"NoSuchBucket", b"The specified bucket does not exist"],
        "severity": "CRITICAL",
    },
    {
        "service": "Azure Storage / CDN",
        "cname_contains": [".blob.core.windows.net", ".cloudapp.net",
                           ".cloudapp.azure.com", ".azureedge.net"],
        "fingerprints": [b"The specified resource does not exist"],
        "severity": "HIGH",
    },
    {
        "service": "Google Cloud Storage",
        "cname_contains": ["storage.googleapis.com"],
        "fingerprints": [b"NoSuchBucket"],
        "severity": "HIGH",
    },
    {
        "service": "Shopify",
        "cname_contains": [".myshopify.com"],
        "fingerprints": [b"Sorry, this shop is currently unavailable"],
        "severity": "HIGH",
    },
    {
        "service": "Fastly",
        "cname_contains": [".fastly.net"],
        "fingerprints": [b"Fastly error: unknown domain"],
        "severity": "HIGH",
    },
    {
        "service": "Tumblr",
        "cname_contains": ["domains.tumblr.com"],
        "fingerprints": [b"Whatever you were looking for doesn't currently exist"],
        "severity": "HIGH",
    },
    {
        "service": "Tilda",
        "cname_contains": ["tilda.ws"],
        "fingerprints": [b"Please renew your subscription"],
        "severity": "HIGH",
    },
    {
        "service": "WordPress.com",
        "cname_contains": ["wordpress.com"],
        "fingerprints": [b"Do you want to register"],
        "severity": "MEDIUM",
    },
    {
        "service": "Cargo Collective",
        "cname_contains": ["cargocollective.com"],
        "fingerprints": [b"404 Not Found"],
        "severity": "MEDIUM",
    },
    {
        "service": "Pantheon",
        "cname_contains": ["pantheonsite.io"],
        "fingerprints": [b"The gods are wise, but do not know of the site which you seek"],
        "severity": "HIGH",
    },
    {
        "service": "Squarespace",
        "cname_contains": ["squarespace.com"],
        "fingerprints": [b"No Such Account",
                         b"You're Almost There"],
        "severity": "MEDIUM",
    },
    {
        "service": "Bitbucket",
        "cname_contains": ["bitbucket.io"],
        "fingerprints": [b"Repository not found"],
        "severity": "HIGH",
    },
    {
        "service": "Ghost",
        "cname_contains": ["ghost.io"],
        "fingerprints": [b"The thing you were looking for is no longer here"],
        "severity": "MEDIUM",
    },
    {
        "service": "Readme.io",
        "cname_contains": ["readme.io"],
        "fingerprints": [b"Project doesnt exist"],
        "severity": "MEDIUM",
    },
    {
        "service": "Surge.sh",
        "cname_contains": ["surge.sh"],
        "fingerprints": [b"project not found"],
        "severity": "HIGH",
    },
    {
        "service": "UserVoice",
        "cname_contains": [".uservoice.com"],
        "fingerprints": [b"This UserVoice subdomain is currently available"],
        "severity": "MEDIUM",
    },
    {
        "service": "Zendesk",
        "cname_contains": ["zendesk.com"],
        "fingerprints": [b"Help Center Closed"],
        "severity": "LOW",
    },
    {
        "service": "Acquia",
        "cname_contains": ["acquia-sites.com"],
        "fingerprints": [b"The site you are looking for could not be found"],
        "severity": "MEDIUM",
    },
]


def _resolve_cname(name: str, dns_server: str = "8.8.8.8",
                    timeout: float = 4.0) -> Optional[str]:
    """Return CNAME target for `name`, or None."""
    from .dns_enum import _query, _RR_TYPES
    answers = _query(name, _RR_TYPES["CNAME"], server=dns_server,
                      timeout=timeout)
    return answers[0].rstrip(".") if answers else None


def _http_get(host: str, *, tls: bool = False, path: str = "/",
              timeout: float = 5.0) -> Optional[bytes]:
    """Fetch a URL — returns the response body bytes or None."""
    port = 443 if tls else 80
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(
            f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
            f"User-Agent: explotica\r\n\r\n".encode()
        )
        chunks: list[bytes] = []
        while True:
            try:
                ch = sock.recv(8192)
            except (socket.timeout, OSError, ssl.SSLError):
                break
            if not ch:
                break
            chunks.append(ch)
            if sum(len(c) for c in chunks) > 64 * 1024:
                break
        sock.close()
        return b"".join(chunks)
    except (socket.timeout, OSError, ssl.SSLError) as e:
        log.debug("takeover HTTP %s failed: %s", host, e)
        return None


def check_subdomain(subdomain: str, *, dns_server: str = "8.8.8.8",
                    timeout: float = 5.0) -> Optional[dict]:
    """Check one subdomain for takeover-ability.

    Returns dict on positive match or None.
    """
    cname = _resolve_cname(subdomain, dns_server, timeout)
    if not cname:
        return None

    cname_lower = cname.lower()
    matched_service = None
    for fp in TAKEOVER_FINGERPRINTS:
        for needle in fp["cname_contains"]:
            if needle.lower() in cname_lower:
                matched_service = fp
                break
        if matched_service:
            break
    if not matched_service:
        return None

    # CNAME points to a takeoverable provider — fetch and check body
    body = _http_get(subdomain, tls=False, timeout=timeout)
    if not body:
        body = _http_get(subdomain, tls=True, timeout=timeout)
    if not body:
        return {
            "subdomain": subdomain,
            "cname": cname,
            "service": matched_service["service"],
            "status": "cname_match_no_response",
            "severity": matched_service["severity"],
            "note": "CNAME points to takeoverable provider; HTTP unreachable",
        }

    for fingerprint in matched_service["fingerprints"]:
        if fingerprint in body:
            return {
                "subdomain": subdomain,
                "cname": cname,
                "service": matched_service["service"],
                "status": "takeoverable",
                "severity": matched_service["severity"],
                "fingerprint": fingerprint.decode("ascii", "ignore"),
                "note": (f"Subdomain takeover candidate: {matched_service['service']} "
                         f"returned 'not found' fingerprint"),
            }

    return None


def check_subdomains(subdomains: list[str], *, dns_server: str = "8.8.8.8",
                     timeout: float = 5.0, workers: int = 8) -> list[dict]:
    """Run takeover checks for many subdomains in parallel."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(check_subdomain, s, dns_server=dns_server,
                             timeout=timeout) for s in subdomains]
        for f in as_completed(futs):
            try:
                r = f.result()
                if r:
                    findings.append(r)
            except Exception as e:
                log.debug("takeover check error: %s", e)
    return findings
