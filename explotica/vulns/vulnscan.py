"""Vulnerability matching — extract product/version from banners, query NVD."""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from ..core.models import CVE, Host, Port
from .nvd import lookup_cves

log = logging.getLogger(__name__)


# Each pattern returns (vendor, product, version) when matched against a banner.
# Vendor is the NVD vendor slug (lowercase, sometimes same as product).
# Order matters: more specific patterns should come first.
_BANNER_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # ── SSH ───────────────────────────────────────────────────────────
    # OpenSSH version can be like 7.4, 7.4p1, 8.2p1 — strip the p-suffix
    # because NVD CPEs use plain X.Y for the major version.
    (re.compile(r"SSH-\d+\.\d+-OpenSSH[_-](?P<v>\d+\.\d+(?:p\d+)?)", re.I),
     "openbsd", "openssh"),
    (re.compile(r"SSH-\d+\.\d+-dropbear[_ ]?(?P<v>\d+\.\d+(?:\.\d+)?)", re.I),
     "dropbear_ssh_project", "dropbear_ssh"),
    (re.compile(r"SSH-\d+\.\d+-libssh[_ -]?(?P<v>\d+\.\d+(?:\.\d+)?)", re.I),
     "libssh", "libssh"),

    # ── FTP ───────────────────────────────────────────────────────────
    # Synology's "NASFTPD Turbo Station X.Y.Z Server (ProFTPD)" — the X.Y.Z
    # is the ProFTPD version. Map directly to proftpd:proftpd CPE.
    (re.compile(r"NASFTPD\s+Turbo\s+Station\s+(?P<v>\d+\.\d+\.\d+)", re.I),
     "proftpd", "proftpd"),
    (re.compile(r"ProFTPD\s+(?P<v>\d+\.\d+\.\d+)", re.I),
     "proftpd", "proftpd"),
    (re.compile(r"vsFTPd\s+(?P<v>\d+\.\d+(?:\.\d+)?)", re.I),
     "vsftpd_project", "vsftpd"),
    (re.compile(r"Pure-FTPd\s+\[?(?P<v>\d+\.\d+(?:\.\d+)?)", re.I),
     "pureftpd", "pure-ftpd"),
    (re.compile(r"FileZilla Server\s+(?P<v>\d+\.\d+(?:\.\d+)?)", re.I),
     "filezilla-project", "filezilla_server"),

    # ── HTTP — Server header (needs --deep to capture reliably) ───────
    (re.compile(r"Server:\s*nginx/(?P<v>[\d.]+)", re.I),
     "nginx", "nginx"),
    (re.compile(r"Server:\s*Apache/(?P<v>[\d.]+)", re.I),
     "apache", "http_server"),
    (re.compile(r"Server:\s*Microsoft-IIS/(?P<v>[\d.]+)", re.I),
     "microsoft", "internet_information_services"),
    (re.compile(r"Server:\s*lighttpd/(?P<v>[\d.]+)", re.I),
     "lighttpd", "lighttpd"),
    (re.compile(r"Server:\s*Werkzeug/(?P<v>[\d.]+)", re.I),
     "pallets", "werkzeug"),
    (re.compile(r"Server:\s*gunicorn/(?P<v>[\d.]+)", re.I),
     "gunicorn", "gunicorn"),
    (re.compile(r"Server:\s*Caddy", re.I),
     "caddyserver", "caddy"),

    # ── SMTP ──────────────────────────────────────────────────────────
    (re.compile(r"Postfix\s+\(?(?P<v>[\d.]+)?", re.I),
     "postfix", "postfix"),
    (re.compile(r"Exim\s+(?P<v>[\d.]+)", re.I),
     "exim", "exim"),

    # ── Databases ─────────────────────────────────────────────────────
    (re.compile(r"MySQL.*?(?P<v>\d+\.\d+\.\d+)", re.I),
     "oracle", "mysql"),
    (re.compile(r"MariaDB.*?(?P<v>\d+\.\d+\.\d+)", re.I),
     "mariadb", "mariadb"),
    (re.compile(r"PostgreSQL\s+(?P<v>[\d.]+)", re.I),
     "postgresql", "postgresql"),

    # ── Rsync ─────────────────────────────────────────────────────────
    # NOTE: @RSYNCD: 31.0 reports the rsync PROTOCOL version (e.g. 31),
    # not the software version. NVD doesn't index by protocol number, so
    # we DON'T pattern-match this — it would just produce 0 hits and
    # mislead the user. To get rsync software version, --use-nmap or
    # check the banner directly. The mapping below would be:
    #   protocol 31 → rsync 3.1.x or 3.2.x (ambiguous)
    #   protocol 30 → rsync 3.0.x

    # ── Telnet ────────────────────────────────────────────────────────
    # (Telnet banners vary wildly; usually just OS strings)

    # ── Generic HTTP product/version in body of first 200 bytes ──────
    (re.compile(r"X-Powered-By:\s*PHP/(?P<v>[\d.]+)", re.I),
     "php", "php"),
]


def parse_banner(banner: Optional[str]) -> Optional[tuple[str, str, str]]:
    """Return (vendor, product, version) from a banner, or None if no match."""
    if not banner:
        return None
    for pattern, vendor, product in _BANNER_PATTERNS:
        m = pattern.search(banner)
        if m:
            try:
                version = m.group("v")
            except (IndexError, KeyError):
                version = ""
            if version:
                return (vendor, product, version)
    return None


def enrich_port(ip: str, port: Port) -> Port:
    """Fill in product/version/cves on a Port. Tries:
       1. Original regex set (banner parser)
       2. Service fingerprint DB (port + response → service)
    """
    match = parse_banner(port.banner)
    if not match:
        # Fallback: try the new fingerprint DB
        try:
            from ..fingerprint.service_fp_db import match_response
            banner_bytes = (port.banner or "").encode("utf-8", "ignore")
            fp = match_response(port.number, banner_bytes)
            if fp and fp.get("vendor") and fp.get("product"):
                match = (fp["vendor"], fp["product"], fp.get("version") or "")
                log.info("vulnscan %s:%d — matched via fp_db: %s/%s/%s",
                         ip, port.number, fp["vendor"], fp["product"],
                         fp.get("version"))
        except Exception as e:
            log.debug("fp_db lookup failed for %s:%d: %s",
                      ip, port.number, e)
    if not match:
        log.debug("vulnscan %s:%d — no banner pattern matched (%s)",
                  ip, port.number, (port.banner or "")[:80])
        return port
    vendor, product, version = match
    port.product_vendor = vendor
    port.product_name = product
    port.product_version = version
    log.info("vulnscan %s:%d — parsed %s:%s:%s, querying NVD…",
             ip, port.number, vendor, product, version)
    try:
        port.cves = lookup_cves(vendor, product, version)
    except Exception as e:
        log.warning("CVE lookup failed for %s:%d (%s %s): %s",
                    ip, port.number, product, version, e)
        return port
    log.info("vulnscan %s:%d — %d CVE(s) for %s:%s:%s",
             ip, port.number, len(port.cves), vendor, product, version)
    return port


def enrich_host(host: Host, workers: int = 4) -> Host:
    """Run banner parsing + CVE lookup for every port on a host.

    Parallel across this host's ports. NVD rate-limiter (in nvd.py) gates
    cross-host concurrency naturally.
    """
    if not host.ports:
        return host
    # Phase 56: enrich only OPEN ports — closed/filtered have no service
    # banner to parse against NVD, and active version probes would just
    # waste the deep-probe timeout budget.
    targets = [p for p in host.ports if p.state == "open"]
    if not targets:
        return host
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(enrich_port, host.ip, p) for p in targets]
        for _ in as_completed(futs):
            pass
    return host


def summarize_vulns(host: Host) -> dict:
    """Return counts of CVEs by severity across host's ports."""
    counts: dict[str, int] = {}
    for p in host.ports:
        for c in p.cves:
            counts[c.severity] = counts.get(c.severity, 0) + 1
    return counts
