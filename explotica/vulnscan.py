"""Vulnerability matching — extract product/version from banners, query NVD."""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from .models import CVE, Host, Port
from .nvd import lookup_cves

log = logging.getLogger(__name__)


# Each pattern returns (vendor, product, version) when matched against a banner.
# Vendor is the NVD vendor slug (lowercase, sometimes same as product).
# Order matters: more specific patterns should come first.
_BANNER_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # ── SSH ───────────────────────────────────────────────────────────
    (re.compile(r"SSH-\d+\.\d+-OpenSSH[_-](?P<v>[\d.p]+)", re.I),
     "openbsd", "openssh"),
    (re.compile(r"SSH-\d+\.\d+-Dropbear[_ ](?P<v>[\d.]+)", re.I),
     "matt_johnston", "dropbear_ssh"),

    # ── FTP ───────────────────────────────────────────────────────────
    (re.compile(r"\(ProFTPD\s+(?P<v>[\d.]+)", re.I),
     "proftpd", "proftpd"),
    (re.compile(r"vsFTPd\s+(?P<v>[\d.]+)", re.I),
     "vsftpd_project", "vsftpd"),
    (re.compile(r"Pure-FTPd\s+\[?(?P<v>[\d.]+)", re.I),
     "pureftpd", "pure-ftpd"),
    (re.compile(r"FileZilla Server\s+(?P<v>[\d.]+)", re.I),
     "filezilla-project", "filezilla_server"),
    (re.compile(r"NASFTPD\s+Turbo\s+Station\s+(?P<v>[\d.]+)", re.I),
     "synology", "diskstation_manager"),  # Synology NAS marker

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
    (re.compile(r"@RSYNCD:\s*(?P<v>[\d.]+)", re.I),
     "samba", "rsync"),

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
    """Fill in product/version/cves on a Port if banner can be parsed."""
    match = parse_banner(port.banner)
    if not match:
        return port
    vendor, product, version = match
    port.product_vendor = vendor
    port.product_name = product
    port.product_version = version
    try:
        port.cves = lookup_cves(vendor, product, version)
    except Exception as e:
        log.warning("CVE lookup failed for %s:%d (%s %s): %s",
                    ip, port.number, product, version, e)
    return port


def enrich_host(host: Host, workers: int = 4) -> Host:
    """Run banner parsing + CVE lookup for every port on a host.

    Parallel across this host's ports. NVD rate-limiter (in nvd.py) gates
    cross-host concurrency naturally.
    """
    if not host.ports:
        return host
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(enrich_port, host.ip, p) for p in host.ports]
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
