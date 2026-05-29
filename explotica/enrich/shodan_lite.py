"""Free Shodan InternetDB integration — what does the internet know about this IP?

The endpoint `https://internetdb.shodan.io/<ip>` returns Shodan's cached
information about an IP. No API key needed, no auth, no rate limit
(within reason). Each response includes:
  - ports: list of TCP ports Shodan has observed open
  - vulns: list of CVE-IDs Shodan associates with this IP
  - hostnames: list of DNS names pointing at this IP
  - tags: high-level labels (router, iot, ssl-vuln, etc.)
  - cpes: CPE strings identifying observed software

This is useful for public IPs only — for RFC1918 / private IPs, you'll
get a 404 (Shodan doesn't scan private networks).

Cached on disk to avoid repeat queries during a single scan campaign.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
import urllib.request
from pathlib import Path
from typing import Optional

from ..core.constants import USER_AGENT

log = logging.getLogger(__name__)

INTERNETDB_URL = "https://internetdb.shodan.io"
TTL_SECONDS = 24 * 3600    # 24h cache

CACHE_DIR = Path(
    os.environ.get("EXPLOTICA_CACHE_DIR",
                   Path.home() / ".cache" / "explotica" / "shodan")
)
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _cache_path(ip: str) -> Path:
    return CACHE_DIR / f"{ip}.json"


def _read_cache(ip: str) -> Optional[dict]:
    p = _cache_path(ip)
    if not p.exists():
        return None
    if time.time() - p.stat().st_mtime > TTL_SECONDS:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(ip: str, payload: dict) -> None:
    try:
        _cache_path(ip).write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass


def lookup_ip(ip: str, timeout: float = 6.0) -> Optional[dict]:
    """Return Shodan InternetDB record for ip, or None.

    Skips private IPs (always 404). Cached on disk for 24h.
    """
    if _is_private(ip):
        log.debug("Shodan: %s is private, skipping", ip)
        return None

    cached = _read_cache(ip)
    if cached is not None:
        log.debug("Shodan cache hit for %s", ip)
        return cached

    url = f"{INTERNETDB_URL}/{ip}"
    req = urllib.request.Request(url, headers={
        "User-Agent": f"{USER_AGENT} (network-recon-toolkit)",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Shodan has nothing for this IP — cache a stub so we don't retry
            _write_cache(ip, {"shodan_404": True})
            return None
        log.debug("Shodan %s HTTP %d", ip, e.code)
        return None
    except Exception as e:
        log.debug("Shodan %s fetch error: %s", ip, e)
        return None

    # Normalize the response
    result = {
        "ip": data.get("ip", ip),
        "ports": sorted(data.get("ports", [])),
        "vulns": data.get("vulns", []),
        "hostnames": data.get("hostnames", []),
        "cpes": data.get("cpes", []),
        "tags": data.get("tags", []),
    }
    log.info("Shodan: %s → %d ports, %d vulns, %d tags",
             ip, len(result["ports"]), len(result["vulns"]),
             len(result["tags"]))
    _write_cache(ip, result)
    return result


def enrich_hosts_with_shodan(hosts, timeout: float = 6.0) -> None:
    """Run Shodan lookup for every host, attach to host's `shodan` field
    (lives inside udp_services for now since we don't have a dedicated dict).

    For public-IP scans, this is a major info source — Shodan often knows
    *more* ports than your active scan caught.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    targets = [h for h in hosts if not _is_private(h.ip)]
    if not targets:
        return

    def lookup(h):
        return (h, lookup_ip(h.ip, timeout=timeout))

    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = [pool.submit(lookup, h) for h in targets]
        for f in as_completed(futs):
            try:
                h, data = f.result()
            except Exception:
                continue
            if data is None or data.get("shodan_404"):
                continue
            # Store in udp_services as a "shodan" key — keeps schema flat
            if h.udp_services is None:
                h.udp_services = {}
            h.udp_services["shodan"] = data
