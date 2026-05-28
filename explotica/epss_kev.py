"""EPSS + CISA KEV catalog enrichment for CVEs.

EPSS (Exploit Prediction Scoring System): probability that a CVE will be
exploited in the wild within the next 30 days. 0.0-1.0 scale. The single
best signal for prioritization beyond CVSS.

CISA KEV (Known Exploited Vulnerabilities): authoritative catalog of CVEs
that have been or are being actively exploited. Federal agencies are
required to patch these on a schedule.

We bulk-fetch the KEV catalog (one ~1MB JSON download, cached on disk),
and query EPSS with CVE batches for efficiency.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path
from threading import Lock
from typing import Optional

from .models import CVE

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CACHE_DIR = Path(
    os.environ.get("EXPLOTICA_CACHE_DIR",
                   Path.home() / ".cache" / "explotica")
)
CACHE_DIR.mkdir(parents=True, exist_ok=True)
KEV_CACHE = CACHE_DIR / "kev.json"
EPSS_CACHE = CACHE_DIR / "epss"
EPSS_CACHE.mkdir(parents=True, exist_ok=True)

KEV_TTL = 24 * 3600  # refresh daily
EPSS_TTL = 24 * 3600  # also daily

_kev_lock = Lock()
_kev_set: Optional[set[str]] = None


def _fetch_url(url: str, timeout: float = 30.0) -> Optional[bytes]:
    req = urllib.request.Request(
        url, headers={"User-Agent": "explotica/0.7.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as e:
        log.warning("fetch failed %s: %s", url, e)
        return None


def load_kev_catalog(force_refresh: bool = False) -> set[str]:
    """Load CISA KEV catalog, return set of CVE IDs known-exploited.

    Cached on disk for 24h. Returns empty set on fetch failure.
    """
    global _kev_set
    with _kev_lock:
        if _kev_set is not None and not force_refresh:
            return _kev_set

        # Try cache first
        if not force_refresh and KEV_CACHE.exists():
            age = time.time() - KEV_CACHE.stat().st_mtime
            if age < KEV_TTL:
                try:
                    data = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
                    _kev_set = {item["cveID"] for item in data.get("vulnerabilities", [])}
                    log.info("KEV: loaded %d CVE(s) from cache", len(_kev_set))
                    return _kev_set
                except (json.JSONDecodeError, KeyError, OSError):
                    pass

        log.info("KEV: fetching catalog from CISA…")
        raw = _fetch_url(KEV_URL)
        if raw is None:
            _kev_set = set()
            return _kev_set
        try:
            data = json.loads(raw.decode("utf-8"))
            KEV_CACHE.write_bytes(raw)
            _kev_set = {item["cveID"] for item in data.get("vulnerabilities", [])}
            log.info("KEV: %d known-exploited CVE(s) loaded", len(_kev_set))
            return _kev_set
        except (json.JSONDecodeError, KeyError) as e:
            log.warning("KEV parse failed: %s", e)
            _kev_set = set()
            return _kev_set


def _epss_cache_path(cve_id: str) -> Path:
    return EPSS_CACHE / f"{cve_id}.json"


def _epss_from_cache(cve_id: str) -> Optional[dict]:
    path = _epss_cache_path(cve_id)
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > EPSS_TTL:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _epss_write_cache(cve_id: str, payload: dict) -> None:
    try:
        _epss_cache_path(cve_id).write_text(
            json.dumps(payload), encoding="utf-8"
        )
    except OSError:
        pass


def fetch_epss_batch(cve_ids: list[str], batch_size: int = 100,
                     timeout: float = 20.0) -> dict[str, dict]:
    """Bulk-fetch EPSS scores for a list of CVEs. Returns {cve_id: {epss, percentile}}.

    Uses disk cache where available; only fetches uncached.
    """
    result: dict[str, dict] = {}
    uncached: list[str] = []

    for cid in cve_ids:
        c = _epss_from_cache(cid)
        if c is not None:
            result[cid] = c
        else:
            uncached.append(cid)

    if not uncached:
        return result

    # Batch the API calls — EPSS supports `?cve=CVE-1,CVE-2,...`
    for i in range(0, len(uncached), batch_size):
        batch = uncached[i:i + batch_size]
        params = urllib.parse.urlencode({"cve": ",".join(batch)})
        url = f"{EPSS_URL}?{params}"
        raw = _fetch_url(url, timeout=timeout)
        if raw is None:
            continue
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            continue
        for item in data.get("data", []):
            cid = item.get("cve")
            if not cid:
                continue
            payload = {
                "epss": float(item.get("epss", 0.0)),
                "percentile": float(item.get("percentile", 0.0)),
            }
            result[cid] = payload
            _epss_write_cache(cid, payload)

    return result


def enrich_cves_with_epss_kev(cves: list[CVE]) -> None:
    """Mutate the CVE list, adding EPSS scores + KEV flag in place."""
    if not cves:
        return

    # 1. KEV — single-pass set membership
    kev = load_kev_catalog()
    if kev:
        for c in cves:
            if c.id in kev:
                c.in_kev = True

    # 2. EPSS — bulk fetch
    ids = list({c.id for c in cves})
    epss = fetch_epss_batch(ids)
    if epss:
        for c in cves:
            payload = epss.get(c.id)
            if payload:
                c.epss_score = payload.get("epss")
                c.epss_percentile = payload.get("percentile")


def enrich_hosts_with_epss_kev(hosts) -> None:
    """Walk every CVE on every port and enrich with EPSS/KEV data."""
    all_cves: list[CVE] = []
    for h in hosts:
        for p in h.ports:
            all_cves.extend(p.cves)
    if not all_cves:
        return
    enrich_cves_with_epss_kev(all_cves)
