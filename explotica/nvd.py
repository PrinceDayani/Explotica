"""NVD (National Vulnerability Database) API client with disk cache.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limits: 5 req / 30s anonymous, 50 req / 30s with API key.

We use urllib (stdlib only) to avoid adding `requests` as a dependency.
Responses are cached on disk keyed by CPE string with a TTL.
"""

from __future__ import annotations

import hashlib
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

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = 7 * 24 * 3600   # 7 days

# Default cache dir: ~/.cache/explotica/nvd  (or env override)
CACHE_DIR = Path(
    os.environ.get("EXPLOTICA_CACHE_DIR",
                   Path.home() / ".cache" / "explotica" / "nvd")
)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Rate limiting — global mutex + sliding window for anonymous tier.
_rate_lock = Lock()
_recent_calls: list[float] = []
_MAX_PER_WINDOW = 5
_WINDOW = 30.0

# Optional API key from env to lift rate limit.
NVD_API_KEY = os.environ.get("NVD_API_KEY")
if NVD_API_KEY:
    _MAX_PER_WINDOW = 50


def _rate_limit() -> None:
    """Block until we're under the rolling-window quota."""
    with _rate_lock:
        now = time.time()
        global _recent_calls
        _recent_calls = [t for t in _recent_calls if now - t < _WINDOW]
        if len(_recent_calls) >= _MAX_PER_WINDOW:
            wait = _WINDOW - (now - _recent_calls[0]) + 0.1
            log.debug("NVD rate limit reached, sleeping %.1fs", wait)
            time.sleep(max(0.0, wait))
            now = time.time()
            _recent_calls = [t for t in _recent_calls if now - t < _WINDOW]
        _recent_calls.append(now)


def _cache_path(cpe: str) -> Path:
    h = hashlib.sha1(cpe.encode()).hexdigest()[:16]
    return CACHE_DIR / f"{h}.json"


def _read_cache(cpe: str) -> Optional[dict]:
    path = _cache_path(cpe)
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > CACHE_TTL_SECONDS:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(cpe: str, data: dict) -> None:
    try:
        _cache_path(cpe).write_text(json.dumps(data), encoding="utf-8")
    except OSError as e:
        log.debug("NVD cache write failed: %s", e)


def _build_cpe(vendor: str, product: str, version: str) -> str:
    """Build a CPE 2.3 string. Lowercased; non-ascii stripped."""
    def norm(x: str) -> str:
        return urllib.parse.quote(x.lower().strip())
    return f"cpe:2.3:a:{norm(vendor)}:{norm(product)}:{norm(version)}:*:*:*:*:*:*:*"


def _fetch(cpe: str, timeout: float = 8.0) -> Optional[dict]:
    """One HTTP request to NVD. Returns parsed JSON or None on failure."""
    _rate_limit()
    params = urllib.parse.urlencode({"cpeName": cpe})
    url = f"{NVD_URL}?{params}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "explotica/0.1 (network-recon-toolkit)",
        **({"apiKey": NVD_API_KEY} if NVD_API_KEY else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            total = data.get("totalResults", 0)
            log.info("NVD: %s → %d CVE(s)%s", cpe, total,
                     "" if NVD_API_KEY else "  [no api key — rate limited]")
            return data
    except Exception as e:
        log.warning("NVD fetch FAILED for %s: %s", cpe, e)
        return None


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _parse_vulns(data: dict) -> list[CVE]:
    out: list[CVE] = []
    for entry in data.get("vulnerabilities", []):
        cve_data = entry.get("cve", {})
        cve_id = cve_data.get("id")
        if not cve_id:
            continue

        # Description (English)
        desc = next(
            (d.get("value") for d in cve_data.get("descriptions", [])
             if d.get("lang") == "en"), None
        )

        # CVSS — prefer v3.1, fall back to v3.0, then v2.
        metrics = cve_data.get("metrics", {})
        score: Optional[float] = None
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                m = arr[0]
                cvss_data = m.get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = (m.get("baseSeverity")
                            or cvss_data.get("baseSeverity")
                            or _severity_from_score(score or 0))
                break

        out.append(CVE(
            id=cve_id,
            severity=severity,
            cvss=score,
            summary=(desc or "")[:280] or None,
            published=cve_data.get("published"),
            source="NVD",
        ))
    # Sort: highest CVSS first
    out.sort(key=lambda c: -(c.cvss or 0))
    return out


def lookup_cves(vendor: str, product: str, version: str) -> list[CVE]:
    """Return list of CVEs matching the given product/version, sorted by severity.

    Cached on disk for 7 days. Returns [] on network failure, bad input,
    or no matches.
    """
    if not vendor or not product or not version:
        return []
    cpe = _build_cpe(vendor, product, version)
    cached = _read_cache(cpe)
    if cached is not None:
        log.debug("NVD cache hit: %s", cpe)
        return _parse_vulns(cached)

    log.info("NVD lookup: %s", cpe)
    data = _fetch(cpe)
    if data is None:
        # Cache a negative response too (with shorter TTL? we use same)
        return []
    _write_cache(cpe, data)
    return _parse_vulns(data)
