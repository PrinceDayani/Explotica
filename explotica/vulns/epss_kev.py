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

from ..core.models import CVE

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


# ── Phase 58: EPSS expansion — classification + historical + combined ──
# EPSS scores break down into actionable tiers. Tenable VPR uses similar
# bucketing internally. Thresholds based on the FIRST.org EPSS team's
# guidance + KEV-correlation studies.
EPSS_TIERS = [
    (0.95, "critical-imminent"),  # top 5% — actively exploited likely
    (0.50, "high-likelihood"),    # 50-95% percentile
    (0.10, "moderate-risk"),      # 10-50%
    (0.01, "low-priority"),       # 1-10%
    (0.00, "negligible"),         # <1%
]


def classify_epss(epss_score: Optional[float]) -> str:
    """Map an EPSS score to a tier label."""
    if epss_score is None:
        return "unknown"
    for threshold, label in EPSS_TIERS:
        if epss_score >= threshold:
            return label
    return "negligible"


def classify_epss_percentile(percentile: Optional[float]) -> str:
    """Map an EPSS percentile to a tier label."""
    if percentile is None:
        return "unknown"
    if percentile >= 0.99:
        return "top-1pct"
    if percentile >= 0.95:
        return "top-5pct"
    if percentile >= 0.90:
        return "top-10pct"
    if percentile >= 0.50:
        return "above-median"
    return "below-median"


def fetch_epss_historical(cve_id: str, days: int = 30,
                            timeout: float = 20.0) -> list[dict]:
    """Fetch EPSS score history for a CVE over the past N days.

    EPSS API supports ?scope=time-series&cve=CVE-X — returns daily scores.
    Useful for detecting "score jumped recently" — a leading indicator of
    exploitation activity in the wild.
    """
    url = (EPSS_URL + "?scope=time-series&cve=" + cve_id
           + "&days=" + str(days))
    raw = _fetch_url(url, timeout=timeout)
    if raw is None:
        return []
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    history: list[dict] = []
    for item in data.get("data", []):
        ts_history = item.get("time-series") or []
        for entry in ts_history:
            history.append({
                "date": entry.get("date"),
                "epss": float(entry.get("epss", 0.0)),
                "percentile": float(entry.get("percentile", 0.0)),
            })
    history.sort(key=lambda h: h["date"] or "")
    return history


def fetch_epss_top_n(n: int = 1000, timeout: float = 30.0) -> list[dict]:
    """Pull the top-N riskiest CVEs by EPSS score from the feed.

    Useful for proactive prioritization — query the feed independent of
    any specific scan. Cached daily.
    """
    cache_path = EPSS_CACHE / ("top_" + str(n) + ".json")
    if cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < EPSS_TTL:
            try:
                return json.loads(cache_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
    url = EPSS_URL + "?order=!epss&limit=" + str(min(n, 5000))
    raw = _fetch_url(url, timeout=timeout)
    if raw is None:
        return []
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return []
    items = data.get("data", [])
    try:
        cache_path.write_text(json.dumps(items), encoding="utf-8")
    except OSError:
        pass
    return items


def epss_trend(cve_id: str, days: int = 30) -> Optional[dict]:
    """Compute a trend signal for one CVE: 'rising', 'falling', or 'stable'.

    Compares the latest 7-day average to the prior 23-day average. A 2×
    jump in either direction triggers the corresponding label.
    """
    history = fetch_epss_historical(cve_id, days=days)
    if len(history) < 14:
        return None
    recent = history[-7:]
    earlier = history[:-7]
    if not earlier:
        return None
    recent_avg = sum(h["epss"] for h in recent) / len(recent)
    earlier_avg = sum(h["epss"] for h in earlier) / max(len(earlier), 1)
    if earlier_avg == 0:
        return {"trend": "rising" if recent_avg > 0.01 else "stable",
                "recent_avg": recent_avg, "earlier_avg": earlier_avg}
    ratio = recent_avg / earlier_avg
    if ratio >= 2.0:
        trend = "rising"
    elif ratio <= 0.5:
        trend = "falling"
    else:
        trend = "stable"
    return {
        "trend": trend,
        "recent_avg": recent_avg,
        "earlier_avg": earlier_avg,
        "ratio": ratio,
        "data_points": len(history),
    }


def combined_risk_score(cve: CVE) -> dict:
    """Compute a combined risk score blending CVSS + EPSS + KEV.

    Output dict has:
      - 'score': 0-100 numeric (higher = more urgent)
      - 'tier': human label ('critical' / 'high' / 'medium' / 'low' / 'info')
      - 'reasons': list of contributing factors

    Weights (tunable):
      - CVSS contributes up to 40 points (cvss * 4)
      - EPSS contributes up to 30 points (epss * 30) — capped
      - KEV adds a flat 25 points
      - Top-1% EPSS percentile adds 5 points
    """
    score = 0.0
    reasons: list[str] = []

    if cve.cvss is not None:
        cvss_pts = min(40, cve.cvss * 4)
        score += cvss_pts
        reasons.append("CVSS " + str(round(cve.cvss, 1))
                        + " (+" + str(round(cvss_pts, 1)) + ")")

    if cve.epss_score is not None:
        epss_pts = min(30, cve.epss_score * 30)
        score += epss_pts
        reasons.append("EPSS " + str(round(cve.epss_score, 3))
                        + " (+" + str(round(epss_pts, 1)) + ")")

    if cve.in_kev:
        score += 25
        reasons.append("CISA KEV (+25)")

    if cve.epss_percentile is not None and cve.epss_percentile >= 0.99:
        score += 5
        reasons.append("top-1% EPSS percentile (+5)")

    if score >= 80:
        tier = "critical"
    elif score >= 60:
        tier = "high"
    elif score >= 40:
        tier = "medium"
    elif score >= 20:
        tier = "low"
    else:
        tier = "info"

    return {"score": round(score, 1), "tier": tier, "reasons": reasons}


def summarize_epss_kev_for_hosts(hosts) -> dict:
    """Summary metrics for dashboard / TUI display."""
    all_cves: list[CVE] = []
    for h in hosts:
        for p in h.ports:
            all_cves.extend(p.cves)
    if not all_cves:
        return {"total_cves": 0}
    in_kev = sum(1 for c in all_cves if c.in_kev)
    with_epss = sum(1 for c in all_cves if c.epss_score is not None)
    tier_counts: dict[str, int] = {}
    for c in all_cves:
        tier = classify_epss(c.epss_score)
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    risk_tier_counts: dict[str, int] = {}
    top_risk_cves: list[dict] = []
    for c in all_cves:
        rs = combined_risk_score(c)
        risk_tier_counts[rs["tier"]] = risk_tier_counts.get(rs["tier"], 0) + 1
        if rs["score"] >= 60:
            top_risk_cves.append({
                "id": c.id, "score": rs["score"], "tier": rs["tier"],
                "cvss": c.cvss, "epss": c.epss_score, "in_kev": c.in_kev,
            })
    top_risk_cves.sort(key=lambda x: -x["score"])
    return {
        "total_cves": len(all_cves),
        "unique_cves": len({c.id for c in all_cves}),
        "in_kev_count": in_kev,
        "with_epss_count": with_epss,
        "epss_tier_counts": tier_counts,
        "risk_tier_counts": risk_tier_counts,
        "top_risk": top_risk_cves[:50],
    }
