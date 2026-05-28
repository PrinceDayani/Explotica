"""NVD (National Vulnerability Database) API client with disk cache.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limits: 5 req / 30s anonymous, 50 req / 30s with API key.

We use urllib (stdlib only) to avoid adding `requests` as a dependency.
Responses are cached on disk keyed by CPE string with a TTL.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import socket
import ssl
import time
import urllib.parse
import urllib.request
from concurrent.futures import Future
from pathlib import Path
from threading import Lock, Semaphore
from typing import Optional

from .models import CVE

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Phase 58: vuln DB cache max-age is 1 day per user requirement. The NVD
# corpus updates daily; stale cache risks missing newly-published CVEs.
# Override via $EXPLOTICA_NVD_TTL_SECONDS env var if you really need longer.
CACHE_TTL_SECONDS = int(os.environ.get(
    "EXPLOTICA_NVD_TTL_SECONDS",
    str(24 * 3600),     # 1 day
))

# Default cache dir: ~/.cache/explotica/nvd  (or env override)
CACHE_DIR = Path(
    os.environ.get("EXPLOTICA_CACHE_DIR",
                   Path.home() / ".cache" / "explotica" / "nvd")
)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Rate limiting — semaphore lets multiple HTTPS calls be in-flight up to the
# quota, instead of serializing them through a lock. The bookkeeping lock is
# only held during quota math, not during the actual network call.
_WINDOW = 30.0
_MAX_PER_WINDOW = 5  # anonymous tier
NVD_API_KEY = os.environ.get("NVD_API_KEY")
if NVD_API_KEY:
    _MAX_PER_WINDOW = 50

_quota = Semaphore(_MAX_PER_WINDOW)
_book_lock = Lock()
_call_history: list[float] = []  # timestamps of calls released back


def _acquire_quota_slot() -> None:
    """Block until a slot in the rolling window is free, then take it."""
    _quota.acquire()  # blocks if all slots in use


def _release_quota_slot() -> None:
    """Schedule the slot to be released after WINDOW elapsed since the call.

    Releasing immediately would allow burst-of-N then nothing for 30s. We
    instead delay release so the *rolling* window holds.
    """
    def _delayed_release(ts: float) -> None:
        # Sleep until WINDOW seconds have passed since the call started
        elapsed = time.time() - ts
        if elapsed < _WINDOW:
            time.sleep(_WINDOW - elapsed)
        _quota.release()

    import threading as _t
    ts = time.time()
    with _book_lock:
        _call_history.append(ts)
    _t.Thread(target=_delayed_release, args=(ts,), daemon=True).start()


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


# ── HTTP keep-alive connection pool ───────────────────────────────────────
# Reuse one HTTPSConnection per thread (thread-local) so we don't pay the
# TLS handshake cost (~150ms) on every CVE lookup.

import threading as _threading
_conn_local = _threading.local()
_NVD_HOST = "services.nvd.nist.gov"
_NVD_PATH_BASE = "/rest/json/cves/2.0"


def _get_conn() -> http.client.HTTPSConnection:
    conn = getattr(_conn_local, "conn", None)
    if conn is None:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(_NVD_HOST, timeout=10,
                                           context=ctx)
        _conn_local.conn = conn
    return conn


def _reset_conn() -> None:
    conn = getattr(_conn_local, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    _conn_local.conn = None


def _fetch(cpe: str, timeout: float = 10.0) -> Optional[dict]:
    """One HTTP request to NVD with HTTP keep-alive + quota gating."""
    _acquire_quota_slot()
    try:
        params = urllib.parse.urlencode({"cpeName": cpe})
        path = f"{_NVD_PATH_BASE}?{params}"
        from .constants import USER_AGENT
        headers = {
            "User-Agent": f"{USER_AGENT} (network-recon-toolkit)",
            "Accept": "application/json",
            "Connection": "keep-alive",
        }
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        # Retry once on connection failure (keep-alive can race with server close)
        for attempt in range(2):
            try:
                conn = _get_conn()
                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()
                body = resp.read()
                if resp.status != 200:
                    log.warning("NVD HTTP %d for %s", resp.status, cpe)
                    return None
                data = json.loads(body.decode("utf-8"))
                total = data.get("totalResults", 0)
                log.info("NVD: %s → %d CVE(s)%s", cpe, total,
                         "" if NVD_API_KEY else "  [anon rate-limited]")
                return data
            except (http.client.HTTPException, OSError, socket.error) as e:
                log.debug("NVD attempt %d failed for %s: %s; resetting conn",
                          attempt + 1, cpe, e)
                _reset_conn()
                if attempt == 1:
                    log.warning("NVD fetch FAILED for %s: %s", cpe, e)
                    return None
        return None
    finally:
        _release_quota_slot()


# ── In-process CPE → result cache (per-run dedup) ────────────────────────
# If 20 hosts share the same (vendor, product, version), only ONE thread
# actually hits NVD. Others receive the same result via Future.
_inflight_lock = Lock()
_inflight: dict[str, Future] = {}


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


def _lookup_uncached(cpe: str) -> list[CVE]:
    """Hit disk cache then NVD; called inside the inflight-dedup wrapper."""
    cached = _read_cache(cpe)
    if cached is not None:
        log.debug("NVD disk-cache hit: %s", cpe)
        return _parse_vulns(cached)

    log.info("NVD lookup: %s", cpe)
    data = _fetch(cpe)
    if data is None:
        return []
    _write_cache(cpe, data)
    return _parse_vulns(data)


def lookup_cves(vendor: str, product: str, version: str) -> list[CVE]:
    """Return list of CVEs matching the given product/version, sorted by severity.

    Three-tier cache:
      1. In-process inflight dedup (same CPE within current run → one query)
      2. Disk cache (7 days TTL)
      3. NVD API
    """
    if not vendor or not product or not version:
        return []
    cpe = _build_cpe(vendor, product, version)

    # Acquire-or-create the inflight future for this CPE
    with _inflight_lock:
        fut = _inflight.get(cpe)
        owner = False
        if fut is None:
            fut = Future()
            _inflight[cpe] = fut
            owner = True

    if owner:
        try:
            result = _lookup_uncached(cpe)
            fut.set_result(result)
        except Exception as e:
            fut.set_exception(e)
        finally:
            # Don't remove from _inflight — keep result available for late
            # arrivals. Cache lifetime = process lifetime.
            pass

    try:
        return fut.result(timeout=60)
    except Exception as e:
        log.warning("NVD inflight lookup failed for %s: %s", cpe, e)
        return []
