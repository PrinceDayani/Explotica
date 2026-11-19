"""Tests for the previously-untested CVE prioritizer and OUI lookup."""
from explotica.vulns.prioritize import score_cve, _bucket, score_port
from explotica.fingerprint import oui


# ── prioritize ────────────────────────────────────────────────────────────
def test_bucket_thresholds():
    assert _bucket(95) == "CRITICAL"
    assert _bucket(80) == "CRITICAL"
    assert _bucket(79.9) == "HIGH"
    assert _bucket(60) == "HIGH"
    assert _bucket(40) == "MEDIUM"
    assert _bucket(20) == "LOW"
    assert _bucket(0) == "INFO"


def test_kev_and_exploit_raise_score():
    low = score_cve(cvss=5.0)
    high = score_cve(cvss=5.0, in_kev=True, has_exploit=True)
    assert high["score"] > low["score"]
    assert any("KEV" in r for r in high["reasons"])


def test_critical_cve_scores_high():
    r = score_cve(cvss=9.8, epss=0.9, in_kev=True, has_exploit=True)
    assert r["bucket"] in ("CRITICAL", "HIGH")
    assert r["score"] > 60


def test_empty_signal_is_zero():
    r = score_cve()
    assert r["score"] == 0
    assert r["bucket"] == "INFO"


def test_score_port_sorts_desc():
    port = {
        "number": 443,
        "cves": [
            {"id": "CVE-1", "cvss": 3.0},
            {"id": "CVE-2", "cvss": 9.5, "in_kev": True},
        ],
    }
    scored = score_port(port)
    assert scored[0]["score"] >= scored[-1]["score"]


# ── oui ──────────────────────────────────────────────────────────────────
def test_oui_known_vendor():
    assert oui.lookup("00:50:56:11:22:33") == "VMware"


def test_oui_formats_tolerated():
    # Different separators / case should resolve the same vendor.
    v1 = oui.lookup("00-50-56-aa-bb-cc")
    v2 = oui.lookup("005056AABBCC")
    assert v1 == v2 == "VMware"


def test_oui_unknown_and_none():
    assert oui.lookup(None) is None
    assert oui.lookup("ZZ:ZZ:ZZ:00:00:00") is None
