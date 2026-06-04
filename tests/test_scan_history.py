"""Tests for the shared scan-history index (shell + TUI data layer)."""

from __future__ import annotations

import json

import pytest

from explotica.ui import scan_history as H


@pytest.fixture
def scans_dir(tmp_path):
    def write(name, doc):
        (tmp_path / name).write_text(json.dumps(doc), encoding="utf-8")
    write("a.json", {
        "target": "10.0.0.0/24", "started_at": "2026-06-04T10:00:00+00:00",
        "duration_s": 320,
        "hosts": [
            {"is_up": True, "ports": [
                {"state": "open", "cves": [{"in_kev": True}, {"in_kev": False}]}]},
            {"is_up": False, "ports": []},
        ],
    })
    write("b.json", {
        "target": "192.168.1.5", "started_at": "2026-06-04T11:00:00+00:00",
        "duration_s": 12,
        "hosts": [{"is_up": True, "ports": [
            {"state": "open", "cves": []}, {"state": "closed", "cves": []}]}],
    })
    (tmp_path / "broken.json").write_text("{not valid", encoding="utf-8")
    # touch mtimes so ordering is deterministic: a older, b newer
    import os
    os.utime(tmp_path / "a.json", (1000, 1000))
    os.utime(tmp_path / "b.json", (2000, 2000))
    os.utime(tmp_path / "broken.json", (1500, 1500))
    return tmp_path


# ── Listing + parsing ─────────────────────────────────────────────────────────
def test_missing_dir_returns_empty():
    assert H.list_scans("definitely/not/a/dir") == []


def test_parses_counts(scans_dir):
    metas = {m.name: m for m in H.list_scans(scans_dir)}
    a = metas["a.json"]
    assert a.target == "10.0.0.0/24"
    assert a.host_count == 2 and a.up_count == 1
    assert a.open_ports == 1
    assert a.cve_count == 2 and a.kev_count == 1
    b = metas["b.json"]
    assert b.open_ports == 1 and b.cve_count == 0   # closed port not counted


def test_corrupt_file_is_a_row_not_a_crash(scans_dir):
    broken = next(m for m in H.list_scans(scans_dir) if m.name == "broken.json")
    assert broken.ok is False
    assert broken.error
    assert broken.row()[0].startswith("[corrupt]")


# ── Ranking ───────────────────────────────────────────────────────────────────
def test_sort_recent_newest_first(scans_dir):
    names = [m.name for m in H.list_scans(scans_dir, sort="recent")]
    assert names.index("b.json") < names.index("a.json")   # b is newer


def test_sort_risk_kev_first(scans_dir):
    metas = H.list_scans(scans_dir, sort="risk")
    assert metas[0].name == "a.json"                        # only one with KEV


def test_limit(scans_dir):
    assert len(H.list_scans(scans_dir, limit=1)) == 1


# ── Resolver ──────────────────────────────────────────────────────────────────
def test_resolve_by_index(scans_dir):
    # index 1 = newest in recent order = b.json
    assert H.resolve_scan("1", scans_dir).name == "b.json"


def test_resolve_by_bare_name(scans_dir):
    assert H.resolve_scan("a", scans_dir).name == "a.json"
    assert H.resolve_scan("a.json", scans_dir).name == "a.json"


def test_resolve_bad_ref(scans_dir):
    assert H.resolve_scan("999", scans_dir) is None
    assert H.resolve_scan("nope", scans_dir) is None
    assert H.resolve_scan("", scans_dir) is None


def test_resolve_direct_path(scans_dir):
    p = scans_dir / "a.json"
    assert H.resolve_scan(str(p), scans_dir) == p


# ── Formatting ────────────────────────────────────────────────────────────────
def test_duration_format():
    assert H._fmt_duration(12) == "12s"
    assert H._fmt_duration(320) == "5m"
    assert H._fmt_duration(7200) == "2.0h"


def test_age_format_buckets():
    import time
    now = time.time()
    assert H._fmt_age(now).endswith("s ago")
    assert H._fmt_age(now - 120).endswith("m ago")
    assert H._fmt_age(now - 7200).endswith("h ago")
    assert H._fmt_age(now - 200000).endswith("d ago")


def test_iso_to_local_handles_garbage():
    assert H.iso_to_local(None) == "?"
    assert H.iso_to_local("not-a-date")          # returns something, no raise
