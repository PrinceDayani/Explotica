"""Tests for shell UX upgrades: context prompt + scan-history commands."""

from __future__ import annotations

import json

import pytest

from explotica.ui.shell import ExploticaShell
from explotica.core.models import ScanResult


def _doc(target="10.0.0.0/24", kev=1, extra_cves=1, hosts=2):
    cves = [{"id": f"CVE-{i}", "in_kev": i < kev} for i in range(kev + extra_cves)]
    host_list = [{"ip": "10.0.0.5", "is_up": True,
                  "ports": [{"number": 22, "protocol": "tcp", "state": "open",
                             "cves": cves}]}]
    for n in range(hosts - 1):
        host_list.append({"ip": f"10.0.0.{6 + n}", "is_up": True, "ports": []})
    return {"target": target, "started_at": "2026-06-04T10:00:00+00:00",
            "finished_at": "2026-06-04T10:05:00+00:00", "duration_s": 300,
            "scanner_version": "0.8.0", "hosts": host_list}


# ── Context-aware prompt ──────────────────────────────────────────────────────
def test_prompt_is_plain_when_empty():
    sh = ExploticaShell()
    assert sh.scan_result is None
    assert sh.prompt == "[bold green]explotica>[/bold green] "


def test_prompt_shows_target_hosts_and_cves():
    sh = ExploticaShell()
    sh.scan_result = ScanResult.from_dict(_doc(hosts=2, kev=1, extra_cves=1))
    sh._update_prompt()
    assert "10.0.0.0/24" in sh.prompt
    assert "2h" in sh.prompt           # 2 hosts
    assert "2cve" in sh.prompt         # 2 CVEs total
    assert "1kev" in sh.prompt         # 1 KEV


def test_prompt_omits_cve_segment_when_none():
    sh = ExploticaShell()
    sh.scan_result = ScanResult.from_dict(_doc(kev=0, extra_cves=0))
    sh._update_prompt()
    assert "cve" not in sh.prompt
    assert "kev" not in sh.prompt


def test_prompt_truncates_long_target():
    sh = ExploticaShell()
    sh.scan_result = ScanResult.from_dict(_doc(target="a" * 50))
    sh._update_prompt()
    assert "…" in sh.prompt


def test_clear_resets_prompt():
    sh = ExploticaShell()
    sh.scan_result = ScanResult.from_dict(_doc())
    sh._update_prompt()
    sh.do_clear("")
    assert sh.prompt == "[bold green]explotica>[/bold green] "


# ── scans / load commands ─────────────────────────────────────────────────────
def test_do_scans_handles_empty(monkeypatch):
    import explotica.ui.shell as shellmod
    monkeypatch.setattr("explotica.ui.scan_history.list_scans", lambda **k: [])
    sh = ExploticaShell()
    # Should not raise, just print a hint.
    assert sh.do_scans("") is False


def test_do_load_by_index(tmp_path, monkeypatch):
    scan_file = tmp_path / "s.json"
    scan_file.write_text(json.dumps(_doc()), encoding="utf-8")
    # resolve_scan('1') -> our temp file
    monkeypatch.setattr("explotica.ui.scan_history.resolve_scan",
                        lambda ref, *a, **k: scan_file if ref == "1" else None)
    sh = ExploticaShell()
    sh.do_load("1")
    assert sh.scan_result is not None
    assert sh.scan_result.target == "10.0.0.0/24"
    # prompt updated to reflect the load
    assert "10.0.0.0/24" in sh.prompt


def test_do_load_bad_ref_is_graceful(monkeypatch):
    monkeypatch.setattr("explotica.ui.scan_history.resolve_scan",
                        lambda ref, *a, **k: None)
    sh = ExploticaShell()
    assert sh.do_load("999") is False
    assert sh.scan_result is None
