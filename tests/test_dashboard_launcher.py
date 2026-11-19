"""Tests for the dashboard scan-launcher (no fastapi/uvicorn required).

Focus: the security-sensitive surface — target validation (argparse-flag and
shell-metacharacter injection guards), the profile allowlist, and server-side
argv construction (which the browser must never be able to override).
"""

import tempfile
from pathlib import Path

import pytest

from explotica.output import dashboard as d


# ── target validation ────────────────────────────────────────────────────
@pytest.mark.parametrize("target", [
    "192.168.1.1",
    "192.168.1.0/24",
    "10.0.0.0/8",
    "example.com",
    "sub.example.com",
    "host-1.internal",
    "2001:db8::1",
    "fe80::1",
])
def test_valid_targets_pass(target):
    assert d.validate_target(target) is None


@pytest.mark.parametrize("target", [
    "",                       # empty
    "-rf",                    # leading dash → argparse flag injection
    "--full-coverage",        # flag injection
    "1.2.3.4 8.8.8.8",        # whitespace (two args)
    "1.2.3.4; rm -rf /",      # shell metacharacters
    "$(whoami)",              # command substitution
    "a`id`b",                 # backtick
    "host|nc",                # pipe
    "a" * 300,                # too long
])
def test_invalid_targets_rejected(target):
    assert d.validate_target(target) is not None


# ── profile allowlist ─────────────────────────────────────────────────────
def test_profiles_are_known_and_safe():
    # Every profile must exist with label/desc/flags and must NOT enable the
    # opt-in destructive super-preset from the web surface.
    assert set(d.PROFILES) >= {"discovery", "quick", "standard", "web", "full"}
    for key, meta in d.PROFILES.items():
        assert meta["label"] and meta["desc"]
        assert isinstance(meta["flags"], list)
        assert "--all-the-things" not in meta["flags"]


# ── argv construction ─────────────────────────────────────────────────────
def _mgr():
    return d.ScanJobManager(Path(tempfile.gettempdir()) / "explotica_dash_test")


def test_build_cmd_includes_yes_and_json_and_target():
    mgr = _mgr()
    job = {"target": "10.0.0.5", "profile": "quick",
           "aggressive": False, "out": "/tmp/out.json"}
    cmd = mgr._build_cmd(job)
    assert cmd[1:3] == ["-m", "explotica"]
    assert "10.0.0.5" in cmd
    assert "--yes" in cmd                       # non-interactive auth gate
    assert "--json" in cmd and "/tmp/out.json" in cmd
    # profile flags are present, in order
    assert "-p" in cmd and "top100" in cmd and "--vuln-scan" in cmd


def test_build_cmd_aggressive_adds_flag_once():
    mgr = _mgr()
    job = {"target": "10.0.0.5", "profile": "quick",
           "aggressive": True, "out": "/tmp/o.json"}
    cmd = mgr._build_cmd(job)
    assert cmd.count("--aggressive") == 1


def test_build_cmd_full_profile_does_not_double_aggressive():
    # --full-coverage already implies aggressive; don't append a second flag.
    mgr = _mgr()
    job = {"target": "10.0.0.5", "profile": "full",
           "aggressive": True, "out": "/tmp/o.json"}
    cmd = mgr._build_cmd(job)
    assert "--full-coverage" in cmd
    assert "--aggressive" not in cmd


def test_start_rejects_bad_target():
    mgr = _mgr()
    with pytest.raises(ValueError):
        mgr.start("--evil", "quick", False)


def test_start_rejects_unknown_profile():
    mgr = _mgr()
    with pytest.raises(ValueError):
        mgr.start("10.0.0.1", "no-such-profile", False)


def _no_run_mgr(monkeypatch):
    """Manager whose jobs never actually run (stay 'queued'), so start()'s
    bookkeeping can be tested without spawning scan subprocesses."""
    mgr = _mgr()
    monkeypatch.setattr(mgr, "_run", lambda job_id: None)
    return mgr


def test_job_limit_enforced(monkeypatch):
    mgr = _no_run_mgr(monkeypatch)
    for i in range(d._MAX_ACTIVE_JOBS):
        mgr.start(f"10.0.0.{i + 1}", "quick", False)
    with pytest.raises(RuntimeError):
        mgr.start("10.0.0.250", "quick", False)


def test_idempotency_key_returns_same_job(monkeypatch):
    mgr = _no_run_mgr(monkeypatch)
    j1 = mgr.start("10.0.0.5", "quick", False, idempotency_key="abc")
    j2 = mgr.start("10.0.0.5", "quick", False, idempotency_key="abc")
    assert j1["id"] == j2["id"]
    # The retry did not consume a second active slot.
    assert mgr.active_count() == 1


def test_publish_ordering_newer_wins(monkeypatch):
    mgr = _no_run_mgr(monkeypatch)
    # Newer scan (seq 5) publishes; an older one (seq 3) finishing later does not.
    assert mgr._mark_published(5) is True
    assert mgr._mark_published(3) is False
    assert mgr._mark_published(6) is True
