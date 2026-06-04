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
