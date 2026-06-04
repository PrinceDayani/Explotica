"""TUI/CLI parity guard.

The TUI is an argv builder that shells out to the CLI, so every user-facing
security/recon module (a `store_true` CLI flag) should have a TUI widget too —
otherwise a capability exists but is undiscoverable from the TUI.

This test fails when a new boolean CLI flag is added without either wiring it
into the TUI or explicitly marking it CLI-only in CLI_ONLY_FLAGS below. That
forces the next module author to make a deliberate choice instead of silently
drifting the two front-ends apart.
"""

from __future__ import annotations

import pathlib
import re

import explotica

_PKG = pathlib.Path(explotica.__file__).parent
_CLI = (_PKG / "cli.py").read_text(encoding="utf-8")
_TUI = (_PKG / "ui" / "tui.py").read_text(encoding="utf-8")


# Boolean flags that are intentionally CLI-only: plumbing, output toggles,
# alternate entry points, and niche sub-options. NOT security modules.
CLI_ONLY_FLAGS = {
    "--async-io", "--auto-fallback", "--exclude-filtered", "--list-network",
    "--log-json", "--no-banners", "--open-only", "--platform-caps",
    "--safe-mode", "--shell", "--strict-scope", "--use-cred-vault", "--yes",
    "--sqli-time",          # sub-toggle of --web-fuzz, not a standalone module
}


def _cli_store_true_flags() -> set[str]:
    flags = set()
    for block in re.split(r"(?=p\.add_argument\()", _CLI):
        m = re.match(r"p\.add_argument\(\s*[\"'](--[a-z0-9-]+)[\"']", block)
        if m and "store_true" in block:
            flags.add(m.group(1))
    return flags


def _tui_referenced_flags() -> set[str]:
    return set(re.findall(r"[\"'](--[a-z0-9-]+)[\"']", _TUI))


def test_every_boolean_module_flag_is_reachable_from_tui():
    cli_bool = _cli_store_true_flags()
    tui = _tui_referenced_flags()
    should_be_in_tui = cli_bool - CLI_ONLY_FLAGS
    missing = should_be_in_tui - tui
    assert not missing, (
        "These boolean CLI module flags have no TUI widget. Either add a "
        "checkbox in explotica/ui/tui.py or, if it's genuinely CLI-only, add it "
        f"to CLI_ONLY_FLAGS in this test: {sorted(missing)}"
    )


def test_allowlist_has_no_stale_entries():
    # Keep the allowlist honest: every CLI_ONLY flag must still exist in the CLI.
    cli_bool = _cli_store_true_flags()
    stale = CLI_ONLY_FLAGS - cli_bool
    assert not stale, f"CLI_ONLY_FLAGS references removed flags: {sorted(stale)}"


def test_recently_added_clusters_are_wired():
    # Explicit spot-check for the AD + Web cluster modules this work wired in.
    tui = _tui_referenced_flags()
    for flag in ("--bloodhound", "--adcs-audit", "--ticket-risk",
                 "--jwt-crack", "--graphql-audit", "--dom-xss", "--idor-test",
                 "--web-security", "--web-appscan", "--syn-scan", "--osint"):
        assert flag in tui, f"{flag} should be reachable from the TUI"
