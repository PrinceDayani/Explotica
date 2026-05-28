"""TUI configuration — user-editable action presets.

Actions are loaded from `~/.config/explotica/actions.json` (or the path in
$EXPLOTICA_TUI_CONFIG). If the file doesn't exist on first launch, a default
set is written there so the user has something to edit.

Edit the file in any text editor while the TUI is closed. Add, remove, or
modify entries. Format:

  {
    "host_actions": [
      {
        "key": "v",
        "label": "✅ Verify probes",
        "flags": ["--ports", "top1000", "--verify-cves", "--no-arp"],
        "description": "Heartbleed/MS17/Shellshock/+18 more"
      },
      ...
    ]
  }

Each action's `flags` get appended to the explotica subprocess command for
the selected host(s). Use `--from-json-merge` as a sentinel to skip target
and re-enrich the existing scan instead.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# ── Default actions (used to seed the config on first run) ───────────────
DEFAULT_HOST_ACTIONS = [
    {
        "key": "a",
        "label": "🔥 Full re-scan (all the things)",
        "flags": ["--ports", "top1000", "--all-the-things", "--turbo"],
        "description": "Every passive + active module. Authorized scans only."
    },
    {
        "key": "v",
        "label": "✅ Verify probes (Heartbleed/MS17/Shellshock/+18)",
        "flags": ["--ports", "top1000", "--verify-cves", "--verify-cves-v2",
                   "--no-arp"],
        "description": "21 hand-written confirm-don't-exploit probes"
    },
    {
        "key": "d",
        "label": "🔎 Deep scan (vuln + nmap + searchsploit)",
        "flags": ["--ports", "top1000", "--vuln-scan", "--deep", "--use-nmap",
                   "--use-searchsploit", "--epss-kev", "--no-arp"],
        "description": "Standard pentest baseline"
    },
    {
        "key": "r",
        "label": "🏷️ Rich intel only (TLS/HTTP/SMB)",
        "flags": ["--ports", "top1000", "--rich-intel", "--deep", "--no-arp"],
        "description": "Identify what this host is + how it's configured"
    },
    {
        "key": "c",
        "label": "🔓 Default credential check",
        "flags": ["--ports", "top1000", "--check-default-creds", "--no-arp"],
        "description": "FTP anon, admin/admin, Redis no-auth, etc."
    },
    {
        "key": "f",
        "label": "💉 Web fuzz (path/XSS/CRLF/SSRF)",
        "flags": ["--ports", "top100", "--web-fuzz", "--no-arp"],
        "description": "One diagnostic payload per category"
    },
    {
        "key": "p",
        "label": "📊 Compute priorities (re-score existing data)",
        "flags": ["--from-json-merge", "--prioritize"],
        "description": "Smart score: CVSS+EPSS+KEV+exposure"
    },
    {
        "key": "o",
        "label": "🎯 OS fingerprint (deep)",
        "flags": ["--ports", "top1000", "--os-fp-db", "--rich-intel", "--no-arp"],
        "description": "Multi-signal OS classification"
    },
    {
        "key": "s",
        "label": "🔍 Quick scan (top 100 ports)",
        "flags": ["--ports", "top100", "--vuln-scan", "--no-arp"],
        "description": "Fast triage — ~10-30 seconds"
    },
    {
        "key": "F",
        "label": "🌐 Full-coverage everything (safe)",
        "flags": ["--ports", "top1000", "--full-coverage", "--ultra", "--no-arp"],
        "description": "Comprehensive but skips active attacks"
    },
    {
        "key": "K",
        "label": "🏢 AS-REP roast (Kerberos)",
        "flags": ["--from-json-merge", "--ad-enum", "{prompt:domain}",
                   "--asrep-roast"],
        "description": "Extract hashcat-format hashes"
    },
    {
        "key": "x",
        "label": "⚙️ Custom flags…",
        "flags": None,
        "description": "Prompts for free-form scan flags"
    },
]


def config_path() -> Path:
    """Where the TUI config lives.

    Order of preference:
      1. $EXPLOTICA_TUI_CONFIG environment variable
      2. $XDG_CONFIG_HOME/explotica/actions.json
      3. ~/.config/explotica/actions.json
    """
    env = os.environ.get("EXPLOTICA_TUI_CONFIG")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "explotica" / "actions.json"
    return Path.home() / ".config" / "explotica" / "actions.json"


def load_actions() -> list[dict]:
    """Load action presets from the config file, or seed defaults.

    Returns a list of action dicts ready to use by the TUI.
    """
    p = config_path()
    if not p.exists():
        # First run — write defaults so the user sees something to edit
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(
                {"host_actions": DEFAULT_HOST_ACTIONS}, indent=2
            ), encoding="utf-8")
            log.info("seeded default action config at %s", p)
        except OSError as e:
            log.warning("could not write config seed at %s: %s", p, e)
        return list(DEFAULT_HOST_ACTIONS)

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        actions = data.get("host_actions") or []
        if not actions:
            log.warning("config at %s has no host_actions; using defaults", p)
            return list(DEFAULT_HOST_ACTIONS)
        return actions
    except (json.JSONDecodeError, OSError) as e:
        log.warning("could not parse config %s: %s — using defaults", p, e)
        return list(DEFAULT_HOST_ACTIONS)


def save_actions(actions: list[dict]) -> Path:
    """Persist the actions back to the config file."""
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"host_actions": actions}, indent=2),
                  encoding="utf-8")
    return p


def reset_to_defaults() -> Path:
    """Restore the default actions; returns the config path."""
    return save_actions(DEFAULT_HOST_ACTIONS)
