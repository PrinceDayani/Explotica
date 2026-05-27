"""Textual TUI — keyboard-driven interactive results browser.

Layout:
  - Left pane: host list (severity-colored)
  - Right pane: tabs for Ports / CVEs / Intel / Exploits
  - Bottom: status bar with stats + search field

Keybindings (vim-style):
  - j / k             — move down / up in host list
  - / + text + Enter  — filter
  - Tab               — cycle tabs
  - q                 — quit

Run:
  python -m explotica.tui scans/full.json
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def textual_available() -> bool:
    try:
        import textual  # noqa: F401
        return True
    except ImportError:
        return False


def _severity_of_host(h: dict) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    worst = "none"
    for p in h.get("ports", []):
        for c in p.get("cves", []):
            s = (c.get("severity") or "none").lower()
            if order.get(s, 0) > order.get(worst, 0):
                worst = s
    return worst


def _ip_sort_key(host_dict: dict) -> tuple:
    try:
        return tuple(int(o) for o in host_dict["ip"].split("."))
    except (ValueError, KeyError):
        return (999, 999, 999, 999)


def run(scan_json_path: str) -> int:
    if not textual_available():
        print("[!] textual library required for TUI.")
        print("    Install: pip install textual")
        return 1

    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.widgets import (
        Header, Footer, ListView, ListItem, Label, Static,
        TabbedContent, TabPane, Input, DataTable
    )
    from textual.binding import Binding
    from textual.reactive import reactive

    scan = json.loads(Path(scan_json_path).read_text(encoding="utf-8"))
    hosts = sorted(scan.get("hosts", []), key=_ip_sort_key)

    _SEV_COLORS = {
        "critical": "bold red",
        "high": "orange1",
        "medium": "yellow",
        "low": "green",
        "none": "dim",
    }

    class HostItem(ListItem):
        def __init__(self, host: dict):
            self.host = host
            sev = _severity_of_host(host)
            color = _SEV_COLORS.get(sev, "white")
            ports_count = len(host.get("ports", []))
            cves_count = sum(len(p.get("cves", [])) for p in host.get("ports", []))
            label_text = (
                f"[{color}]●[/{color}] {host['ip']:<15} "
                f"{(host.get('hostname') or '-')[:18]:<18} "
                f"[dim]{ports_count}p {cves_count}c[/dim]"
            )
            super().__init__(Label(label_text))

    class ExploticaTUI(App):
        CSS = """
        Screen { background: #0d1117; }
        Header { background: #161b22; color: #58a6ff; }
        Footer { background: #161b22; }
        #host-list { width: 42%; border: solid #30363d; background: #161b22; }
        #detail-pane { width: 58%; border: solid #30363d; background: #161b22; padding: 1 2; }
        ListView > ListItem { padding: 0 1; }
        ListView > ListItem.--highlight { background: #30363d; }
        TabbedContent { background: #161b22; }
        .stat-line { color: #8b949e; }
        .crit { color: #ff3b30; text-style: bold; }
        .high { color: #ff9500; }
        .med { color: #ffcc00; }
        .low { color: #34c759; }
        .kev { color: #ff3b30; text-style: bold; }
        """
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("/", "focus_search", "Search"),
            Binding("j", "down", "Down", show=False),
            Binding("k", "up", "Up", show=False),
            Binding("tab", "next_tab", "Next tab"),
            Binding("escape", "clear_search", "Clear filter"),
        ]

        filter_text: str = reactive("")

        def compose(self) -> ComposeResult:
            yield Header(name=f"Explotica — {scan.get('target','?')}")
            with Horizontal():
                with Vertical(id="host-list"):
                    yield Input(placeholder="filter (IP, hostname, CVE-ID)…",
                                id="search")
                    self.host_list = ListView(*[HostItem(h) for h in hosts],
                                                id="hosts")
                    yield self.host_list
                with VerticalScroll(id="detail-pane"):
                    yield Static("Select a host to see details",
                                  id="detail-content")
            yield Footer()

        def on_mount(self) -> None:
            # Pre-build stats string for header
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "kev": 0}
            for h in hosts:
                for p in h.get("ports", []):
                    for c in p.get("cves", []):
                        sev = (c.get("severity") or "").lower()
                        if sev in counts:
                            counts[sev] += 1
                        if c.get("in_kev"):
                            counts["kev"] += 1
            self.title = (
                f"Explotica · {len(hosts)} hosts · "
                f"{counts['critical']} crit · {counts['high']} high · "
                f"{counts['kev']} KEV"
            )
            if hosts:
                self.host_list.index = 0

        def on_list_view_highlighted(self, event) -> None:
            item = event.item
            if isinstance(item, HostItem):
                self.show_host(item.host)

        def show_host(self, h: dict) -> None:
            lines = []
            lines.append(f"[bold cyan]{h['ip']}[/bold cyan]")
            if h.get("hostname"):
                lines.append(f"  hostname: [cyan]{h['hostname']}[/cyan]")
            if h.get("mac"):
                lines.append(f"  MAC: {h['mac']}  vendor: {h.get('vendor') or '-'}")
            if h.get("os_hint"):
                oh = h["os_hint"]
                lines.append(
                    f"  OS: {oh.get('os_family','?')} "
                    f"({oh.get('hops_estimate','?')}h, TTL={h.get('ttl','?')})"
                )
            # UDP services / Shodan
            udp = h.get("udp_services") or {}
            if udp.get("shodan"):
                sh = udp["shodan"]
                lines.append(
                    f"  [dim]Shodan: {len(sh.get('ports', []))} ports, "
                    f"{len(sh.get('vulns', []))} CVEs, "
                    f"tags={','.join(sh.get('tags', []))}[/dim]"
                )
            lines.append("")

            for p in h.get("ports", []):
                svc = p.get("service") or ""
                prod = ""
                if p.get("product_name") and p.get("product_version"):
                    prod = f" [yellow]{p['product_name']} {p['product_version']}[/yellow]"
                lines.append(f"[bold green]{p['number']}/{p.get('protocol','tcp')}[/bold green]"
                              f" {svc}{prod}")
                if p.get("banner"):
                    b = p["banner"][:140]
                    lines.append(f"  [dim]{b}[/dim]")

                # CVEs sorted by KEV → EPSS → CVSS
                cves = sorted(
                    p.get("cves", []),
                    key=lambda c: (
                        not c.get("in_kev"),
                        -(c.get("epss_score") or 0),
                        -(c.get("cvss") or 0),
                    ),
                )
                for c in cves[:8]:
                    sev = (c.get("severity") or "unknown").lower()
                    cls = {"critical": "crit", "high": "high",
                           "medium": "med", "low": "low"}.get(sev, "")
                    score = f"{c.get('cvss'):.1f}" if c.get('cvss') is not None else "?"
                    marker = ""
                    if c.get("in_kev"):
                        marker += " [kev]KEV[/kev]"
                    if c.get("epss_score"):
                        marker += f" [dim]EPSS={c['epss_score']:.2f}[/dim]"
                    lines.append(
                        f"  [{cls}]{sev.upper():<8}[/{cls}] "
                        f"{score:>4}  [cyan]{c.get('id','')}[/cyan]{marker}"
                    )
                if len(cves) > 8:
                    lines.append(f"  [dim]+{len(cves)-8} more CVEs[/dim]")
                # Exploits
                for ex in (p.get("exploits") or [])[:3]:
                    edb = f"EDB-{ex.get('edb_id','?')}"
                    lines.append(f"  💥 [magenta]{edb}[/magenta]  {ex.get('title','')[:60]}")
                lines.append("")

            content = "\n".join(lines)
            try:
                self.query_one("#detail-content", Static).update(content)
            except Exception:
                pass

        def action_down(self) -> None:
            self.host_list.action_cursor_down()

        def action_up(self) -> None:
            self.host_list.action_cursor_up()

        def action_focus_search(self) -> None:
            try:
                self.query_one("#search", Input).focus()
            except Exception:
                pass

        def action_clear_search(self) -> None:
            try:
                inp = self.query_one("#search", Input)
                inp.value = ""
                self.filter_hosts("")
            except Exception:
                pass

        def action_next_tab(self) -> None:
            pass  # placeholder for tab cycling

        def on_input_changed(self, event) -> None:
            self.filter_hosts(event.value)

        def filter_hosts(self, q: str) -> None:
            q = q.lower().strip()
            self.host_list.clear()
            for h in hosts:
                if not q:
                    self.host_list.append(HostItem(h))
                    continue
                hay = (
                    h.get("ip", "").lower()
                    + " " + (h.get("hostname") or "").lower()
                )
                cve_match = any(
                    q in str(c.get("id", "")).lower()
                    for p in h.get("ports", [])
                    for c in p.get("cves", [])
                )
                if q in hay or cve_match:
                    self.host_list.append(HostItem(h))

    ExploticaTUI().run()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="explotica-tui",
        description="Interactive TUI for Explotica scan results."
    )
    p.add_argument("scan_json", help="Path to scan JSON file")
    args = p.parse_args(argv)
    if not Path(args.scan_json).exists():
        print(f"[!] Scan file not found: {args.scan_json}")
        return 2
    return run(args.scan_json)


if __name__ == "__main__":
    sys.exit(main())
