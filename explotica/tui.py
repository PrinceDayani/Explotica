"""Textual TUI — full polished terminal app for Explotica.

Features:
  - Multi-tab layout: Hosts / CVEs / Ports / Exploits / Compliance / Extra
  - DataTables with sortable columns + severity coloring
  - Detail pane updates on host/CVE selection
  - Modal command palette (Ctrl-K) — run any shell action without leaving
  - Hotkeys for every major action (s/v/c/f/a/t/C/p/r/d/?/q)
  - Live filter (/) by IP / hostname / CVE-ID
  - Status bar with stats + current selection
  - Dark theme matching the web dashboard

Launch:
  python -m explotica.tui scans/full.json
  # or from inside the shell:
  explotica> tui
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger(__name__)


# ── Worker pool: tracks concurrent subprocess scans ──────────────────────
@dataclass
class ScanProcess:
    """One running (or completed) per-host scan."""
    id: str
    ip: str
    action: str           # human-readable action name
    cmd: list[str]        # the subprocess argv
    started_at: float
    status: str = "running"     # running / done / failed / killed
    ended_at: Optional[float] = None
    error: Optional[str] = None
    json_out: Optional[str] = None  # path to temp JSON

    @property
    def elapsed(self) -> float:
        end = self.ended_at or time.time()
        return end - self.started_at


class WorkerPool:
    """Manages concurrent per-host scan subprocesses + post-completion merge."""

    def __init__(self, on_change: Callable, on_complete: Callable):
        # on_change(): fires whenever the process list mutates (start, end,
        # status). Used to refresh the tracker widget.
        # on_complete(scan_process, new_scan_dict): fires when one process
        # completes successfully — caller merges new data into the scan.
        self.processes: list[ScanProcess] = []
        self._lock = threading.Lock()
        self.on_change = on_change
        self.on_complete = on_complete

    def start(self, ip: str, action: str, cmd: list[str],
               json_out: Optional[str] = None) -> ScanProcess:
        proc = ScanProcess(
            id=uuid.uuid4().hex[:8], ip=ip, action=action,
            cmd=cmd, started_at=time.time(), json_out=json_out,
        )
        with self._lock:
            self.processes.append(proc)
        self.on_change()
        threading.Thread(target=self._worker, args=(proc,),
                          daemon=True).start()
        return proc

    def _worker(self, proc: ScanProcess) -> None:
        try:
            result = subprocess.run(proc.cmd, capture_output=True,
                                     timeout=900, check=False)
            if result.returncode == 0 and proc.json_out and Path(proc.json_out).exists():
                try:
                    new_data = json.loads(
                        Path(proc.json_out).read_text(encoding="utf-8")
                    )
                    proc.status = "done"
                    proc.ended_at = time.time()
                    self.on_change()
                    self.on_complete(proc, new_data)
                except (json.JSONDecodeError, OSError) as e:
                    proc.status = "failed"
                    proc.error = f"parse JSON: {e}"
                    proc.ended_at = time.time()
                    self.on_change()
            else:
                proc.status = "failed"
                proc.error = (result.stderr[:200].decode("utf-8", "ignore")
                                if result.stderr else
                                f"exit code {result.returncode}")
                proc.ended_at = time.time()
                self.on_change()
        except subprocess.TimeoutExpired:
            proc.status = "failed"
            proc.error = "timeout (15min)"
            proc.ended_at = time.time()
            self.on_change()
        except Exception as e:
            proc.status = "failed"
            proc.error = str(e)
            proc.ended_at = time.time()
            self.on_change()

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for p in self.processes if p.status == "running")

    def all_processes(self) -> list[ScanProcess]:
        with self._lock:
            return list(self.processes)

    def clear_completed(self) -> None:
        with self._lock:
            self.processes = [p for p in self.processes if p.status == "running"]
        self.on_change()


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


def _ip_sort_key(h: dict) -> tuple:
    try:
        return tuple(int(o) for o in h["ip"].split("."))
    except (ValueError, KeyError):
        return (999, 999, 999, 999)


# ── Color/severity helpers ────────────────────────────────────────────────
SEV_COLORS = {
    "critical": "red",
    "high":     "orange1",
    "medium":   "yellow",
    "low":      "green",
    "none":     "dim",
}
SEV_ICONS = {
    "critical": "●",
    "high":     "●",
    "medium":   "●",
    "low":      "●",
    "none":     "○",
}


def run(scan_json_path: str) -> int:
    """Launch the TUI on a scan JSON file."""
    if not textual_available():
        print("[!] textual library required for TUI.")
        print("    Install: pip install textual")
        return 1

    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, Vertical, VerticalScroll
    from textual.screen import ModalScreen
    from textual.widgets import (Button, DataTable, Footer, Header, Input,
                                  Label, Static, TabbedContent, TabPane)
    from textual.reactive import reactive

    scan = json.loads(Path(scan_json_path).read_text(encoding="utf-8"))

    # ── Modal: command input dialog ──────────────────────────────────────
    class CommandModal(ModalScreen[str]):
        """Generic modal prompting for one input. Returns the entered string."""
        CSS = """
        CommandModal { align: center middle; }
        #cmd-box {
            background: $surface; border: thick $primary;
            padding: 1 2; min-width: 60; max-width: 80;
        }
        #cmd-title { color: $text; margin-bottom: 1; }
        #cmd-input { margin-top: 1; }
        """
        BINDINGS = [
            Binding("escape", "dismiss(None)", "Cancel"),
        ]

        def __init__(self, title: str, placeholder: str = "",
                      default: str = ""):
            super().__init__()
            self.title_text = title
            self.placeholder = placeholder
            self.default = default

        def compose(self) -> ComposeResult:
            with Container(id="cmd-box"):
                yield Label(self.title_text, id="cmd-title")
                yield Input(value=self.default, placeholder=self.placeholder,
                             id="cmd-input")

        def on_input_submitted(self, event) -> None:
            self.dismiss(event.value)

    # ── Modal: host action checklist ─────────────────────────────────────
    # Available actions a user can trigger against a single host. Each is a
    # tuple of (action_key, label, default_flags_for_explotica_cli).
    HOST_ACTIONS = [
        ("a", "🔥 Full re-scan (all the things)",
         ["--ports", "top1000", "--all-the-things", "--turbo"]),
        ("v", "✅ Verify probes (Heartbleed/MS17/Shellshock/+19)",
         ["--ports", "top1000", "--verify-cves", "--verify-cves-v2",
          "--no-arp"]),
        ("d", "🔎 Deep scan (vuln + nmap + searchsploit)",
         ["--ports", "top1000", "--vuln-scan", "--deep", "--use-nmap",
          "--use-searchsploit", "--epss-kev", "--no-arp"]),
        ("r", "🏷️ Rich intel only (TLS/HTTP/SMB)",
         ["--ports", "top1000", "--rich-intel", "--deep", "--no-arp"]),
        ("c", "🔓 Default credential check",
         ["--ports", "top1000", "--check-default-creds", "--no-arp"]),
        ("f", "💉 Web fuzz (path traversal/XSS/CRLF/SSRF)",
         ["--ports", "top100", "--web-fuzz", "--no-arp"]),
        ("p", "📊 Compute priorities (CVSS+EPSS+KEV)",
         ["--from-json-merge", "--prioritize"]),
        ("o", "🎯 OS fingerprint (deep)",
         ["--ports", "top1000", "--os-fp-db", "--rich-intel", "--no-arp"]),
        ("s", "🔍 Quick scan (top 100 ports only)",
         ["--ports", "top100", "--vuln-scan", "--no-arp"]),
        ("F", "🌐 Full-coverage everything",
         ["--ports", "top1000", "--full-coverage", "--ultra", "--no-arp"]),
        ("x", "⚙️ Custom flags…", None),  # special — prompts for flag string
    ]

    class HostActionModal(ModalScreen[tuple[str, list[str]]]):
        """Pops up when user activates a host. Lets them pick which scan
        action to run. Returns (action_label, cmd_flags) or None on cancel."""
        CSS = """
        HostActionModal { align: center middle; }
        #action-box {
            background: $surface; border: thick $accent;
            padding: 1 2; min-width: 70; max-width: 95;
            max-height: 30;
        }
        #action-title { color: $text; margin-bottom: 1; }
        #action-list { height: 22; overflow-y: auto; }
        .action-row {
            padding: 0 1;
        }
        .action-key {
            color: $accent; text-style: bold;
            width: 4;
        }
        """
        BINDINGS = [
            Binding("escape", "dismiss(None)", "Cancel"),
        ]

        def __init__(self, host_ip: str, host_hostname: str = ""):
            super().__init__()
            self.host_ip = host_ip
            self.host_hostname = host_hostname

        def compose(self) -> ComposeResult:
            with Container(id="action-box"):
                title = f"🎯 Scan actions for [cyan]{self.host_ip}[/cyan]"
                if self.host_hostname:
                    title += f"  ({self.host_hostname})"
                yield Label(title, id="action-title")
                yield Label(
                    "[dim]Pick an action (single letter):[/dim]",
                    id="action-subtitle",
                )
                with VerticalScroll(id="action-list"):
                    for key, label, _flags in HOST_ACTIONS:
                        yield Static(
                            f"  [bold accent]{key}[/bold accent]  {label}",
                            classes="action-row",
                        )
                yield Label("[dim]Esc to cancel[/dim]", id="action-footer")

        def on_key(self, event) -> None:
            ch = event.key
            for k, label, flags in HOST_ACTIONS:
                if ch == k:
                    if flags is None:
                        # Custom — push another modal asking for flags
                        def cb(custom: Optional[str]) -> None:
                            if custom is None:
                                self.dismiss(None)
                                return
                            self.dismiss((label, custom.split()))
                        self.app.push_screen(CommandModal(
                            f"Custom flags for {self.host_ip}",
                            "scan flags (e.g. --ports all --use-nmap)",
                            "--ports top1000 --vuln-scan --deep --no-arp",
                        ), cb)
                        return
                    self.dismiss((label, list(flags)))
                    return

    # ── Modal: help overlay ──────────────────────────────────────────────
    class HelpModal(ModalScreen):
        CSS = """
        HelpModal { align: center middle; }
        #help-box {
            background: $surface; border: thick $primary;
            padding: 1 2; min-width: 70; max-width: 90;
        }
        """
        BINDINGS = [Binding("escape,q,?", "dismiss", "Close")]

        def compose(self) -> ComposeResult:
            help_text = """
[b]Explotica TUI — Hotkeys[/b]

[b]Navigation[/b]
  Tab / Shift-Tab    Switch tabs
  j / k / ↑ / ↓      Move in lists
  Enter              Drill-down on host
  /                  Filter / search
  Esc                Clear filter / close modal

[b]Tabs[/b]
  1 Hosts            2 CVEs            3 Ports
  4 Exploits         5 Compliance      6 Extra

[b]Per-host action menu (Hosts tab)[/b]
  [b]Enter[/b]              open scan-action menu for host under cursor
                     (or for ALL selected hosts — runs in parallel)
  Then pick a letter:
      [accent]a[/accent]  Full re-scan        [accent]v[/accent]  Verify probes (Heartbleed/MS17/+19)
      [accent]d[/accent]  Deep scan           [accent]r[/accent]  Rich intel (TLS/HTTP/SMB)
      [accent]c[/accent]  Default creds       [accent]f[/accent]  Web fuzz
      [accent]p[/accent]  Priorities          [accent]o[/accent]  OS fingerprint
      [accent]s[/accent]  Quick scan (top100) [accent]F[/accent]  Full-coverage everything
      [accent]x[/accent]  Custom flags

[b]Selection (Hosts tab)[/b]
  [b]space[/b]              toggle select on host under cursor
  [b]*[/b] (Shift-8)        select all visible hosts
  [b]n[/b]                  clear selection
  [b]g[/b]                  configure DEFAULT scan flags for host under cursor
  [b]R[/b]                  re-scan selected hosts (or host under cursor) — direct
  [b]B[/b]                  bulk action (alias for R)

[b]Live process tracker (bottom-right)[/b]
  Shows every running/recent scan — IP, action, elapsed time, status.
  Multiple scans run concurrently in their own subprocesses.

[b]Global actions[/b]
  s    [b]s[/b]can — new full scan
  l    [b]l[/b]oad another JSON file
  S    [b]S[/b]ave current scan
  v    [b]v[/b]erify probes (Heartbleed/MS17/etc.)
  c    [b]c[/b]redentialed SSH scan
  W    [b]W[/b]inRM credentialed scan
  a    [b]a[/b]ctive Directory enum
  A    [b]A[/b]S-REP roast
  f    [b]f[/b]uzz web services
  D    [b]D[/b]efault credential check
  t    [b]t[/b]akeover detection
  C    [b]C[/b]loud asset discovery
  p    [b]p[/b]riorities view
  m    co[b]m[/b]pliance evaluation
  e    [b]e[/b]xtra findings
  r    save [b]r[/b]eport (HTML/PDF/MD)
  d    open web [b]d[/b]ashboard
  ?    show this help
  q    [b]q[/b]uit
"""
            yield Static(help_text, id="help-box")

    # ── Main app ─────────────────────────────────────────────────────────
    class ExploticaTUI(App):
        CSS = """
        Screen { background: #0d1117; }
        Header { background: #161b22; color: #58a6ff; }
        Footer { background: #161b22; }
        TabbedContent > #--tabs { background: #161b22; }
        Tab { color: #8b949e; }
        Tab.--active { color: #58a6ff; background: #1f2937; }
        DataTable { background: #161b22; }
        DataTable > .datatable--header { background: #0d1117; color: #58a6ff; }
        DataTable > .datatable--cursor { background: #1f6feb; color: white; }
        #right-column {
            width: 50%;
            border-left: solid #30363d;
        }
        #detail-pane {
            background: #161b22;
            padding: 1 2;
            height: 70%;
        }
        #process-pane {
            background: #0d1117;
            border-top: solid #30363d;
            padding: 1 2;
            height: 30%;
        }
        .proc-running { color: #ffcc00; }
        .proc-done { color: #34c759; }
        .proc-failed { color: #ff3b30; }
        #status-bar {
            background: #161b22; color: #8b949e;
            padding: 0 2; height: 1;
        }
        .critical { color: #ff3b30; text-style: bold; }
        .high { color: #ff9500; }
        .medium { color: #ffcc00; }
        .low { color: #34c759; }
        .kev { color: #ff3b30; text-style: bold; }
        .product { color: #d29922; }
        .banner { color: #7d8590; }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("?", "show_help", "Help"),
            Binding("/", "search", "Search"),
            Binding("escape", "clear_search", "Clear", show=False),
            # Selection + per-host rescan (Phase 49)
            Binding("space", "toggle_select", "Select", show=True),
            Binding("R", "rescan", "Rescan host(s)", show=True),
            Binding("g", "config_host", "Configure", show=True),
            Binding("B", "bulk_action", "Bulk", show=False),
            Binding("asterisk", "select_all", "Select all", show=False),
            Binding("n", "clear_selection", "Clear sel.", show=False),
            Binding("enter", "rescan_current", "Rescan this", show=False),
            # Scan setup actions
            Binding("s", "action_scan", "Scan"),
            Binding("l", "action_load", "Load"),
            Binding("S", "action_save", "Save", show=False),
            Binding("v", "action_verify", "Verify"),
            Binding("c", "action_sshcreds", "SSH creds"),
            Binding("W", "action_winrm", "WinRM", show=False),
            Binding("a", "action_ad", "AD enum"),
            Binding("A", "action_asrep", "AS-REP", show=False),
            Binding("f", "action_fuzz", "Fuzz"),
            Binding("D", "action_defcreds", "Defcreds", show=False),
            Binding("t", "action_takeover", "Takeover", show=False),
            Binding("C", "action_cloud", "Cloud", show=False),
            Binding("p", "action_priorities", "Priorities"),
            Binding("m", "action_compliance", "Compliance"),
            Binding("e", "action_extra", "Extra"),
            Binding("r", "action_report", "Report"),
            Binding("d", "action_dashboard", "Dashboard"),
            # Tab quick-keys
            Binding("1", "switch_tab('hosts')", "Hosts", show=False),
            Binding("2", "switch_tab('cves')", "CVEs", show=False),
            Binding("3", "switch_tab('ports')", "Ports", show=False),
            Binding("4", "switch_tab('exploits')", "Exploits", show=False),
            Binding("5", "switch_tab('compliance')", "Compliance", show=False),
            Binding("6", "switch_tab('extra')", "Extra", show=False),
        ]

        filter_text: reactive[str] = reactive("")

        def __init__(self, scan_data: dict, scan_path: str):
            super().__init__()
            self.scan_data = scan_data
            self.scan_path = scan_path
            self.hosts = sorted(scan_data.get("hosts", []), key=_ip_sort_key)
            self.current_host = None
            # Per-host selection + custom-flag state
            self.selected_hosts: set[str] = set()
            self.per_host_config: dict[str, list[str]] = {}
            # Worker pool — concurrent per-host subprocess scans
            self.pool = WorkerPool(
                on_change=self._on_pool_change,
                on_complete=self._on_scan_complete,
            )

        def compose(self) -> ComposeResult:
            yield Header(name=f"🛰️  Explotica  •  {self.scan_data.get('target', '?')}")
            with TabbedContent(id="tabs", initial="hosts"):
                with TabPane("Hosts", id="hosts"):
                    with Horizontal():
                        with Vertical():
                            yield Input(placeholder="filter (IP, hostname, CVE)…",
                                         id="search")
                            self.host_table = DataTable(id="host-table",
                                                          cursor_type="row",
                                                          zebra_stripes=True)
                            yield self.host_table
                        with Vertical(id="right-column"):
                            self.detail_pane = VerticalScroll(id="detail-pane")
                            yield self.detail_pane
                            self.process_pane = VerticalScroll(id="process-pane")
                            yield self.process_pane
                with TabPane("CVEs", id="cves"):
                    self.cve_table = DataTable(id="cve-table",
                                                 cursor_type="row",
                                                 zebra_stripes=True)
                    yield self.cve_table
                with TabPane("Ports", id="ports"):
                    self.port_table = DataTable(id="port-table",
                                                  cursor_type="row",
                                                  zebra_stripes=True)
                    yield self.port_table
                with TabPane("Exploits", id="exploits"):
                    self.exploit_table = DataTable(id="exploit-table",
                                                     cursor_type="row",
                                                     zebra_stripes=True)
                    yield self.exploit_table
                with TabPane("Compliance", id="compliance"):
                    self.compliance_view = VerticalScroll(id="compliance-view")
                    yield self.compliance_view
                with TabPane("Extra", id="extra"):
                    self.extra_view = VerticalScroll(id="extra-view")
                    yield self.extra_view
            yield Static("", id="status-bar")
            yield Footer()

        # ── Worker pool callbacks ────────────────────────────────────────
        def _on_pool_change(self) -> None:
            """WorkerPool fires this on any process state change (cross-thread)."""
            self.call_from_thread(self._render_process_pane)

        def _on_scan_complete(self, proc: ScanProcess,
                                new_data: dict) -> None:
            """A scan finished — merge its results into our in-memory scan."""
            self.call_from_thread(self._merge_rescan_result, new_data)
            self.call_from_thread(self._save_scan)
            self.call_from_thread(self._populate_hosts)
            self.call_from_thread(self._populate_cves)
            self.call_from_thread(self._populate_ports)
            self.call_from_thread(self._populate_exploits)
            self.call_from_thread(self._populate_extra)
            self.call_from_thread(
                self.notify,
                f"✓ {proc.action} on {proc.ip} complete ({proc.elapsed:.1f}s)",
                timeout=4,
            )

        def _render_process_pane(self) -> None:
            """Refresh the bottom-right process-tracker panel."""
            try:
                pane = self.process_pane
            except Exception:
                return
            pane.remove_children()
            procs = self.pool.all_processes()
            active = sum(1 for p in procs if p.status == "running")
            done = sum(1 for p in procs if p.status == "done")
            failed = sum(1 for p in procs if p.status == "failed")
            pane.mount(Static(
                f"[bold]⚡ Process Tracker[/bold]   "
                f"[yellow]{active} running[/yellow] · "
                f"[green]{done} done[/green] · "
                f"[red]{failed} failed[/red]"
            ))
            if not procs:
                pane.mount(Static("[dim]No scans running. "
                                    "Enter on a host to start one.[/dim]"))
                return
            # Most recent first, cap at 12
            for p in reversed(procs[-12:]):
                if p.status == "running":
                    cls = "proc-running"
                    icon = "⏳"
                    tail = f"({p.elapsed:.1f}s)"
                elif p.status == "done":
                    cls = "proc-done"
                    icon = "✓"
                    tail = f"({p.elapsed:.1f}s)"
                else:
                    cls = "proc-failed"
                    icon = "✗"
                    tail = f"({p.error or 'failed'})"
                pane.mount(Static(
                    f"  {icon} [{cls}]{p.ip:<16}[/{cls}] "
                    f"{p.action[:40]:<40} {tail}",
                    classes=cls,
                ))

        def on_mount(self) -> None:
            # Title (live stats)
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "kev": 0}
            for h in self.hosts:
                for p in h.get("ports", []):
                    for c in p.get("cves", []):
                        s = (c.get("severity") or "").lower()
                        if s in counts:
                            counts[s] += 1
                        if c.get("in_kev"):
                            counts["kev"] += 1
            self.title = "Explotica"
            self.sub_title = (
                f"{len(self.hosts)} hosts · "
                f"[red]{counts['critical']} crit[/red] · "
                f"[orange1]{counts['high']} high[/orange1] · "
                f"[red bold]{counts['kev']} KEV[/red bold]"
            )
            self._populate_hosts()
            self._populate_cves()
            self._populate_ports()
            self._populate_exploits()
            self._populate_compliance()
            self._populate_extra()
            self._update_status()
            self._render_process_pane()
            # Tick every 1s to update elapsed times in process tracker
            self.set_interval(1.0, self._render_process_pane)

        # ── Tab population ───────────────────────────────────────────────
        def _populate_hosts(self) -> None:
            t = self.host_table
            t.clear(columns=True)
            t.add_columns("Sel", "Cfg", "IP", "Hostname", "Vendor",
                           "Ports", "CVEs", "Worst")
            q = self.filter_text.lower()
            for h in self.hosts:
                if q:
                    hay = (h.get("ip", "") + " "
                            + (h.get("hostname") or "")).lower()
                    if q not in hay and not any(
                        q in str(c.get("id", "")).lower()
                        for p in h.get("ports", [])
                        for c in p.get("cves", [])
                    ):
                        continue
                sev = _severity_of_host(h)
                color = SEV_COLORS.get(sev, "dim")
                ports = h.get("ports", [])
                cves = sum(len(p.get("cves", [])) for p in ports)
                worst_text = f"[{color}]{sev.upper()}[/{color}]" if sev != "none" else "-"
                sel_mark = "[green]✓[/green]" if h["ip"] in self.selected_hosts else " "
                cfg_mark = "[yellow]⚙[/yellow]" if h["ip"] in self.per_host_config else " "
                t.add_row(
                    sel_mark, cfg_mark,
                    f"[cyan]{h['ip']}[/cyan]",
                    (h.get("hostname") or "-")[:24],
                    (h.get("vendor") or "-")[:18],
                    str(len(ports)),
                    str(cves),
                    worst_text,
                    key=h["ip"],
                )

        def _populate_cves(self) -> None:
            t = self.cve_table
            t.clear(columns=True)
            t.add_columns("CVE", "Severity", "CVSS", "EPSS", "KEV", "Hosts")
            seen: dict[str, list] = {}
            for h in self.hosts:
                for p in h.get("ports", []):
                    for c in p.get("cves", []):
                        seen.setdefault(c["id"], []).append((h["ip"], c))
            ranked = sorted(
                seen.items(),
                key=lambda kv: (
                    not kv[1][0][1].get("in_kev"),
                    -(kv[1][0][1].get("epss_score") or 0),
                    -(kv[1][0][1].get("cvss") or 0),
                ),
            )
            for cve_id, occurrences in ranked[:300]:
                c = occurrences[0][1]
                sev = (c.get("severity") or "?").upper()
                color = SEV_COLORS.get(sev.lower(), "dim")
                t.add_row(
                    f"[cyan]{cve_id}[/cyan]",
                    f"[{color}]{sev}[/{color}]",
                    f"{c.get('cvss'):.1f}" if c.get("cvss") else "-",
                    f"{c.get('epss_score'):.2f}" if c.get("epss_score") else "-",
                    "[red bold]KEV[/red bold]" if c.get("in_kev") else "",
                    str(len(occurrences)),
                    key=cve_id,
                )

        def _populate_ports(self) -> None:
            t = self.port_table
            t.clear(columns=True)
            t.add_columns("Port", "Service", "Product/Version", "Hosts", "CVEs")
            port_map: dict[int, list] = {}
            for h in self.hosts:
                for p in h.get("ports", []):
                    port_map.setdefault(p["number"], []).append((h, p))
            for port in sorted(port_map.keys()):
                entries = port_map[port]
                sample = entries[0][1]
                cves = sum(len(p.get("cves", [])) for _, p in entries)
                prod = ""
                if sample.get("product_name") and sample.get("product_version"):
                    prod = f"{sample['product_name']} {sample['product_version']}"
                t.add_row(
                    str(port),
                    sample.get("service") or "-",
                    prod or "-",
                    str(len(entries)),
                    str(cves),
                    key=str(port),
                )

        def _populate_exploits(self) -> None:
            t = self.exploit_table
            t.clear(columns=True)
            t.add_columns("EDB-ID", "Host", "Port", "Title", "Type", "Platform")
            for h in self.hosts:
                for p in h.get("ports", []):
                    for ex in p.get("exploits", []):
                        t.add_row(
                            ex.get("edb_id") or "?",
                            h["ip"],
                            str(p["number"]),
                            (ex.get("title") or "")[:60],
                            ex.get("type") or "-",
                            ex.get("platform") or "-",
                        )

        def _populate_compliance(self) -> None:
            self.compliance_view.remove_children()
            ef = self.scan_data.get("extra_findings") or {}
            comp = ef.get("compliance") or {}
            if not comp:
                self.compliance_view.mount(Static(
                    "[dim]No compliance results in this scan. "
                    "Run with `--compliance cis,pci,hipaa` or `m` to run now.[/dim]"
                ))
                return
            for fw, r in comp.items():
                self.compliance_view.mount(Static(
                    f"[bold]{r.get('framework', fw)}[/bold]  "
                    f"Pass: {r.get('pass', 0)}  Fail: {r.get('fail', 0)}  "
                    f"Score: {r.get('score_pct', 0)}%"
                ))
                for res in r.get("results", []):
                    mark = ("[green]✓[/green]" if res["outcome"] == "PASS"
                            else "[red]✗[/red]" if res["outcome"] == "FAIL"
                            else "[dim]~[/dim]")
                    self.compliance_view.mount(Static(
                        f"  {mark} {res['id']:<14} {res['title']}"
                    ))

        def _populate_extra(self) -> None:
            self.extra_view.remove_children()
            ef = self.scan_data.get("extra_findings") or {}
            if not ef:
                self.extra_view.mount(Static(
                    "[dim]No extra findings. Active modules (verify/fuzz/AD/etc.) "
                    "haven't been run on this scan yet.[/dim]"
                ))
                return
            for key, val in ef.items():
                if isinstance(val, dict):
                    summary = f"{len(val)} entries"
                elif isinstance(val, list):
                    summary = f"{len(val)} items"
                else:
                    summary = str(val)[:80]
                self.extra_view.mount(Static(
                    f"[bold cyan]{key}[/bold cyan]: {summary}"
                ))

        def _update_status(self) -> None:
            try:
                status = self.query_one("#status-bar", Static)
                sel = len(self.selected_hosts)
                cfg = len(self.per_host_config)
                sel_str = (f"[green]{sel} selected[/green] · " if sel
                            else "")
                cfg_str = (f"[yellow]{cfg} custom-cfg[/yellow] · " if cfg
                            else "")
                status.update(
                    f"[dim]{sel_str}{cfg_str}"
                    f"Source: {self.scan_path} · "
                    f"[b]space[/b] select  [b]R[/b] rescan  [b]g[/b] config  "
                    f"[b]?[/b] help  [b]q[/b] quit[/dim]"
                )
            except Exception:
                pass

        # ── Row selection → detail pane ──────────────────────────────────
        def on_data_table_row_selected(self, event) -> None:
            if event.data_table.id == "host-table":
                ip = str(event.row_key.value)
                host = next((h for h in self.hosts if h["ip"] == ip), None)
                if host:
                    self._show_host_detail(host)

        def _show_host_detail(self, h: dict) -> None:
            self.detail_pane.remove_children()
            from textual.widgets import Static as S
            lines = [f"[bold cyan]{h['ip']}[/bold cyan]"]
            if h.get("hostname"):
                lines.append(f"hostname: [cyan]{h['hostname']}[/cyan]")
            if h.get("mac"):
                lines.append(f"MAC: {h['mac']}  vendor: {h.get('vendor') or '-'}")
            if h.get("os_hint"):
                oh = h["os_hint"]
                lines.append(
                    f"OS: {oh.get('os_family')} "
                    f"(TTL={h.get('ttl')})"
                )
            self.detail_pane.mount(S("\n".join(lines)))

            for p in h.get("ports", []):
                pl = [f"\n[bold green]{p['number']}/{p.get('protocol', 'tcp')}[/bold green] {p.get('service', '')}"]
                if p.get("product_name") and p.get("product_version"):
                    pl.append(f"  [yellow]{p['product_name']} {p['product_version']}[/yellow]")
                if p.get("banner"):
                    pl.append(f"  [dim]{p['banner'][:120]}[/dim]")
                cves = sorted(
                    p.get("cves", []),
                    key=lambda c: (
                        not c.get("in_kev"),
                        -(c.get("epss_score") or 0),
                        -(c.get("cvss") or 0),
                    ),
                )
                for c in cves[:8]:
                    sev = (c.get("severity") or "?").upper()
                    color = SEV_COLORS.get(sev.lower(), "dim")
                    marker = " [red bold]KEV[/red bold]" if c.get("in_kev") else ""
                    pl.append(
                        f"  [{color}]{sev:<8}[/{color}] "
                        f"{c.get('cvss') or '?':<5}  [cyan]{c['id']}[/cyan]{marker}"
                    )
                for ex in (p.get("exploits") or [])[:3]:
                    pl.append(f"  💥 [magenta]EDB-{ex.get('edb_id', '?')}[/magenta]  {ex.get('title', '')[:60]}")
                self.detail_pane.mount(S("\n".join(pl)))

        # ── Search / filter ─────────────────────────────────────────────
        def on_input_changed(self, event) -> None:
            if event.input.id == "search":
                self.filter_text = event.value
                self._populate_hosts()

        def action_search(self) -> None:
            try:
                self.query_one("#search", Input).focus()
            except Exception:
                pass

        def action_clear_search(self) -> None:
            try:
                inp = self.query_one("#search", Input)
                inp.value = ""
                self.filter_text = ""
                self._populate_hosts()
            except Exception:
                pass

        # ── Tab switching ───────────────────────────────────────────────
        def action_switch_tab(self, tab_id: str) -> None:
            try:
                self.query_one("#tabs", TabbedContent).active = tab_id
            except Exception:
                pass

        # ── Modal action handlers ───────────────────────────────────────
        def _run_subprocess_and_reload(self, cmd: list[str], action_name: str) -> None:
            """Run an explotica subprocess + reload our scan view from JSON."""
            self.notify(f"Running {action_name}…", timeout=2)
            def worker():
                try:
                    subprocess.run(cmd, capture_output=True, timeout=600, check=False)
                    # Reload scan from disk in case the action wrote new data
                    if Path(self.scan_path).exists():
                        self.scan_data = json.loads(
                            Path(self.scan_path).read_text(encoding="utf-8")
                        )
                        self.hosts = sorted(self.scan_data.get("hosts", []),
                                             key=_ip_sort_key)
                        self.call_from_thread(self._populate_hosts)
                        self.call_from_thread(self._populate_cves)
                        self.call_from_thread(self._populate_extra)
                        self.call_from_thread(self.notify,
                                                f"{action_name} done.", timeout=3)
                except Exception as e:
                    self.call_from_thread(self.notify,
                                            f"{action_name} failed: {e}", timeout=4)
            threading.Thread(target=worker, daemon=True).start()

        def action_scan(self) -> None:
            def callback(target: Optional[str]) -> None:
                if not target:
                    return
                self.notify(f"Scanning {target}… (will reload when done)", timeout=3)
                cmd = [sys.executable, "-m", "explotica"] + target.split() + [
                    "--json", self.scan_path
                ]
                self._run_subprocess_and_reload(cmd, "scan")
            self.push_screen(CommandModal(
                "🔍 Run scan", "target [flags]", "192.168.1.0/24 --full-coverage --turbo"
            ), callback)

        def action_load(self) -> None:
            def callback(path: Optional[str]) -> None:
                if not path or not Path(path).exists():
                    return
                self.scan_data = json.loads(Path(path).read_text(encoding="utf-8"))
                self.scan_path = path
                self.hosts = sorted(self.scan_data.get("hosts", []),
                                      key=_ip_sort_key)
                self._populate_hosts()
                self._populate_cves()
                self._populate_ports()
                self._populate_exploits()
                self._populate_compliance()
                self._populate_extra()
                self.notify(f"Loaded {path}", timeout=2)
            self.push_screen(CommandModal(
                "📂 Load JSON", "path to scan JSON", self.scan_path or ""
            ), callback)

        def action_save(self) -> None:
            def callback(path: Optional[str]) -> None:
                if not path:
                    return
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_text(json.dumps(self.scan_data, indent=2),
                                       encoding="utf-8")
                self.notify(f"Saved to {path}", timeout=2)
            self.push_screen(CommandModal(
                "💾 Save", "path to save JSON", self.scan_path
            ), callback)

        def action_verify(self) -> None:
            cmd = [sys.executable, "-m", "explotica",
                    "--from-json", self.scan_path,
                    "--verify-cves", "--verify-cves-v2",
                    "--json", self.scan_path]
            self._run_subprocess_and_reload(cmd, "verify probes")

        def action_sshcreds(self) -> None:
            def callback(creds: Optional[str]) -> None:
                if not creds:
                    return
                cmd = [sys.executable, "-m", "explotica",
                        "--from-json", self.scan_path,
                        "--ssh-creds", creds,
                        "--json", self.scan_path]
                self._run_subprocess_and_reload(cmd, "SSH credentialed scan")
            self.push_screen(CommandModal(
                "🔑 SSH credentialed scan", "user:password", ""
            ), callback)

        def action_winrm(self) -> None:
            def callback(creds: Optional[str]) -> None:
                if not creds:
                    return
                cmd = [sys.executable, "-m", "explotica",
                        "--from-json", self.scan_path,
                        "--winrm-creds", creds,
                        "--json", self.scan_path]
                self._run_subprocess_and_reload(cmd, "WinRM scan")
            self.push_screen(CommandModal(
                "🪟 WinRM credentialed scan", "user:password", ""
            ), callback)

        def action_ad(self) -> None:
            def callback(domain: Optional[str]) -> None:
                if not domain:
                    return
                cmd = [sys.executable, "-m", "explotica",
                        "--from-json", self.scan_path,
                        "--ad-enum", domain,
                        "--json", self.scan_path]
                self._run_subprocess_and_reload(cmd, "AD enum")
            self.push_screen(CommandModal(
                "🏢 Active Directory enum", "domain (e.g. corp.local)", ""
            ), callback)

        def action_asrep(self) -> None:
            def callback(domain: Optional[str]) -> None:
                if not domain:
                    return
                cmd = [sys.executable, "-m", "explotica",
                        "--from-json", self.scan_path,
                        "--ad-enum", domain, "--asrep-roast",
                        "--json", self.scan_path]
                self._run_subprocess_and_reload(cmd, "AS-REP roast")
            self.push_screen(CommandModal(
                "🔥 AS-REP roast", "domain", ""
            ), callback)

        def action_fuzz(self) -> None:
            cmd = [sys.executable, "-m", "explotica",
                    "--from-json", self.scan_path,
                    "--web-fuzz",
                    "--json", self.scan_path]
            self._run_subprocess_and_reload(cmd, "web fuzz")

        def action_defcreds(self) -> None:
            cmd = [sys.executable, "-m", "explotica",
                    "--from-json", self.scan_path,
                    "--check-default-creds",
                    "--json", self.scan_path]
            self._run_subprocess_and_reload(cmd, "default cred check")

        def action_takeover(self) -> None:
            cmd = [sys.executable, "-m", "explotica",
                    "--from-json", self.scan_path,
                    "--check-takeover",
                    "--json", self.scan_path]
            self._run_subprocess_and_reload(cmd, "takeover check")

        def action_cloud(self) -> None:
            def callback(kw: Optional[str]) -> None:
                if not kw:
                    return
                cmd = [sys.executable, "-m", "explotica",
                        "--from-json", self.scan_path,
                        "--check-cloud", kw,
                        "--json", self.scan_path]
                self._run_subprocess_and_reload(cmd, f"cloud asset discovery ({kw})")
            self.push_screen(CommandModal(
                "☁ Cloud asset discovery", "keyword (e.g. company name)", ""
            ), callback)

        def action_priorities(self) -> None:
            cmd = [sys.executable, "-m", "explotica",
                    "--from-json", self.scan_path,
                    "--prioritize",
                    "--json", self.scan_path]
            self._run_subprocess_and_reload(cmd, "prioritization")
            self.action_switch_tab("cves")

        def action_compliance(self) -> None:
            def callback(fw: Optional[str]) -> None:
                if not fw:
                    return
                cmd = [sys.executable, "-m", "explotica",
                        "--from-json", self.scan_path,
                        "--compliance", fw,
                        "--json", self.scan_path]
                self._run_subprocess_and_reload(cmd, f"{fw} compliance")
                self.action_switch_tab("compliance")
            self.push_screen(CommandModal(
                "📋 Compliance evaluation", "cis | pci | hipaa | cis,pci,hipaa", "cis"
            ), callback)

        def action_extra(self) -> None:
            self.action_switch_tab("extra")

        def action_report(self) -> None:
            def callback(spec: Optional[str]) -> None:
                if not spec:
                    return
                # spec format: "html scans/foo.html"  or  "pdf scans/foo.pdf"
                parts = spec.split(maxsplit=1)
                if len(parts) != 2:
                    self.notify("Format: <html|pdf|md> <path>", timeout=3)
                    return
                fmt, path = parts
                from .models import ScanResult
                sr = ScanResult.from_dict(self.scan_data)
                try:
                    if fmt == "html":
                        from .report import write_report
                        out = write_report(sr, path)
                    elif fmt == "pdf":
                        from .report_pdf import write_pdf_report
                        out = write_pdf_report(sr, path)
                    elif fmt == "md":
                        from .report_pdf import write_markdown_report
                        out = write_markdown_report(sr, path)
                    else:
                        self.notify(f"Unknown format: {fmt}", timeout=3)
                        return
                    self.notify(f"Report written to {out}", timeout=3)
                except Exception as e:
                    self.notify(f"Report failed: {e}", timeout=4)
            self.push_screen(CommandModal(
                "📝 Save report", "<html|pdf|md> <path>", "html scans/from_tui.html"
            ), callback)

        def action_dashboard(self) -> None:
            cmd = [sys.executable, "-m", "explotica.dashboard", self.scan_path]
            try:
                subprocess.Popen(cmd)
                self.notify("Dashboard launched at http://localhost:8765 "
                            "(check your browser)", timeout=4)
            except Exception as e:
                self.notify(f"Dashboard failed: {e}", timeout=4)

        def action_show_help(self) -> None:
            self.push_screen(HelpModal())

        # ── Phase 49: selection + per-host rescan ────────────────────────
        def _current_row_ip(self) -> Optional[str]:
            """Return the IP under the cursor in the host table, or None."""
            try:
                row_key = self.host_table.coordinate_to_cell_key(
                    self.host_table.cursor_coordinate
                ).row_key
                return str(row_key.value)
            except Exception:
                return None

        def action_toggle_select(self) -> None:
            ip = self._current_row_ip()
            if not ip:
                return
            if ip in self.selected_hosts:
                self.selected_hosts.discard(ip)
            else:
                self.selected_hosts.add(ip)
            # Repopulate keeping cursor position
            cur = self.host_table.cursor_coordinate
            self._populate_hosts()
            try:
                self.host_table.cursor_coordinate = cur
            except Exception:
                pass
            self._update_status()

        def action_select_all(self) -> None:
            q = self.filter_text.lower()
            for h in self.hosts:
                if q:
                    hay = (h["ip"] + " " + (h.get("hostname") or "")).lower()
                    if q not in hay:
                        continue
                self.selected_hosts.add(h["ip"])
            self._populate_hosts()
            self._update_status()
            self.notify(f"Selected {len(self.selected_hosts)} host(s)", timeout=2)

        def action_clear_selection(self) -> None:
            self.selected_hosts.clear()
            self._populate_hosts()
            self._update_status()

        def action_config_host(self) -> None:
            """Set custom scan flags for the host under cursor."""
            ip = self._current_row_ip()
            if not ip:
                self.notify("No host selected.", timeout=2)
                return
            current = " ".join(self.per_host_config.get(ip, []))

            def callback(flags: Optional[str]) -> None:
                if flags is None:
                    return
                if flags.strip():
                    self.per_host_config[ip] = flags.split()
                    self.notify(f"Saved config for {ip}: {flags[:60]}",
                                  timeout=3)
                else:
                    self.per_host_config.pop(ip, None)
                    self.notify(f"Cleared config for {ip}", timeout=2)
                self._populate_hosts()
                self._update_status()

            self.push_screen(CommandModal(
                f"⚙ Configure scan flags for {ip}",
                "e.g. --ports top1000 --vuln-scan --deep --verify-cves",
                current or "--ports top1000 --vuln-scan --deep --verify-cves",
            ), callback)

        def action_rescan_current(self) -> None:
            """Enter key — opens the action menu for the host under cursor.

            If multiple hosts are selected, opens the action menu and applies
            the chosen action to ALL selected (each spawns its own subprocess
            in parallel).
            """
            ip = self._current_row_ip()
            if not ip:
                return
            # Determine target list — selection if any, else just this row
            if self.selected_hosts:
                targets = sorted(self.selected_hosts,
                                  key=lambda x: tuple(int(o) for o in x.split(".")))
            else:
                targets = [ip]

            host = next((h for h in self.hosts if h["ip"] == ip), None)
            hostname = host.get("hostname", "") if host else ""

            def callback(chosen: Optional[tuple[str, list[str]]]) -> None:
                if not chosen:
                    return
                action_label, flags = chosen
                for target in targets:
                    self._launch_host_scan(target, action_label, flags)

            # Title shows count if multi-target
            display_ip = (f"{targets[0]} (+ {len(targets) - 1} more)"
                          if len(targets) > 1 else targets[0])
            self.push_screen(HostActionModal(display_ip, hostname), callback)

        def _launch_host_scan(self, ip: str, action_label: str,
                                flags: list[str]) -> None:
            """Start a per-host subprocess scan via the worker pool.

            Each invocation gets its OWN temp JSON output, so concurrent
            scans don't trample each other. Results get merged when each
            completes.
            """
            # Allocate temp JSON for this subprocess
            tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            tmp.close()
            tmp_path = tmp.name
            # Special-case "from-json-merge" pseudo-flag for re-enrich actions
            # like priorities that need the existing scan as input.
            if "--from-json-merge" in flags:
                flags = [f for f in flags if f != "--from-json-merge"]
                cmd = ([sys.executable, "-m", "explotica",
                          "--from-json", self.scan_path]
                        + flags
                        + ["--json", tmp_path])
            else:
                cmd = ([sys.executable, "-m", "explotica", ip]
                        + flags
                        + ["--json", tmp_path])
            self.pool.start(ip=ip, action=action_label, cmd=cmd,
                              json_out=tmp_path)
            self.notify(f"Launched: {action_label} on {ip}", timeout=3)

        def action_rescan(self) -> None:
            """Re-scan selected hosts (or host under cursor if no selection)."""
            if self.selected_hosts:
                ips = sorted(self.selected_hosts, key=lambda x: tuple(int(o) for o in x.split(".")))
            else:
                ip = self._current_row_ip()
                if not ip:
                    self.notify("No host to rescan.", timeout=2)
                    return
                ips = [ip]

            def confirm_callback(answer: Optional[str]) -> None:
                if not answer or answer.strip().lower() not in ("y", "yes", ""):
                    return
                self._rescan_hosts(ips)

            target_desc = f"{len(ips)} host(s)" if len(ips) > 1 else ips[0]
            self.push_screen(CommandModal(
                f"🔄 Re-scan {target_desc}?  (per-host configs will be used "
                "where set; otherwise default flags)",
                "press Enter to confirm, Esc to cancel",
                "y"
            ), confirm_callback)

        def action_bulk_action(self) -> None:
            """Alias for rescan against multiple selected hosts."""
            self.action_rescan()

        DEFAULT_RESCAN_FLAGS = [
            "--ports", "top1000",
            "--vuln-scan", "--deep", "--epss-kev",
            "--rich-intel", "--use-searchsploit",
            "--no-arp",  # we already know the host is alive
        ]

        def _rescan_hosts(self, ips: list[str]) -> None:
            """Background worker: rescan each IP (using per-host config or defaults),
            merge results back into self.scan_data, write JSON, refresh tables."""
            import tempfile

            self.notify(f"Rescanning {len(ips)} host(s)…", timeout=3)

            def worker():
                for i, ip in enumerate(ips, 1):
                    flags = self.per_host_config.get(ip, self.DEFAULT_RESCAN_FLAGS)
                    self.call_from_thread(
                        self.notify,
                        f"[{i}/{len(ips)}] scanning {ip} with "
                        f"{' '.join(flags[:6])}…", timeout=4
                    )
                    with tempfile.NamedTemporaryFile(suffix=".json",
                                                       delete=False) as tmp:
                        tmp_path = tmp.name
                    cmd = ([sys.executable, "-m", "explotica", ip]
                            + list(flags)
                            + ["--json", tmp_path])
                    # Ensure --no-arp is in flags for single-host scans
                    if "--no-arp" not in cmd and "/" not in ip:
                        cmd.append("--no-arp")
                    try:
                        proc = subprocess.run(cmd, capture_output=True,
                                                timeout=600, check=False)
                        if Path(tmp_path).exists():
                            new_data = json.loads(
                                Path(tmp_path).read_text(encoding="utf-8")
                            )
                            self.call_from_thread(self._merge_rescan_result,
                                                    new_data)
                        else:
                            self.call_from_thread(
                                self.notify,
                                f"{ip} rescan: no output. stderr={proc.stderr[:100].decode('utf-8', 'ignore')}",
                                timeout=4
                            )
                        Path(tmp_path).unlink(missing_ok=True)
                    except subprocess.TimeoutExpired:
                        self.call_from_thread(
                            self.notify, f"{ip} rescan timed out", timeout=4
                        )
                    except Exception as e:
                        self.call_from_thread(
                            self.notify, f"{ip} rescan failed: {e}", timeout=4
                        )
                # All done — persist + refresh
                self.call_from_thread(self._save_scan)
                self.call_from_thread(self._populate_hosts)
                self.call_from_thread(self._populate_cves)
                self.call_from_thread(self._populate_ports)
                self.call_from_thread(self._populate_exploits)
                self.call_from_thread(self._populate_extra)
                self.call_from_thread(
                    self.notify, f"Rescan of {len(ips)} host(s) complete.",
                    timeout=4
                )

            threading.Thread(target=worker, daemon=True).start()

        def _merge_rescan_result(self, new_scan: dict) -> None:
            """Merge a fresh scan's hosts into self.scan_data."""
            new_hosts_by_ip = {h["ip"]: h for h in new_scan.get("hosts", [])}
            if not new_hosts_by_ip:
                return
            updated = []
            seen = set()
            for h in self.scan_data.get("hosts", []):
                if h["ip"] in new_hosts_by_ip:
                    updated.append(new_hosts_by_ip[h["ip"]])
                    seen.add(h["ip"])
                else:
                    updated.append(h)
            for ip, h in new_hosts_by_ip.items():
                if ip not in seen:
                    updated.append(h)
            self.scan_data["hosts"] = updated
            self.hosts = sorted(updated, key=_ip_sort_key)

        def _save_scan(self) -> None:
            """Persist self.scan_data to self.scan_path."""
            try:
                Path(self.scan_path).parent.mkdir(parents=True, exist_ok=True)
                Path(self.scan_path).write_text(
                    json.dumps(self.scan_data, indent=2), encoding="utf-8"
                )
            except Exception as e:
                self.notify(f"Save failed: {e}", timeout=3)

    app = ExploticaTUI(scan, scan_json_path)
    app.run()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="explotica-tui",
        description="Interactive TUI for Explotica scan results.",
    )
    p.add_argument("scan_json", help="Path to scan JSON file")
    args = p.parse_args(argv)
    if not Path(args.scan_json).exists():
        print(f"[!] Scan file not found: {args.scan_json}")
        return 2
    return run(args.scan_json)


if __name__ == "__main__":
    sys.exit(main())
