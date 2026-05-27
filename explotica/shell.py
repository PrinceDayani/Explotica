"""Interactive REPL shell — stays alive between actions.

Launch with `python -m explotica --shell`. From the prompt:

  explotica> scan 192.168.1.0/24 --full-coverage --turbo
  explotica> hosts
  explotica> host 192.168.1.200
  explotica> cves --severity CRITICAL
  explotica> dashboard
  explotica> save scans/my.json
  explotica> quit

Scans run, results stay in memory, you query them with shell commands.
No restart between scans — the same session can scan multiple targets,
load and merge JSON files, drill into specific findings, and launch
viewers (dashboard, TUI) on the data.
"""

from __future__ import annotations

import cmd
import json
import logging
import shlex
import sys
import threading
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

log = logging.getLogger(__name__)
console = Console()


class ExploticaShell(cmd.Cmd):
    intro = (
        "\n[bold blue]🛰️  Explotica Interactive Shell[/bold blue]\n"
        "[dim]Type 'help' for commands, 'quit' to exit, Tab to autocomplete.[/dim]"
    )
    prompt = "[bold green]explotica>[/bold green] "

    def __init__(self):
        super().__init__()
        self.scan_result = None        # current ScanResult (in-memory)
        self.scan_path: Optional[Path] = None  # last loaded/saved path
        # cmd uses raw stdin — we print intro via rich
        self.intro_text = self.intro

    # ── Lifecycle ────────────────────────────────────────────────────────
    def preloop(self) -> None:
        console.print(Panel.fit(self.intro_text, border_style="blue"))

    def cmdloop(self, intro=None):
        # Rich-friendly prompt rendering — use console.input for color prompts
        while True:
            try:
                line = console.input(self.prompt)
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Bye.[/dim]")
                return
            if line is None:
                return
            stop = self.onecmd(line.strip())
            if stop:
                return

    def emptyline(self) -> bool:
        return False  # don't repeat last command

    def default(self, line: str) -> bool:
        console.print(f"[red]Unknown command:[/red] {line}")
        console.print("[dim]Type 'help' to see available commands.[/dim]")
        return False

    # ── Help ─────────────────────────────────────────────────────────────
    def do_help(self, arg: str) -> bool:
        if arg:
            return super().do_help(arg)
        t = Table(title="Commands", show_lines=False)
        t.add_column("Command", style="cyan")
        t.add_column("What it does")
        rows = [
            ("scan <target> [opts]", "Run a fresh scan (e.g. `scan 192.168.1.0/24 --full-coverage --turbo`)"),
            ("load <file.json>", "Load a previous scan from JSON into memory"),
            ("save [<file.json>]", "Save current scan to JSON (uses last path if omitted)"),
            ("status", "Show current loaded scan summary"),
            ("hosts [--up-only] [--has-cves]", "List discovered hosts"),
            ("host <ip>", "Show one host in detail (ports, CVEs, intel)"),
            ("cves [--severity X] [--kev]", "List all CVEs, optionally filter"),
            ("cve <CVE-ID>", "Show one CVE in detail + which hosts have it"),
            ("ports [--service X]", "List all open ports across all hosts"),
            ("port <num>", "Show every host with that port open"),
            ("priorities", "Top 10 prioritized findings by smart score"),
            ("compliance <cis|pci|hipaa>", "Run compliance evaluation"),
            ("report html|pdf|md <file>", "Write a report"),
            ("dashboard", "Launch web dashboard"),
            ("tui", "Launch textual TUI"),
            ("extra", "Show extra_findings (honeypot/AD/cloud/etc.)"),
            ("clear", "Drop the loaded scan"),
            ("history", "Show command history"),
            ("quit / exit / q", "Leave the shell"),
        ]
        for cmd_name, desc in rows:
            t.add_row(cmd_name, desc)
        console.print(t)
        return False

    # ── Scan ─────────────────────────────────────────────────────────────
    def do_scan(self, arg: str) -> bool:
        """Run a scan: `scan <target> [args ...]`"""
        if not arg.strip():
            console.print("[red]Usage:[/red] scan <target> [options]")
            console.print("[dim]Example: scan 192.168.1.0/24 --full-coverage --turbo[/dim]")
            return False
        from .cli import main as cli_main
        argv = shlex.split(arg)
        # Force a temp JSON output so we can pick the result back up
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        argv.extend(["--json", tmp.name])
        try:
            console.print(f"[dim]Running: explotica {' '.join(argv)}[/dim]\n")
            rc = cli_main(argv)
            if rc == 0 and Path(tmp.name).exists():
                from .models import ScanResult
                data = json.loads(Path(tmp.name).read_text(encoding="utf-8"))
                self.scan_result = ScanResult.from_dict(data)
                self.scan_path = Path(tmp.name)
                console.print(f"\n[green]✓ Scan loaded into memory.[/green] "
                              f"({len(self.scan_result.hosts)} hosts)")
            else:
                console.print(f"[red]Scan exited with code {rc}[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted.[/yellow]")
        except Exception as e:
            console.print(f"[red]Scan error:[/red] {e}")
        return False

    # ── Load / Save / Status ─────────────────────────────────────────────
    def do_load(self, arg: str) -> bool:
        """Load a scan JSON: `load <file.json>`"""
        path = Path(arg.strip().strip('"').strip("'"))
        if not path.exists():
            console.print(f"[red]File not found:[/red] {path}")
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            from .models import ScanResult
            self.scan_result = ScanResult.from_dict(data)
            self.scan_path = path
            console.print(f"[green]✓ Loaded[/green] {len(self.scan_result.hosts)} "
                          f"hosts from [cyan]{path}[/cyan]")
        except (json.JSONDecodeError, OSError, KeyError) as e:
            console.print(f"[red]Could not load:[/red] {e}")
        return False

    def do_save(self, arg: str) -> bool:
        """Save scan to JSON: `save [file.json]`"""
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red] Run `scan` or `load` first.")
            return False
        path = Path(arg.strip() or (self.scan_path or "scans/shell_session.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.scan_result.to_dict(), indent=2),
                         encoding="utf-8")
        self.scan_path = path
        console.print(f"[green]✓ Saved to[/green] [cyan]{path}[/cyan]")
        return False

    def do_status(self, arg: str) -> bool:
        if not self.scan_result:
            console.print("[dim]No scan in memory. Use 'scan' or 'load'.[/dim]")
            return False
        sr = self.scan_result
        open_ports = sum(len(h.ports) for h in sr.hosts)
        total_cves = sum(len(p.cves) for h in sr.hosts for p in h.ports)
        kev = sum(1 for h in sr.hosts for p in h.ports for c in p.cves
                   if c.in_kev)
        console.print(Panel.fit(
            f"[bold]Target:[/bold] {sr.target}\n"
            f"[bold]Hosts:[/bold] {len(sr.hosts)}\n"
            f"[bold]Open ports:[/bold] {open_ports}\n"
            f"[bold]CVEs:[/bold] {total_cves} ({kev} KEV)\n"
            f"[bold]Duration:[/bold] {sr.duration_s}s\n"
            f"[bold]Source:[/bold] {self.scan_path or 'in-memory'}",
            title="Current scan",
            border_style="green",
        ))
        return False

    def do_clear(self, arg: str) -> bool:
        self.scan_result = None
        self.scan_path = None
        console.print("[dim]Scan cleared.[/dim]")
        return False

    # ── Browse ───────────────────────────────────────────────────────────
    def do_hosts(self, arg: str) -> bool:
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        flags = arg.split()
        up_only = "--up-only" in flags
        has_cves = "--has-cves" in flags

        t = Table(title=f"Hosts ({self.scan_result.target})", show_lines=False)
        t.add_column("IP", style="cyan")
        t.add_column("Hostname")
        t.add_column("MAC", style="dim")
        t.add_column("Vendor")
        t.add_column("Ports", justify="right")
        t.add_column("CVEs", justify="right")
        t.add_column("Worst", style="bold")

        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        for h in sorted(self.scan_result.hosts,
                         key=lambda x: tuple(int(o) for o in x.ip.split("."))):
            if up_only and not h.is_up:
                continue
            cves = [c for p in h.ports for c in p.cves]
            if has_cves and not cves:
                continue
            worst = max((sev_order.get((c.severity or "").upper(), 0)
                          for c in cves), default=0)
            worst_str = {4: "[red]CRITICAL[/red]", 3: "[orange1]HIGH[/orange1]",
                          2: "[yellow]MEDIUM[/yellow]",
                          1: "[green]LOW[/green]"}.get(worst, "-")
            t.add_row(h.ip, h.hostname or "-",
                       (h.mac or "-")[:17],
                       (h.vendor or "-")[:18],
                       str(len(h.ports)),
                       str(len(cves)),
                       worst_str)
        console.print(t)
        return False

    def do_host(self, arg: str) -> bool:
        """Show details for one host: `host <ip>`"""
        ip = arg.strip()
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        target = next((h for h in self.scan_result.hosts if h.ip == ip), None)
        if not target:
            console.print(f"[red]Host {ip} not found[/red]")
            return False

        # Build a detail block
        from rich.text import Text
        lines = Text()
        lines.append(f"{target.ip}\n", style="bold cyan")
        if target.hostname:
            lines.append(f"  hostname: {target.hostname}\n")
        if target.mac:
            lines.append(f"  MAC: {target.mac}  vendor: {target.vendor or '-'}\n")
        if target.os_hint:
            oh = target.os_hint
            lines.append(f"  OS: {oh.get('os_family')} (TTL={target.ttl})\n")
        lines.append("\n")
        for p in target.ports:
            lines.append(f"  {p.number}/{p.protocol}", style="bold green")
            if p.service:
                lines.append(f" {p.service}")
            if p.product_name and p.product_version:
                lines.append(f"  [{p.product_name} {p.product_version}]",
                              style="yellow")
            lines.append("\n")
            if p.banner:
                lines.append(f"    {p.banner[:120]}\n", style="dim")
            for c in sorted(p.cves, key=lambda x: (
                not x.in_kev, -(x.epss_score or 0), -(x.cvss or 0)
            ))[:5]:
                sev = (c.severity or "?").upper()
                marker = " KEV" if c.in_kev else ""
                lines.append(
                    f"    {sev:<10} {c.cvss or '?':<5} {c.id}{marker}\n"
                )
        console.print(lines)
        return False

    def do_cves(self, arg: str) -> bool:
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        flags = arg.split()
        severity_filter = None
        kev_only = False
        for i, f in enumerate(flags):
            if f == "--severity" and i + 1 < len(flags):
                severity_filter = flags[i + 1].upper()
            elif f == "--kev":
                kev_only = True

        all_cves = []
        for h in self.scan_result.hosts:
            for p in h.ports:
                for c in p.cves:
                    if severity_filter and (c.severity or "").upper() != severity_filter:
                        continue
                    if kev_only and not c.in_kev:
                        continue
                    all_cves.append((h.ip, p.number, c))

        # Dedupe by CVE id but keep one example
        seen: dict[str, list] = {}
        for ip, port, c in all_cves:
            seen.setdefault(c.id, []).append((ip, port, c))

        t = Table(title=f"CVEs ({len(seen)} unique, {len(all_cves)} total findings)")
        t.add_column("CVE", style="cyan")
        t.add_column("Sev", style="bold")
        t.add_column("CVSS", justify="right")
        t.add_column("EPSS", justify="right")
        t.add_column("KEV")
        t.add_column("Hosts", justify="right")

        sorted_cves = sorted(seen.items(), key=lambda kv: (
            not kv[1][0][2].in_kev,
            -(kv[1][0][2].epss_score or 0),
            -(kv[1][0][2].cvss or 0),
        ))
        for cve_id, occs in sorted_cves[:50]:
            c = occs[0][2]
            sev = (c.severity or "?").upper()
            sev_str = {"CRITICAL": "[red]CRITICAL[/red]",
                        "HIGH": "[orange1]HIGH[/orange1]",
                        "MEDIUM": "[yellow]MEDIUM[/yellow]",
                        "LOW": "[green]LOW[/green]"}.get(sev, sev)
            t.add_row(cve_id, sev_str,
                       f"{c.cvss:.1f}" if c.cvss else "-",
                       f"{c.epss_score:.2f}" if c.epss_score else "-",
                       "[red bold]KEV[/red bold]" if c.in_kev else "",
                       str(len(occs)))
        console.print(t)
        if len(seen) > 50:
            console.print(f"[dim](showing top 50 of {len(seen)})[/dim]")
        return False

    def do_cve(self, arg: str) -> bool:
        """Show CVE detail + hosts affected: `cve <CVE-ID>`"""
        cve_id = arg.strip()
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        affected = []
        cve_obj = None
        for h in self.scan_result.hosts:
            for p in h.ports:
                for c in p.cves:
                    if c.id == cve_id:
                        affected.append((h.ip, p.number, c))
                        cve_obj = c
        if not cve_obj:
            console.print(f"[red]CVE {cve_id} not in current scan[/red]")
            return False
        console.print(Panel.fit(
            f"[bold cyan]{cve_obj.id}[/bold cyan]\n"
            f"Severity: [bold]{cve_obj.severity}[/bold]  CVSS: {cve_obj.cvss}\n"
            f"EPSS: {cve_obj.epss_score}  "
            f"{'[bold red]KEV-listed[/bold red]' if cve_obj.in_kev else ''}\n"
            f"Source: {cve_obj.source}\n\n"
            f"{cve_obj.summary or '(no summary)'}",
            title="CVE detail",
            border_style="red" if cve_obj.in_kev else "yellow",
        ))
        console.print("\n[bold]Affected hosts:[/bold]")
        for ip, port, _ in affected:
            console.print(f"  {ip}:{port}")
        return False

    def do_ports(self, arg: str) -> bool:
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        flags = arg.split()
        svc_filter = None
        for i, f in enumerate(flags):
            if f == "--service" and i + 1 < len(flags):
                svc_filter = flags[i + 1].lower()

        port_map: dict[int, list[str]] = {}
        for h in self.scan_result.hosts:
            for p in h.ports:
                if svc_filter and (p.service or "").lower() != svc_filter:
                    continue
                port_map.setdefault(p.number, []).append(h.ip)

        t = Table(title="Open ports across network")
        t.add_column("Port", justify="right", style="cyan")
        t.add_column("Service")
        t.add_column("Hosts", justify="right")
        for port in sorted(port_map.keys()):
            sample_host = next((h for h in self.scan_result.hosts
                                  if any(p.number == port for p in h.ports)), None)
            svc = ""
            if sample_host:
                p = next((p for p in sample_host.ports if p.number == port), None)
                if p:
                    svc = p.service or ""
            t.add_row(str(port), svc, str(len(port_map[port])))
        console.print(t)
        return False

    def do_port(self, arg: str) -> bool:
        """List hosts with a specific port open: `port <num>`"""
        try:
            target_port = int(arg.strip())
        except ValueError:
            console.print("[red]Usage:[/red] port <number>")
            return False
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        hits = []
        for h in self.scan_result.hosts:
            for p in h.ports:
                if p.number == target_port:
                    hits.append((h, p))
        if not hits:
            console.print(f"[dim]No host has port {target_port} open[/dim]")
            return False
        t = Table(title=f"Hosts with port {target_port} open")
        t.add_column("Host", style="cyan")
        t.add_column("Service")
        t.add_column("Product/version")
        t.add_column("Banner", overflow="fold")
        t.add_column("CVEs", justify="right")
        for h, p in hits:
            prod = (f"{p.product_name} {p.product_version}"
                    if p.product_name else "-")
            t.add_row(h.ip, p.service or "-", prod,
                       (p.banner or "")[:60], str(len(p.cves)))
        console.print(t)
        return False

    def do_priorities(self, arg: str) -> bool:
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        from .prioritize import score_scan_result
        scored = score_scan_result(self.scan_result.to_dict())
        top = scored.get("top_priorities", [])
        if not top:
            console.print("[dim]No findings to prioritize[/dim]")
            return False
        t = Table(title="Top 10 priorities")
        t.add_column("Score", justify="right", style="bold")
        t.add_column("Bucket")
        t.add_column("CVE", style="cyan")
        t.add_column("Host")
        t.add_column("Reasons", overflow="fold")
        for tp in top:
            t.add_row(f"{tp['score']:.0f}",
                       tp.get("bucket", ""),
                       tp.get("cve_id", ""),
                       tp.get("host_ip", ""),
                       "; ".join(tp.get("reasons", []))[:80])
        console.print(t)
        return False

    def do_compliance(self, arg: str) -> bool:
        fw = arg.strip().lower() or "cis"
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        from .compliance import evaluate
        r = evaluate(self.scan_result.to_dict(), framework=fw)
        if "error" in r:
            console.print(f"[red]{r['error']}[/red]")
            return False
        console.print(Panel.fit(
            f"[bold]{r['framework']}[/bold]\n"
            f"Pass: {r['pass']}  Fail: {r['fail']}  Skip: {r['skip']}\n"
            f"Score: {r['score_pct']}%",
            border_style="green" if r['fail'] == 0 else "yellow",
        ))
        for res in r["results"]:
            mark = ("[green]✓[/green]" if res["outcome"] == "PASS"
                    else "[red]✗[/red]" if res["outcome"] == "FAIL"
                    else "[dim]~[/dim]")
            sev_color = {"CRITICAL": "red", "HIGH": "orange1",
                          "MEDIUM": "yellow"}.get(res["severity"], "dim")
            console.print(f"  {mark} [{sev_color}]{res['severity']:<8}[/{sev_color}] "
                          f"{res['id']:<14} {res['title']}")
            if res["outcome"] == "FAIL" and res["evidence"]:
                ev = res["evidence"] if isinstance(res["evidence"], list) else [res["evidence"]]
                console.print(f"     [dim]evidence: {', '.join(str(e) for e in ev[:3])}[/dim]")
        return False

    def do_extra(self, arg: str) -> bool:
        if not self.scan_result or not self.scan_result.extra_findings:
            console.print("[dim]No extra findings[/dim]")
            return False
        for key, val in self.scan_result.extra_findings.items():
            if isinstance(val, dict):
                console.print(f"[bold cyan]{key}:[/bold cyan] {len(val)} entries")
            elif isinstance(val, list):
                console.print(f"[bold cyan]{key}:[/bold cyan] {len(val)} items")
            else:
                console.print(f"[bold cyan]{key}:[/bold cyan] {val}")
        return False

    # ── Report / view ────────────────────────────────────────────────────
    def do_report(self, arg: str) -> bool:
        """Write report: `report html|pdf|md <path>`"""
        parts = arg.split()
        if len(parts) < 2:
            console.print("[red]Usage:[/red] report html|pdf|md <path>")
            return False
        fmt, path = parts[0], parts[1]
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        if fmt == "html":
            from .report import write_report
            out = write_report(self.scan_result, path)
            console.print(f"[green]✓ HTML written to[/green] [cyan]{out}[/cyan]")
        elif fmt == "pdf":
            from .report_pdf import write_pdf_report
            out = write_pdf_report(self.scan_result, path)
            console.print(f"[green]✓ PDF written to[/green] [cyan]{out}[/cyan]")
        elif fmt == "md":
            from .report_pdf import write_markdown_report
            out = write_markdown_report(self.scan_result, path)
            console.print(f"[green]✓ MD written to[/green] [cyan]{out}[/cyan]")
        else:
            console.print(f"[red]Unknown format:[/red] {fmt}")
        return False

    def do_dashboard(self, arg: str) -> bool:
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        # Need a file on disk for the dashboard to serve
        if not self.scan_path:
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            tmp.write(json.dumps(self.scan_result.to_dict()).encode())
            tmp.close()
            self.scan_path = Path(tmp.name)
        from .dashboard import serve
        port = 8765
        console.print(f"[green]Launching dashboard at http://127.0.0.1:{port}[/green]")
        console.print("[dim]Ctrl-C to stop and return to shell.[/dim]")
        try:
            serve(str(self.scan_path), host="127.0.0.1", port=port)
        except KeyboardInterrupt:
            console.print("\n[dim]Dashboard stopped.[/dim]")
        return False

    def do_tui(self, arg: str) -> bool:
        if not self.scan_result:
            console.print("[red]No scan loaded.[/red]")
            return False
        if not self.scan_path:
            self.do_save("scans/_shell_tmp.json")
        from .tui import run
        run(str(self.scan_path))
        return False

    def do_history(self, arg: str) -> bool:
        try:
            import readline
            for i in range(1, readline.get_current_history_length() + 1):
                console.print(f"  {i:3d}  {readline.get_history_item(i)}")
        except ImportError:
            console.print("[dim]readline not available[/dim]")
        return False

    def do_quit(self, arg: str) -> bool:
        console.print("[dim]Bye.[/dim]")
        return True

    do_exit = do_quit
    do_q = do_quit
    do_EOF = do_quit


def launch_shell() -> int:
    ExploticaShell().cmdloop()
    return 0
