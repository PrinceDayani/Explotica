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

    def _try_autoload(self) -> bool:
        """If no scan in memory, try to load the most recent JSON in ./scans/

        Returns True if a scan got loaded, False if nothing found.
        """
        if self.scan_result is not None:
            return True
        scans_dir = Path("scans")
        if not scans_dir.exists():
            return False
        candidates = sorted(scans_dir.glob("*.json"),
                             key=lambda p: p.stat().st_mtime,
                             reverse=True)
        if not candidates:
            return False
        newest = candidates[0]
        try:
            from .models import ScanResult
            data = json.loads(newest.read_text(encoding="utf-8"))
            self.scan_result = ScanResult.from_dict(data)
            self.scan_path = newest
            console.print(f"[dim]Auto-loaded most recent scan: [cyan]{newest}[/cyan][/dim]")
            return True
        except Exception as e:
            console.print(f"[dim]Could not auto-load {newest}: {e}[/dim]")
            return False

    def _require_scan(self) -> bool:
        """Return True if a scan is in memory (auto-loading if needed).
        Otherwise print a helpful message and return False."""
        if self.scan_result is not None:
            return True
        if self._try_autoload():
            return True
        console.print("[yellow]No scan in memory.[/yellow]")
        console.print("  Run a fresh scan:  [cyan]scan <target> --full-coverage --turbo[/cyan]")
        console.print("  Or load a previous one:  [cyan]load <file.json>[/cyan]")
        scans_dir = Path("scans")
        if scans_dir.exists():
            jsons = list(scans_dir.glob("*.json"))
            if jsons:
                console.print(f"  [dim](found {len(jsons)} JSON files in scans/ — try `load scans/...`)[/dim]")
        return False

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
            ("─── Scan setup ───", ""),
            ("scan <target> [opts]", "Fresh scan (e.g. `scan 192.168.1.0/24 --full-coverage --turbo`)"),
            ("auto [opts]", "Auto-discover & scan all local subnets"),
            ("wizard", "Guided setup wizard"),
            ("listnet", "List local subnets without scanning"),
            ("spider <cidr> [--depth N]", "Recursive subnet discovery (network spider)"),
            ("load <file.json>", "Load previous scan"),
            ("save [<file.json>]", "Save current scan"),
            ("clear", "Drop loaded scan"),
            ("─── Browse / query ───", ""),
            ("status", "Current scan summary"),
            ("hosts [--up-only] [--has-cves]", "List hosts"),
            ("host <ip>", "Host detail"),
            ("cves [--severity X] [--kev]", "List CVEs"),
            ("cve <CVE-ID>", "CVE detail + affected hosts"),
            ("ports [--service X]", "List all open ports"),
            ("port <num>", "Hosts with that port open"),
            ("priorities", "Top 10 by smart score"),
            ("extra", "Show extra_findings"),
            ("─── Active checks ───", ""),
            ("ad <domain>", "Active Directory enumeration"),
            ("asrep <domain>", "AS-REP roast hash extraction"),
            ("sshcreds user:pass [--key F]", "Credentialed SSH scan"),
            ("winrm user:pass", "Credentialed WinRM (Windows) scan"),
            ("defaultcreds", "Test default creds against scan"),
            ("verify", "Run verify probes (Heartbleed/MS17/etc.)"),
            ("fuzz [--sqli-time]", "Active web fuzzing on HTTP services"),
            ("takeover [sub1 sub2 …]", "Subdomain takeover check"),
            ("cloud <keyword>", "Cloud asset discovery"),
            ("smtp <host>", "SMTP open relay + VRFY/EXPN audit"),
            ("─── Output / view ───", ""),
            ("compliance <cis|pci|hipaa>", "Compliance evaluation"),
            ("report html|pdf|md <file>", "Write report"),
            ("dashboard", "Web dashboard"),
            ("tui", "Textual TUI"),
            ("plugins", "List loaded plugins"),
            ("history", "Command history"),
            ("quit / exit / q", "Leave"),
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
        if not self._require_scan():
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
        if not self._require_scan():
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
        if not self._require_scan():
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
        if not self._require_scan():
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
        if not self._require_scan():
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
        if not self._require_scan():
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
        if not self._require_scan():
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
        if not self._require_scan():
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
        if not self._require_scan():
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
        if not self._require_scan():
            return False
        # fastapi/uvicorn are optional — check first
        from .dashboard import fastapi_available, serve
        if not fastapi_available():
            console.print("[yellow]The dashboard requires fastapi + uvicorn.[/yellow]")
            console.print("  Install:  [cyan]pip install fastapi uvicorn[standard][/cyan]")
            console.print("  Or use the TUI instead:  [cyan]tui[/cyan]")
            return False
        # Need a file on disk for the dashboard to serve
        if not self.scan_path:
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            tmp.write(json.dumps(self.scan_result.to_dict()).encode())
            tmp.close()
            self.scan_path = Path(tmp.name)
        port = 8765
        console.print(f"[green]Launching dashboard at http://127.0.0.1:{port}[/green]")
        console.print("[dim]Ctrl-C to stop and return to shell.[/dim]")
        try:
            serve(str(self.scan_path), host="127.0.0.1", port=port)
        except KeyboardInterrupt:
            console.print("\n[dim]Dashboard stopped.[/dim]")
        return False

    def do_tui(self, arg: str) -> bool:
        if not self._require_scan():
            return False
        # textual is optional — check first so we give a nice error
        try:
            import textual  # noqa: F401
        except ImportError:
            console.print("[yellow]The TUI requires the `textual` library.[/yellow]")
            console.print("  Install:  [cyan]pip install textual[/cyan]")
            console.print("  Or alternatively use the web dashboard:  [cyan]dashboard[/cyan]")
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

    # ────────────────────────────────────────────────────────────────────
    # Module command surface — every major capability accessible from REPL
    # ────────────────────────────────────────────────────────────────────

    def do_wizard(self, arg: str) -> bool:
        """Launch the interactive setup wizard from inside the shell."""
        from .interactive import run_wizard
        wiz_args = run_wizard()
        if wiz_args:
            self.do_scan(" ".join(wiz_args))
        return False

    def do_auto(self, arg: str) -> bool:
        """Auto-discover all local subnets and scan each. `auto [extra flags]`"""
        args = "--auto " + arg
        self.do_scan(args.strip())
        return False

    def do_listnet(self, arg: str) -> bool:
        """List discovered local subnets without scanning."""
        try:
            from .enumerate import list_subnets, format_summary
            net = list_subnets()
            console.print(format_summary(net))
        except Exception as e:
            console.print(f"[red]Failed:[/red] {e}")
        return False

    def do_spider(self, arg: str) -> bool:
        """Recursive network spider: `spider <seed_cidr> [--depth N]`"""
        parts = arg.split()
        if not parts:
            console.print("[red]Usage:[/red] spider <seed_cidr> [--depth N]")
            return False
        seed = parts[0]
        depth = 2
        for i, p in enumerate(parts):
            if p == "--depth" and i + 1 < len(parts):
                try:
                    depth = int(parts[i + 1])
                except ValueError:
                    pass
        from .network_spider import spider
        console.print(f"[bold]Spidering[/bold] from [cyan]{seed}[/cyan] (depth={depth})…")
        result = spider(seed, max_depth=depth,
                          progress=lambda m: console.print(f"  [dim]·[/dim] {m}"))
        console.print(Panel.fit(
            f"Subnets found:  {result['subnet_count']}\n"
            f"Routers found:  {result['router_count']}\n"
            f"Depth reached:  {result['depth_reached']}",
            title="Spider results", border_style="green",
        ))
        for s in result["subnets"]:
            console.print(f"  📡 {s}")
        for e in result["edges"]:
            console.print(f"  🔗 {e['router']} routes to {e['subnet']}")
        return False

    def do_ad(self, arg: str) -> bool:
        """Active Directory enumeration: `ad <domain>`"""
        domain = arg.strip()
        if not domain:
            console.print("[red]Usage:[/red] ad <domain>")
            return False
        from .ad_enum import run_ad_enum
        console.print(f"[bold]AD enum:[/bold] {domain}")
        result = run_ad_enum(domain)
        console.print(f"  DCs found: {len(result.get('dcs', []))}")
        for dc in result.get("dcs", []):
            console.print(f"    {dc.get('target')} (port {dc.get('port')})")
        console.print(f"  Users confirmed: {len(result.get('users_found', []))}")
        roastable = result.get("asreproastable", [])
        if roastable:
            console.print(f"  [bold red]AS-REP roastable:[/bold red] "
                          f"{len(roastable)} (run `asrep {domain}` to extract)")
            for u in roastable:
                console.print(f"    {u['username']}")
        return False

    def do_asrep(self, arg: str) -> bool:
        """AS-REP roast: `asrep <domain>` (extracts hashcat-format hashes)"""
        domain = arg.strip()
        if not domain:
            console.print("[red]Usage:[/red] asrep <domain>")
            return False
        from .kerberoast import run_roast
        result = run_roast(domain)
        hashes = result.get("asrep_hashes", [])
        if not hashes:
            console.print("[dim]No AS-REP roastable accounts found.[/dim]")
            return False
        console.print(f"[bold red]🔥 {len(hashes)} hash(es) extracted![/bold red]")
        for h in hashes:
            console.print(f"\n  [bold cyan]{h['username']}@{domain}[/bold cyan] "
                          f"(etype {h['etype_name']})")
            console.print(f"  [dim]{h['hashcat_format'][:120]}…[/dim]")
        console.print(f"\n[dim]Crack with: hashcat -m {hashes[0]['hashcat_mode']} <hashfile> <wordlist>[/dim]")
        return False

    def do_takeover(self, arg: str) -> bool:
        """Check loaded scan's discovered subdomains for takeover."""
        if not self._require_scan():
            return False
        from .takeover import check_subdomains
        # Pull subdomains from the dns_info of the scan
        di = self.scan_result.dns_info or {}
        subs = [s["name"] for s in di.get("subdomains_found", [])]
        if not subs:
            arg_subs = arg.split()
            if arg_subs:
                subs = arg_subs
        if not subs:
            console.print("[yellow]No subdomains to check.[/yellow]")
            console.print("  Either scan a domain first OR pass subdomains: takeover sub.example.com sub2.example.com")
            return False
        console.print(f"[bold]Checking {len(subs)} subdomain(s) for takeover…[/bold]")
        findings = check_subdomains(subs)
        if not findings:
            console.print("[green]No takeover candidates found.[/green]")
            return False
        for f in findings:
            console.print(f"  💥 [bold red]{f['subdomain']}[/bold red] → "
                          f"{f['service']} ({f['severity']})")
            console.print(f"     [dim]{f.get('note', '')}[/dim]")
        return False

    def do_cloud(self, arg: str) -> bool:
        """Cloud asset discovery: `cloud <keyword>`"""
        keyword = arg.strip()
        if not keyword:
            console.print("[red]Usage:[/red] cloud <keyword>")
            console.print("[dim]Example: cloud mycompany — searches mycompany-prod, mycompany-backup, etc.[/dim]")
            return False
        from .cloud_assets import discover_cloud_assets
        console.print(f"[bold]Discovering cloud assets for '{keyword}'…[/bold]")
        findings = discover_cloud_assets(keyword)
        if not findings:
            console.print("[dim]No accessible cloud assets found.[/dim]")
            return False
        for f in findings:
            console.print(f"  ☁ [bold]{f['provider']}[/bold] "
                          f"[cyan]{f.get('bucket', f.get('account'))}[/cyan] "
                          f"({f['status']}, {f['severity']})")
            console.print(f"     [dim]{f.get('url', '')}[/dim]")
        return False

    def do_smtp(self, arg: str) -> bool:
        """SMTP audit (open relay + VRFY/EXPN): `smtp <host>`"""
        host = arg.strip()
        if not host:
            console.print("[red]Usage:[/red] smtp <host>")
            return False
        from .smtp_test import audit_smtp
        console.print(f"[bold]SMTP audit:[/bold] {host}")
        result = audit_smtp(host)
        rt = result.get("relay_test", {})
        if rt.get("finding") == "OPEN_RELAY":
            console.print("[bold red]💥 OPEN RELAY[/bold red]")
        else:
            console.print(f"  Relay: {rt.get('finding', '?')}")
        vrfy = result.get("vrfy_expn", {})
        if vrfy.get("users_found"):
            console.print(f"  Users enumerated: {len(vrfy['users_found'])}")
            for u in vrfy["users_found"][:10]:
                console.print(f"    {u['user']} ({u['via']})")
        return False

    def do_defaultcreds(self, arg: str) -> bool:
        """Test default credentials against loaded scan's open services."""
        if not self._require_scan():
            return False
        from .default_creds import check_host_defaults
        console.print("[bold]Testing default credentials…[/bold]")
        any_found = False
        for h in self.scan_result.hosts:
            ports = [p.number for p in h.ports]
            findings = check_host_defaults(h.ip, ports)
            for f in findings:
                any_found = True
                console.print(f"  💥 [bold red]{h.ip}[/bold red] "
                              f"{f['service']}: {f['credentials']} "
                              f"({f.get('severity')})")
        if not any_found:
            console.print("[green]No default credentials accepted.[/green]")
        return False

    def do_verify(self, arg: str) -> bool:
        """Run verification probes (Heartbleed, MS17, Shellshock, etc.) on loaded scan."""
        if not self._require_scan():
            return False
        from .verify_probes import verify_scan
        from .verify_probes_v2 import verify_scan_v2
        scan_dict = {"hosts": [h.to_dict() for h in self.scan_result.hosts]}
        console.print("[bold]Running verify probes…[/bold]")
        v1 = verify_scan(scan_dict)
        v2 = verify_scan_v2(scan_dict)
        all_findings = {**v1, **v2}
        if not all_findings:
            console.print("[green]No verified vulnerabilities found.[/green]")
            return False
        for ip, findings in all_findings.items():
            for f in findings:
                cve = f.get("cve", f.get("name", "?"))
                console.print(f"  💥 [bold red]{ip}[/bold red] "
                              f"{cve} - {f.get('name', '')} "
                              f"({f.get('severity', 'INFO')})")
                if f.get("note"):
                    console.print(f"     [dim]{f['note']}[/dim]")
        return False

    def do_fuzz(self, arg: str) -> bool:
        """Active web fuzzing on loaded scan's HTTP services."""
        if not self._require_scan():
            return False
        from .web_fuzz import fuzz_scan
        include_sqli = "--sqli-time" in arg
        console.print("[bold]Web fuzzing…[/bold]")
        scan_dict = {"hosts": [h.to_dict() for h in self.scan_result.hosts]}
        results = fuzz_scan(scan_dict, include_sqli_time=include_sqli)
        if not results:
            console.print("[green]No web vulns found via fuzz.[/green]")
            return False
        for ip, findings in results.items():
            for f in findings:
                console.print(f"  💥 [bold red]{ip}:{f.get('port', '?')}[/bold red] "
                              f"{f['vuln']} ({f['severity']})")
                if f.get("evidence"):
                    console.print(f"     [dim]{f['evidence'][:100]}[/dim]")
        return False

    def do_sshcreds(self, arg: str) -> bool:
        """Credentialed SSH scan: `sshcreds user:password [--key keyfile]`"""
        if not self._require_scan():
            return False
        if not arg.strip():
            console.print("[red]Usage:[/red] sshcreds user:password [--key keyfile]")
            return False
        parts = arg.split()
        creds_str = parts[0]
        key = None
        if "--key" in parts:
            idx = parts.index("--key")
            if idx + 1 < len(parts):
                key = parts[idx + 1]
        if ":" in creds_str:
            user, pw = creds_str.split(":", 1)
        else:
            user, pw = creds_str, None
        from .creds_scan import credentialed_scan_hosts
        creds = {"username": user, "password": pw, "key_filename": key}
        console.print(f"[bold]Credentialed SSH scan ({user}@…)[/bold]")
        results = credentialed_scan_hosts(self.scan_result.hosts, creds)
        for ip, data in results.items():
            console.print(f"\n  [bold cyan]{ip}[/bold cyan]")
            console.print(f"    Packages: {data.get('system_package_count', 0)}")
            console.print(f"    CVEs found: {data.get('total_cves', 0)}")
            for cve in data.get("cve_findings", [])[:5]:
                console.print(f"      {cve['package']} {cve['version']}: "
                              f"{cve['cve_count']} CVE(s)")
        if not self.scan_result.extra_findings:
            self.scan_result.extra_findings = {}
        self.scan_result.extra_findings["credentialed"] = results
        return False

    def do_winrm(self, arg: str) -> bool:
        """Credentialed WinRM scan: `winrm user:password`"""
        if not self._require_scan():
            return False
        if not arg.strip():
            console.print("[red]Usage:[/red] winrm user:password")
            return False
        creds_str = arg.split()[0]
        if ":" in creds_str:
            user, pw = creds_str.split(":", 1)
        else:
            user, pw = creds_str, ""
        from .winrm_scan import winrm_scan_hosts
        creds = {"username": user, "password": pw, "transport": "ntlm"}
        console.print(f"[bold]Credentialed WinRM scan ({user}@…)[/bold]")
        results = winrm_scan_hosts(self.scan_result.hosts, creds)
        for ip, data in results.items():
            console.print(f"\n  [bold cyan]{ip}[/bold cyan]")
            console.print(f"    Products: {data.get('product_count', 0)}")
            console.print(f"    Hotfixes: {data.get('hotfix_count', 0)}")
            console.print(f"    CVEs: {data.get('total_cves', 0)}")
        return False

    def do_plugins(self, arg: str) -> bool:
        """List discovered probe plugins."""
        from .plugins import discover_plugins, all_probes, all_reports
        loaded = discover_plugins()
        probes = all_probes()
        reports = all_reports()
        console.print(f"[bold]Plugins loaded:[/bold] "
                      f"{len(probes)} probe(s), {len(reports)} report(s)")
        for p in probes:
            console.print(f"  probe: {p.name} (ports: {p.ports})")
        for r in reports:
            console.print(f"  report: {r.name}")
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
