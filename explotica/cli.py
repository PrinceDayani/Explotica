"""CLI entry point — pretty terminal output via rich, JSON export via --json."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                            TimeElapsedColumn)
from rich.table import Table
from rich.text import Text

from . import __version__
from .models import ScanResult
from .ports import TOP_100_PORTS
from .scanner import run_scan

log = logging.getLogger(__name__)

console = Console()


def parse_ports(spec: str) -> list[int]:
    """Accept '22,80,443' or '1-1024' or 'top100'."""
    spec = spec.strip().lower()
    if spec == "top100":
        return TOP_100_PORTS
    if spec == "top1000":
        return list(range(1, 1001))
    if spec == "all":
        return list(range(1, 65536))
    out: list[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(chunk))
    return out


_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "NONE":     "dim",
    "UNKNOWN":  "dim",
}


def render_result(result: ScanResult, show_vulns: bool = False) -> Table:
    table = Table(
        title=f"Explotica scan — {result.target}",
        caption=f"{len(result.hosts)} host(s) in {result.duration_s:.2f}s",
        show_lines=True,
    )
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Hostname")
    table.add_column("MAC", style="dim")
    table.add_column("Vendor")
    table.add_column("Open ports / services", overflow="fold")
    if show_vulns:
        table.add_column("Vulns (top CVEs)", overflow="fold")

    for host in sorted(result.hosts, key=lambda h: tuple(int(o) for o in h.ip.split("."))):
        ports_cell = Text()
        vulns_cell = Text()
        for p in host.ports:
            label = f"{p.number}"
            if p.service:
                label += f"/{p.service}"
            ports_cell.append(label + " ", style="bold green")
            if p.product_name and p.product_version:
                ports_cell.append(
                    f"[{p.product_name} {p.product_version}] ", style="bold yellow"
                )
            if p.banner:
                ports_cell.append(f"({p.banner[:60]})\n", style="dim")
            else:
                ports_cell.append("\n")

            # Tech stack labels show up in the ports cell
            if p.tech_stack:
                ports_cell.append(
                    f"  tech: {', '.join(p.tech_stack[:4])}\n", style="cyan"
                )
            # TLS issues
            if p.tls_info and p.tls_info.get("issues"):
                for iss in p.tls_info["issues"][:2]:
                    ports_cell.append(f"  ⚠ TLS: {iss}\n", style="bold yellow")
            # HTTP sensitive paths
            if p.http_info:
                paths = p.http_info.get("paths_found", [])
                if paths:
                    sample = ", ".join(
                        f"{x['path']}({x['status']})" for x in paths[:3]
                    )
                    ports_cell.append(f"  paths: {sample}\n", style="dim cyan")
                if p.http_info.get("title"):
                    ports_cell.append(
                        f"  title: {p.http_info['title'][:60]}\n", style="dim"
                    )
            # SMB findings
            if p.smb_info and p.smb_info.get("recommendations"):
                for rec in p.smb_info["recommendations"][:2]:
                    ports_cell.append(f"  ⚠ SMB: {rec}\n", style="bold yellow")
            # SSH algorithm enum
            if p.ssh_info:
                lib = p.ssh_info.get("library_hint", "?")
                ports_cell.append(f"  SSH lib: {lib}\n", style="dim cyan")
                if p.ssh_info.get("issues"):
                    for iss in p.ssh_info["issues"][:2]:
                        ports_cell.append(f"  ⚠ SSH: {iss}\n", style="bold yellow")
            # Web crawl summary
            if p.crawl_info:
                ci = p.crawl_info
                ports_cell.append(
                    f"  crawl: {ci.get('total_pages', 0)} page(s), "
                    f"{len(ci.get('api_endpoints_found', []))} API endpoint(s), "
                    f"{len(ci.get('forms', []))} form(s)\n",
                    style="dim cyan"
                )
                # Show top 3 API endpoints
                for ep in (ci.get("api_endpoints_found") or [])[:3]:
                    ports_cell.append(f"    {ep}\n", style="dim")

            if show_vulns:
                # Sort by KEV first, then EPSS/CVSS
                sorted_cves = sorted(
                    p.cves,
                    key=lambda c: (
                        not c.in_kev,
                        -(c.epss_score or 0),
                        -(c.cvss or 0),
                    ),
                )
                if sorted_cves:
                    # Top 3 CVEs per port, prioritized
                    for cve in sorted_cves[:3]:
                        style = _SEVERITY_STYLE.get(cve.severity, "white")
                        score = f"{cve.cvss:.1f}" if cve.cvss is not None else "?"
                        markers = []
                        if cve.in_kev:
                            markers.append("[bold red]KEV[/bold red]")
                        if cve.epss_score is not None and cve.epss_score >= 0.5:
                            markers.append(f"EPSS={cve.epss_score:.2f}")
                        marker_str = (" " + " ".join(markers)) if markers else ""
                        vulns_cell.append(
                            f"{cve.id} ({cve.severity} {score}){marker_str} @{p.number}\n",
                            style=style,
                        )
                    if len(sorted_cves) > 3:
                        vulns_cell.append(
                            f"+{len(sorted_cves) - 3} more @{p.number}\n", style="dim"
                        )
                if p.exploits:
                    # Up to 3 exploits per port
                    for ex in p.exploits[:3]:
                        edb = f"EDB-{ex.edb_id}" if ex.edb_id else "exploit"
                        vulns_cell.append(
                            f"💥 {edb}: {ex.title[:60]} @{p.number}\n",
                            style="bold magenta",
                        )
                    if len(p.exploits) > 3:
                        vulns_cell.append(
                            f"+{len(p.exploits) - 3} more exploits @{p.number}\n",
                            style="dim",
                        )

        # Augment hostname column with OS hint when we have it
        host_display = host.hostname or "-"
        if host.os_hint:
            host_display = (
                f"{host_display}\n"
                f"[dim]OS: {host.os_hint['os_family']} "
                f"({host.os_hint['hops_estimate']}h, TTL={host.ttl})[/dim]"
            )
        if host.udp_services:
            udp_summary: list[str] = []
            if host.udp_services.get("snmp"):
                sd = host.udp_services["snmp"].get("sysDescr", "")[:40]
                udp_summary.append(f"SNMP ({sd})" if sd else "SNMP")
            if host.udp_services.get("mdns"):
                svcs = host.udp_services["mdns"].get("services", [])
                udp_summary.append(f"mDNS({len(svcs)})")
            if host.udp_services.get("ssdp"):
                udp_summary.append("SSDP/UPnP")
            if host.udp_services.get("netbios"):
                ns = host.udp_services["netbios"].get("names", [])
                udp_summary.append(f"NetBIOS({len(ns)})")
            if udp_summary:
                host_display += f"\n[dim cyan]UDP: {', '.join(udp_summary)}[/dim cyan]"

        row = [
            host.ip,
            host_display,
            host.mac or "-",
            host.vendor or "-",
            ports_cell or Text("-", style="dim"),
        ]
        if show_vulns:
            row.append(vulns_cell or Text("-", style="dim"))
        table.add_row(*row)
    return table


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="explotica",
        description="Network discovery & reconnaissance — for authorized use only.",
    )
    p.add_argument("target", nargs="?",
                   help="CIDR ('192.168.1.0/24'), single IP, or hostname. "
                        "Optional when using --from-json or --auto.")
    p.add_argument("--auto", action="store_true",
                   help="Auto-discover all directly-connected subnets and scan "
                        "each. Don't combine with a positional target.")
    p.add_argument("--max-hosts-per-subnet", type=int, default=4096,
                   help="Refuse to auto-scan subnets larger than this many "
                        "addresses (default: 4096 = /20).")
    p.add_argument("--list-network", action="store_true",
                   help="Just print the discovered subnets and exit — no scanning.")
    p.add_argument("-p", "--ports", default="top100",
                   help="Ports: 'top100', 'top1000', 'all', or '22,80,443' or '1-1024'")
    p.add_argument("--no-arp", action="store_true",
                   help="Skip ARP (use ICMP sweep). Use for non-LAN targets.")
    p.add_argument("--no-banners", action="store_true",
                   help="Skip banner grabbing (faster).")
    p.add_argument("--vuln-scan", action="store_true",
                   help="Match service banners against the NVD CVE database. "
                        "Adds network calls to nvd.nist.gov.")
    p.add_argument("--deep", action="store_true",
                   help="Active version probes (HTTP GET, FTP SYST, HTTPS cert, "
                        "SMB negotiate). Touches each open port. Implies more "
                        "noise on the target.")
    p.add_argument("--use-nmap", action="store_true",
                   help="Run `nmap -sV --script vuln` per host and merge findings. "
                        "Requires `nmap` on PATH. Slow but thorough.")
    p.add_argument("--auto-fallback", action="store_true",
                   help="With --vuln-scan: auto-run nmap on ports whose banner "
                        "couldn't be fingerprinted. Off by default because "
                        "nmap is slow — opt in when you want maximum coverage.")
    p.add_argument("--use-searchsploit", action="store_true",
                   help="After fingerprinting, query local Exploit-DB via "
                        "`searchsploit` for known exploits per product. "
                        "Requires `searchsploit` (apt install exploitdb).")
    p.add_argument("--rich-intel", action="store_true",
                   help="Run per-port deep intel: TLS analysis (ciphers, "
                        "cert chain, weak crypto), HTTP fingerprinting "
                        "(tech stack, paths, security headers), SMB enum.")
    p.add_argument("--epss-kev", action="store_true",
                   help="Enrich CVEs with EPSS scores (exploit prediction) "
                        "and CISA KEV catalog membership (known-exploited).")
    p.add_argument("--unmask", action="store_true",
                   help="Send protocol-specific probes to unfingerprinted "
                        "ports (JetDirect, RTSP, Redis, MongoDB, MySQL, "
                        "Postgres, SIP, IPP, Elasticsearch, etc.)")
    p.add_argument("--udp-probe", action="store_true",
                   help="Send SNMP, mDNS, SSDP, NetBIOS-NS queries to every "
                        "host. Discovers UDP-only services TCP scans miss.")
    p.add_argument("--web-crawl", action="store_true",
                   help="Crawl HTTP(S) services starting from / — extracts "
                        "links, forms, JavaScript API endpoints.")
    p.add_argument("--shodan", action="store_true",
                   help="Query free Shodan InternetDB for each public IP "
                        "(known CVEs, ports, tags, hostnames). Skips RFC1918.")
    p.add_argument("--ssh-enum", action="store_true",
                   help="Enumerate SSH algorithms via KEXINIT — KEX, host "
                        "keys, ciphers, MACs, compression. Flags weak algs.")
    p.add_argument("--dns-enum", action="store_true",
                   help="Pull DNS records (A/AAAA/MX/NS/TXT/SOA), brute "
                        "common subdomains, try AXFR, analyze SPF/DMARC.")
    p.add_argument("--full-coverage", action="store_true",
                   help="MAXIMUM COVERAGE preset. Turns on: --vuln-scan, --deep, "
                        "--use-nmap, --use-searchsploit, --aggressive. "
                        "Defaults --ports to top1000 if not set.")
    p.add_argument("--nmap-timeout", type=int, default=120,
                   help="Per-host nmap timeout in seconds (default: 120)")
    p.add_argument("--workers", type=int, default=16,
                   help="Parallel host workers (default: 16)")
    p.add_argument("--aggressive", action="store_true",
                   help="Crank parallelism: host workers 16 → 128, lower "
                        "timeouts, parallel banner/deep probes. Faster but noisier.")
    p.add_argument("--ultra", action="store_true",
                   help="Maximum speed: 256 workers, 0.15s port timeout, "
                        "0.5s banner timeout. Implies --aggressive. Use on "
                        "fast LANs where you don't mind packet loss.")
    p.add_argument("--port-timeout", type=float, default=0.4,
                   help="TCP connect timeout per port (default: 0.4s — LAN tuned)")
    p.add_argument("--banner-timeout", type=float, default=1.0,
                   help="Banner read timeout per port (default: 1.0s)")
    p.add_argument("--json", metavar="PATH",
                   help="Also write results as JSON to PATH")
    p.add_argument("--from-json", metavar="PATH",
                   help="Skip the scan; load a previous scan from JSON and "
                        "(optionally) re-run --vuln-scan / --use-nmap on it.")
    p.add_argument("--report-html", metavar="PATH",
                   help="Write a self-contained HTML report to PATH.")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"explotica {__version__}")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # --full-coverage preset: maximum vuln discovery
    if args.full_coverage:
        args.vuln_scan = True
        args.deep = True
        args.use_nmap = True
        args.use_searchsploit = True
        args.rich_intel = True
        args.epss_kev = True
        args.unmask = True
        args.udp_probe = True
        args.web_crawl = True
        args.shodan = True
        args.ssh_enum = True
        args.dns_enum = True
        args.aggressive = True
        if args.ports == "top100":  # only override the default
            args.ports = "top1000"
        console.print(
            "[bold magenta]--full-coverage:[/bold magenta] enabling "
            "--vuln-scan --deep --use-nmap --use-searchsploit --rich-intel "
            "--epss-kev --unmask --udp-probe --web-crawl --shodan "
            "--ssh-enum --dns-enum --aggressive, "
            f"--ports={args.ports}"
        )

    # --ultra implies --aggressive but cranks even harder
    if args.ultra:
        args.aggressive = True
        if args.workers <= 16:
            args.workers = 256
        args.port_timeout = 0.15
        args.banner_timeout = 0.5
        console.print(
            f"[red]--ultra:[/red] workers={args.workers}, "
            f"port_timeout={args.port_timeout}s, "
            f"banner_timeout={args.banner_timeout}s"
        )
    elif args.aggressive:
        if args.workers <= 16:
            args.workers = 128
        if args.port_timeout >= 0.4:
            args.port_timeout = 0.25
        if args.banner_timeout >= 1.0:
            args.banner_timeout = 0.7
        console.print(
            f"[yellow]--aggressive:[/yellow] workers={args.workers}, "
            f"port_timeout={args.port_timeout}s, "
            f"banner_timeout={args.banner_timeout}s"
        )

    # ── --list-network: read-only enumeration, no scanning ───────────
    if args.list_network:
        from .enumerate import list_subnets, format_summary
        net = list_subnets(max_hosts_per_subnet=args.max_hosts_per_subnet)
        console.print(format_summary(net))
        return 0

    # Validate input mode
    if not args.target and not args.from_json and not args.auto:
        console.print("[red]Need one of: positional `target`, `--from-json PATH`, "
                      "or `--auto`.[/red]")
        return 2

    # Progress: when verbose, use a streaming log style so messages don't
    # collide with INFO logs. Otherwise a single live status line.
    progress_obj = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=None),
        TimeElapsedColumn(),
        TextColumn("{task.fields[detail]}"),
        console=console,
        transient=False,
    )
    progress_task = progress_obj.add_task(
        "scanning", total=None, detail=""
    )
    progress_obj.start()

    def progress(msg: str) -> None:
        if args.verbose:
            console.print(f"  [dim]·[/dim] {msg}")
        else:
            progress_obj.update(progress_task, detail=msg)

    # ── Branch 0: --auto — enumerate then scan each subnet ────────────
    if args.auto and not args.from_json:
        from .enumerate import list_subnets, format_summary
        from .models import ScanResult
        net = list_subnets(max_hosts_per_subnet=args.max_hosts_per_subnet)
        console.print("[bold]Auto-discovered network position:[/bold]")
        console.print(format_summary(net))
        if not net.subnets:
            console.print("[red]No reachable subnets found to scan.[/red]")
            return 2

        try:
            port_list = parse_ports(args.ports)
        except ValueError as e:
            console.print(f"[red]Invalid --ports value:[/red] {e}")
            return 2

        agg_started = ScanResult.now_iso()
        import time as _time
        t0 = _time.perf_counter()
        all_hosts = []
        targets_scanned = []
        for sn in net.subnets:
            console.print(
                f"\n[bold cyan]▶ Scanning {sn.cidr}[/bold cyan] "
                f"(iface={sn.interface}, gw={sn.gateway or '-'})"
            )
            try:
                sub_result = run_scan(
                    sn.cidr,
                    use_arp=not args.no_arp,
                    ports=port_list,
                    port_timeout=args.port_timeout,
                    banner_timeout=args.banner_timeout,
                    host_workers=args.workers,
                    skip_banners=args.no_banners,
                    vuln_scan=args.vuln_scan,
                    deep=args.deep,
                    use_nmap=args.use_nmap,
                    auto_fallback=args.auto_fallback,
                    use_searchsploit=args.use_searchsploit,
                    rich_intel=args.rich_intel,
                    epss_kev=args.epss_kev,
                    unmask=args.unmask,
                    udp_probe=args.udp_probe,
                    web_crawl_enabled=args.web_crawl,
                    shodan_enabled=args.shodan,
                    ssh_enum_enabled=args.ssh_enum,
                    dns_enum_enabled=args.dns_enum,
                    nmap_timeout=args.nmap_timeout,
                    progress=progress,
                )
            except KeyboardInterrupt:
                console.print("[red]Aborted by user.[/red]")
                return 130
            except Exception as e:
                console.print(f"[yellow]  scan of {sn.cidr} failed: {e}[/yellow]")
                continue
            all_hosts.extend(sub_result.hosts)
            targets_scanned.append(sn.cidr)
            # Mark which subnet each host belongs to using hostname if empty
            # (small affordance — not perfect but helps cross-subnet reports)

        result = ScanResult(
            target="auto: " + ", ".join(targets_scanned),
            started_at=agg_started,
            finished_at=ScanResult.now_iso(),
            duration_s=round(_time.perf_counter() - t0, 2),
            hosts=all_hosts,
            scanner_version=__version__,
        )

    # ── Branch A: load from existing JSON, optionally re-enrich ──────
    elif args.from_json:
        from .models import ScanResult
        try:
            data = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
            result = ScanResult.from_dict(data)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            console.print(f"[red]Could not load {args.from_json}:[/red] {e}")
            return 2
        console.print(
            f"[bold]Loaded[/bold] {len(result.hosts)} host(s) from "
            f"[cyan]{args.from_json}[/cyan] (target was [cyan]{result.target}[/cyan])"
        )
        # Re-enrich if requested
        if (args.vuln_scan or args.deep or args.use_nmap or args.use_searchsploit
                or args.rich_intel or args.epss_kev):
            from .epss_kev import enrich_hosts_with_epss_kev
            from .nmap_wrap import enrich_host_with_nmap, nmap_available
            from .scanner import _rich_intel_host
            from .searchsploit_wrap import (enrich_host_with_exploits,
                                            searchsploit_available)
            from .service_fp import deepen_host
            from .vulnscan import enrich_host as vuln_enrich_host
            for h in result.hosts:
                if args.deep and h.ports:
                    progress(f"deep probe {h.ip}…")
                    deepen_host(h.ip, h.ports)
                if args.rich_intel and h.ports:
                    progress(f"rich intel (TLS/HTTP/SMB) {h.ip}…")
                    _rich_intel_host(h)
                if args.vuln_scan and h.ports:
                    progress(f"NVD lookup {h.ip}…")
                    vuln_enrich_host(h)
                if args.use_nmap and h.ports and nmap_available():
                    progress(f"nmap NSE {h.ip}…")
                    enrich_host_with_nmap(h.ip, h.ports, timeout=args.nmap_timeout)
                if args.use_searchsploit and h.ports and searchsploit_available():
                    progress(f"searchsploit {h.ip}…")
                    enrich_host_with_exploits(h)
            if args.epss_kev:
                progress("EPSS+KEV CVE prioritization…")
                try:
                    enrich_hosts_with_epss_kev(result.hosts)
                except Exception as e:
                    log.warning("EPSS/KEV enrichment failed: %s", e)
    # ── Branch B: live scan ───────────────────────────────────────────
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError as e:
            console.print(f"[red]Invalid --ports value:[/red] {e}")
            return 2

        console.print(
            f"[bold]Explotica[/bold] scanning [cyan]{args.target}[/cyan] "
            f"({len(ports)} port(s), workers={args.workers})"
        )

        try:
            result = run_scan(
                args.target,
                use_arp=not args.no_arp,
                ports=ports,
                port_timeout=args.port_timeout,
                banner_timeout=args.banner_timeout,
                host_workers=args.workers,
                skip_banners=args.no_banners,
                vuln_scan=args.vuln_scan,
                deep=args.deep,
                use_nmap=args.use_nmap,
                auto_fallback=args.auto_fallback,
                use_searchsploit=args.use_searchsploit,
                rich_intel=args.rich_intel,
                epss_kev=args.epss_kev,
                unmask=args.unmask,
                udp_probe=args.udp_probe,
                web_crawl_enabled=args.web_crawl,
                shodan_enabled=args.shodan,
                ssh_enum_enabled=args.ssh_enum,
                dns_enum_enabled=args.dns_enum,
                nmap_timeout=args.nmap_timeout,
                progress=progress,
            )
        except NotImplementedError as e:
            console.print(f"[yellow]Orchestrator not implemented yet:[/yellow] {e}")
            return 3
        except KeyboardInterrupt:
            console.print("[red]Aborted by user.[/red]")
            return 130
        except PermissionError as e:
            console.print(f"[red]Permission denied:[/red] {e}\n"
                          "On Windows, ARP needs Administrator + Npcap installed.")
            return 1

    # Stop the progress bar before printing the final table so they don't
    # collide on the same TTY rows.
    try:
        progress_obj.stop()
    except Exception:
        pass

    show_vulns = (args.vuln_scan or args.use_nmap or args.deep
                  or args.auto_fallback or args.use_searchsploit
                  or args.rich_intel or args.epss_kev
                  or args.unmask or args.udp_probe
                  or args.web_crawl or args.shodan or args.ssh_enum
                  or args.dns_enum)
    console.print(render_result(result, show_vulns=show_vulns))

    if show_vulns:
        # CVE severity summary + coverage report
        sev_counts: dict[str, int] = {}
        total_open = 0
        fingerprinted = 0
        ports_with_cve = 0
        for h in result.hosts:
            for p in h.ports:
                total_open += 1
                if p.product_name:
                    fingerprinted += 1
                if p.cves:
                    ports_with_cve += 1
                for c in p.cves:
                    sev_counts[c.severity] = sev_counts.get(c.severity, 0) + 1

        # Coverage line — shows what fraction of open ports got identified
        unfp = total_open - fingerprinted
        cov_color = "green" if fingerprinted >= total_open * 0.5 else "yellow"
        console.print(
            f"[bold]Coverage:[/bold] "
            f"[{cov_color}]{fingerprinted}/{total_open}[/{cov_color}] port(s) "
            f"fingerprinted, {ports_with_cve} with CVE matches"
            + (f", {unfp} unfingerprinted" if unfp else "")
        )

        if sev_counts:
            parts = []
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev_counts.get(sev):
                    parts.append(f"[{_SEVERITY_STYLE[sev]}]"
                                 f"{sev_counts[sev]} {sev}[/]")
            console.print("[bold]CVE summary:[/bold] " + ", ".join(parts))

            # Priority: KEV-listed + high-EPSS
            kev_count = sum(1 for h in result.hosts for p in h.ports
                            for c in p.cves if c.in_kev)
            high_epss = sum(1 for h in result.hosts for p in h.ports
                            for c in p.cves
                            if c.epss_score is not None and c.epss_score >= 0.5)
            if kev_count or high_epss:
                console.print(
                    f"[bold]Prioritize:[/bold] "
                    f"[bold red]{kev_count}[/bold red] KEV-listed "
                    f"(actively exploited), "
                    f"[yellow]{high_epss}[/yellow] high-EPSS (>=0.5 exploitation likelihood)"
                )

    # Phase 12 summary lines
    if args.shodan:
        shodan_hits = sum(1 for h in result.hosts
                          if h.udp_services and h.udp_services.get("shodan"))
        if shodan_hits:
            console.print(
                f"[bold]Shodan InternetDB:[/bold] {shodan_hits} public host(s) "
                f"with cached data"
            )

    if result.dns_info:
        di = result.dns_info
        rec_count = sum(len(v) for v in di.get("records", {}).values())
        console.print(
            f"[bold]DNS:[/bold] {len(di.get('records', {}))} record type(s) "
            f"({rec_count} answers), "
            f"{len(di.get('subdomains_found', []))} subdomain(s) found"
        )
        if di.get("axfr_attempts"):
            console.print("[bold red]⚠ AXFR succeeded on:[/bold red] "
                          + ", ".join(a["ns"] for a in di["axfr_attempts"]))
        else:
            console.print(
                "[dim]No CVEs matched. Try [bold]--deep[/bold] for active "
                "version probes, or [bold]--use-nmap[/bold] for nmap NSE "
                "vuln scripts. Also check `-v` output for banner patterns "
                "we couldn't parse.[/dim]"
            )

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]✓[/green] JSON written to [cyan]{out}[/cyan]")

    if args.report_html:
        from .report import write_report
        out = write_report(result, args.report_html)
        console.print(f"[green]✓[/green] HTML report at [cyan]{out}[/cyan]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
