"""CLI entry point — pretty terminal output via rich, JSON export via --json."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from . import __version__
from .models import ScanResult
from .ports import TOP_100_PORTS
from .scanner import run_scan

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


def render_result(result: ScanResult) -> Table:
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

    for host in sorted(result.hosts, key=lambda h: tuple(int(o) for o in h.ip.split("."))):
        ports_cell = Text()
        for p in host.ports:
            label = f"{p.number}"
            if p.service:
                label += f"/{p.service}"
            ports_cell.append(label + " ", style="bold green")
            if p.banner:
                ports_cell.append(f"({p.banner[:60]})\n", style="dim")
            else:
                ports_cell.append("\n")
        table.add_row(
            host.ip,
            host.hostname or "-",
            host.mac or "-",
            host.vendor or "-",
            ports_cell or Text("-", style="dim"),
        )
    return table


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="explotica",
        description="Network discovery & reconnaissance — for authorized use only.",
    )
    p.add_argument("target",
                   help="CIDR ('192.168.1.0/24'), single IP, or hostname")
    p.add_argument("-p", "--ports", default="top100",
                   help="Ports: 'top100', 'top1000', 'all', or '22,80,443' or '1-1024'")
    p.add_argument("--no-arp", action="store_true",
                   help="Skip ARP (use ICMP sweep). Use for non-LAN targets.")
    p.add_argument("--no-banners", action="store_true",
                   help="Skip banner grabbing (faster).")
    p.add_argument("--workers", type=int, default=16,
                   help="Parallel host workers (default: 16)")
    p.add_argument("--port-timeout", type=float, default=0.8)
    p.add_argument("--banner-timeout", type=float, default=1.5)
    p.add_argument("--json", metavar="PATH",
                   help="Also write results as JSON to PATH")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"explotica {__version__}")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        console.print(f"[red]Invalid --ports value:[/red] {e}")
        return 2

    console.print(
        f"[bold]Explotica[/bold] scanning [cyan]{args.target}[/cyan] "
        f"({len(ports)} port(s), workers={args.workers})"
    )

    status_line = ""

    def progress(msg: str) -> None:
        nonlocal status_line
        status_line = msg
        console.print(f"  [dim]·[/dim] {msg}")

    try:
        result = run_scan(
            args.target,
            use_arp=not args.no_arp,
            ports=ports,
            port_timeout=args.port_timeout,
            banner_timeout=args.banner_timeout,
            host_workers=args.workers,
            skip_banners=args.no_banners,
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

    console.print(render_result(result))

    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]✓[/green] JSON written to [cyan]{out}[/cyan]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
