"""Scan orchestrator — wires discovery + enrichment + ports + banners together.

This is the brain of the tool. The individual primitives (discovery.py,
ports.py, banners.py, oui.py) are deliberately dumb and single-purpose; this
module decides ORDER, CONCURRENCY, and ERROR HANDLING.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from . import __version__
from .banners import grab_banner
from .discovery import arp_scan, expand_targets, icmp_sweep, resolve_hostname
from .models import Host, Port, ScanResult
from .oui import lookup as oui_lookup
from .ports import TOP_100_PORTS, scan_ports

log = logging.getLogger(__name__)

ProgressCb = Optional[Callable[[str], None]]


# ────────────────────────────────────────────────────────────────────────────
# Helpers — small, single-purpose. Use these in `run_scan` below.
# ────────────────────────────────────────────────────────────────────────────

def _discover(target: str, use_arp: bool, timeout: float,
              progress: ProgressCb) -> list[Host]:
    """Discover live hosts. Tries ARP first if requested, else ICMP sweep."""
    if progress:
        progress(f"Discovering hosts in {target}…")
    if use_arp:
        try:
            return arp_scan(target, timeout=timeout)
        except Exception as e:
            log.warning("ARP failed (%s); falling back to ICMP", e)
    ips = expand_targets(target)
    return icmp_sweep(ips, timeout=timeout)


def _enrich(host: Host) -> Host:
    """Cheap enrichment — hostname (reverse DNS) + MAC vendor lookup."""
    host.hostname = resolve_hostname(host.ip)
    host.vendor = oui_lookup(host.mac)
    return host


def _scan_host_ports(host: Host, ports: list[int], port_timeout: float) -> Host:
    """Open-port scan for one host. Mutates host in place."""
    host.ports = scan_ports(host.ip, ports=ports, timeout=port_timeout)
    return host


def _grab_host_banners(host: Host, banner_timeout: float) -> Host:
    """For each open port on host, attempt a banner. Mutates port objects."""
    for p in host.ports:
        try:
            p.banner = grab_banner(host.ip, p.number, timeout=banner_timeout)
        except Exception as e:
            log.debug("banner %s:%d failed: %s", host.ip, p.number, e)
    return host


# ────────────────────────────────────────────────────────────────────────────
# THE ORCHESTRATOR — YOU WRITE THIS.
#
# Read the helpers above. They are your building blocks. Compose them.
#
# Requirements:
#   1. Run discovery first (use _discover).
#   2. For each live host, do: enrich → port-scan → banner-grab.
#   3. Decide: do hosts in parallel? (recommended) If yes, what max_workers?
#   4. Call `progress(...)` with short status strings so the CLI can show them.
#   5. Build and return a ScanResult with started_at/finished_at/duration_s set.
#
# Tradeoffs to consider:
#   - Too many host-level threads → router drops packets, false negatives.
#   - Banner grab is the slowest. You COULD skip banners on hosts with >N ports.
#   - You can do enrich + port-scan concurrently per host (they don't overlap),
#     but the simpler "sequential per host, parallel across hosts" is fine.
#
# Suggested signature is below — fill the body.
# ────────────────────────────────────────────────────────────────────────────

def run_scan(
    target: str,
    *,
    use_arp: bool = True,
    ports: list[int] | None = None,
    discover_timeout: float = 2.0,
    port_timeout: float = 0.8,
    banner_timeout: float = 1.5,
    host_workers: int = 16,
    skip_banners: bool = False,
    progress: ProgressCb = None,
) -> ScanResult:
    """Run a full scan and return a ScanResult.

    Concurrency model: each host's enrich → port-scan → banner pipeline runs
    sequentially within one worker thread; multiple hosts run in parallel.
    Tunable via host_workers.
    """
    started_iso = ScanResult.now_iso()
    t0 = time.perf_counter()

    # ── Phase 1: discovery ──────────────────────────────────────────────
    hosts = _discover(target, use_arp, discover_timeout, progress)
    if progress:
        progress(f"Found {len(hosts)} live host(s); enriching…")

    if not hosts:
        return ScanResult(
            target=target,
            started_at=started_iso,
            finished_at=ScanResult.now_iso(),
            duration_s=round(time.perf_counter() - t0, 2),
            hosts=[],
            scanner_version=__version__,
        )

    # ── Phase 2: per-host pipeline (parallel across hosts) ──────────────
    def pipeline(h: Host) -> Host:
        try:
            _enrich(h)
            _scan_host_ports(h, ports or [], port_timeout)
            if not skip_banners and h.ports:
                _grab_host_banners(h, banner_timeout)
        except Exception as e:  # one bad host shouldn't kill the scan
            log.warning("pipeline failed for %s: %s", h.ip, e)
        return h

    completed = 0
    with ThreadPoolExecutor(max_workers=host_workers) as pool:
        futures = {pool.submit(pipeline, h): h for h in hosts}
        for f in as_completed(futures):
            completed += 1
            h = f.result()
            if progress:
                progress(
                    f"[{completed}/{len(hosts)}] {h.ip} "
                    f"— {len(h.ports)} open port(s)"
                )

    return ScanResult(
        target=target,
        started_at=started_iso,
        finished_at=ScanResult.now_iso(),
        duration_s=round(time.perf_counter() - t0, 2),
        hosts=hosts,
        scanner_version=__version__,
    )
