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
from .dns_enum import enum_dns
from .epss_kev import enrich_hosts_with_epss_kev
from .http_audit import audit_http
from .http_scan import scan_http
from .netfabric import dhcp_discover, traceroute_many
from .nmap_wrap import (enrich_host_with_nmap, enrich_hosts_with_nmap,
                         nmap_available)
from .osint import run_osint
from .protocol_probes import unmask_port, unmask_ports
from .searchsploit_wrap import (enrich_host_with_exploits,
                                searchsploit_available)
from .service_probes_v2 import (probe_service, probe_udp_ntp,
                                 SERVICE_PROBES)
from .shodan_lite import enrich_hosts_with_shodan
from .smb_scan import scan_smb
from .ssh_enum import enum_ssh
from .tls_scan import scan_tls
from .udp_probes import probe_all_udp
from .web_crawler import crawl as web_crawl
from .oui import lookup as oui_lookup
from .ports import TOP_100_PORTS, scan_ports
from .service_fp import deepen_host
from .vulnscan import enrich_host as vuln_enrich_host

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
    """Cheap enrichment — hostname (reverse DNS) + MAC vendor lookup + TTL hint.

    Reverse-DNS gets a short timeout (0.3s) because most consumer devices
    don't register reverse DNS and the lookup just wastes wall-clock time.

    TTL is captured during ICMP discovery already (host.ttl). For ARP-discovered
    hosts we do ONE quick ICMP echo here to fill it in (skip if already set).
    """
    host.hostname = resolve_hostname(host.ip, timeout=0.3)
    host.vendor = oui_lookup(host.mac)
    # If TTL wasn't captured during discovery (ARP path), grab it quickly.
    if host.ttl is None:
        from .discovery import quick_ttl
        ttl = quick_ttl(host.ip, timeout=0.5)
        if ttl is not None:
            host.ttl = ttl
    if host.ttl is not None and host.os_hint is None:
        from .os_fingerprint import guess_os_from_ttl
        host.os_hint = guess_os_from_ttl(host.ttl)
    return host


_HTTP_PORTS = frozenset({80, 81, 88, 591, 800, 1080, 3000, 4000, 4080, 5000,
                          5050, 7001, 8000, 8008, 8080, 8081, 8088, 8888,
                          9000, 9090})
_HTTPS_PORTS = frozenset({443, 4443, 8443, 9443})


def _service_intel_host(host: Host) -> None:
    """Run service_probes_v2 probes for ports we know how to deep-probe."""
    if not host.ports:
        return
    for p in host.ports:
        if p.number not in SERVICE_PROBES:
            continue
        try:
            info = probe_service(host.ip, p.number)
            if info:
                p.service_intel = info
        except Exception as e:
            log.debug("service_intel %s:%d failed: %s", host.ip, p.number, e)


_HTTP_AUDIT_PORTS = frozenset({80, 81, 88, 800, 3000, 5000, 7001, 8000,
                                8008, 8080, 8081, 8888, 9000, 9090,
                                443, 4443, 8443, 9443})


def _http_audit_host(host: Host) -> None:
    """Run http_audit (methods/CORS/GraphQL/WP) for each HTTP-ish port."""
    if not host.ports:
        return
    for p in host.ports:
        if p.number not in _HTTP_AUDIT_PORTS:
            continue
        tls = p.number in (443, 4443, 8443, 9443)
        # Pull crawled paths if web crawler ran
        crawled = []
        if p.crawl_info and p.crawl_info.get("pages_crawled"):
            crawled = [
                urllib_split_path(pg["url"])
                for pg in p.crawl_info["pages_crawled"]
            ]
        try:
            audit = audit_http(host.ip, p.number, tls=tls,
                                crawled_paths=crawled or None)
            if audit:
                p.http_audit_info = audit
        except Exception as e:
            log.debug("http_audit %s:%d failed: %s", host.ip, p.number, e)


def urllib_split_path(url: str) -> str:
    """Extract just the path component from a URL."""
    from urllib.parse import urlparse
    try:
        return urlparse(url).path or "/"
    except Exception:
        return "/"


def _ssh_enum_host(host: Host) -> None:
    """Enumerate SSH algorithms on any port serving SSH."""
    for p in host.ports:
        # SSH usually runs on 22 but can be anywhere; detect from banner
        if p.number == 22 or (p.banner and p.banner.startswith(("SSH-", "deep: SSH-"))):
            try:
                info = enum_ssh(host.ip, p.number)
                if info:
                    p.ssh_info = info
            except Exception as e:
                log.debug("ssh_enum %s:%d failed: %s", host.ip, p.number, e)


_HTTP_LIKE_PORTS = frozenset({80, 81, 88, 591, 800, 1080, 3000, 4000, 4080,
                               5000, 5050, 7001, 8000, 8008, 8080, 8081,
                               8088, 8888, 9000, 9090, 443, 4443, 8443, 9443})
_HTTPS_PORTS_CRAWL = frozenset({443, 4443, 8443, 9443})


def _web_crawl_host(host: Host) -> None:
    """Crawl every HTTP/HTTPS port on this host."""
    for p in host.ports:
        if p.number not in _HTTP_LIKE_PORTS:
            continue
        try:
            info = web_crawl(host.ip, p.number,
                              tls=(p.number in _HTTPS_PORTS_CRAWL),
                              max_pages=15, depth=1, timeout=4.0)
            if info and info.get("total_pages"):
                p.crawl_info = info
        except Exception as e:
            log.debug("crawl %s:%d failed: %s", host.ip, p.number, e)


def _unmask_host(host: Host) -> None:
    """Run protocol-specific probes on this host's UNFINGERPRINTED ports.

    Fills in port.banner + product fields when a probe identifies the service.
    Parallel across this host's unfingerprinted ports.
    """
    if not host.ports:
        return
    probe_ports = unmask_ports()
    candidates = [p for p in host.ports
                  if p.number in probe_ports and not p.product_name]
    if not candidates:
        return

    def probe_one(p: Port) -> None:
        result = unmask_port(host.ip, p.number)
        if not result:
            return
        banner_str, vendor, product, version = result
        # Append to banner (preserve any existing data)
        p.banner = (f"{p.banner} || unmask: {banner_str}"
                    if p.banner else f"unmask: {banner_str}")[:512]
        if vendor and not p.product_vendor:
            p.product_vendor = vendor
        if product and not p.product_name:
            p.product_name = product
        if version and not p.product_version:
            p.product_version = version

    with ThreadPoolExecutor(max_workers=min(8, len(candidates))) as pool:
        list(pool.map(probe_one, candidates))


def _udp_probe_host(host: Host) -> None:
    """Run SNMP/mDNS/SSDP/NetBIOS UDP probes; attach result to host.udp_services."""
    try:
        results = probe_all_udp(host.ip, timeout=2.0)
        if results:
            host.udp_services = results
    except Exception as e:
        log.debug("udp probes on %s failed: %s", host.ip, e)


def _rich_intel_host(host: Host) -> None:
    """Run TLS / HTTP / SMB deep scans on this host's open ports.

    Per-port enrichment happens in parallel within the host. Each port's
    result lands on the Port object (tls_info / http_info / smb_info /
    tech_stack).
    """
    if not host.ports:
        return

    def enrich_port(p: Port) -> None:
        try:
            if p.number in _HTTPS_PORTS:
                tls = scan_tls(host.ip, p.number, timeout=3.0)
                if tls:
                    p.tls_info = tls
                http = scan_http(host.ip, p.number, tls=True, timeout=3.0)
                if http:
                    p.http_info = http
                    if http.get("tech_stack"):
                        p.tech_stack = http["tech_stack"]
            elif p.number in _HTTP_PORTS:
                http = scan_http(host.ip, p.number, tls=False, timeout=3.0)
                if http:
                    p.http_info = http
                    if http.get("tech_stack"):
                        p.tech_stack = http["tech_stack"]
            elif p.number == 445:
                smb = scan_smb(host.ip, p.number, timeout=3.0)
                if smb:
                    p.smb_info = smb
        except Exception as e:
            log.debug("rich-intel %s:%d failed: %s", host.ip, p.number, e)

    with ThreadPoolExecutor(max_workers=min(8, len(host.ports))) as pool:
        list(pool.map(enrich_port, host.ports))


def _scan_host_ports(host: Host, ports: list[int], port_timeout: float) -> Host:
    """Open-port scan for one host. Mutates host in place."""
    host.ports = scan_ports(host.ip, ports=ports, timeout=port_timeout)
    return host


# Ports that NEVER yield text banners (binary protocols). Skipping these
# saves up to `banner_timeout` per port. We use --deep for these instead.
_BANNER_SKIP = frozenset({
    135,    # MSRPC — binary
    137,    # NetBIOS name service (UDP, won't connect)
    139,    # NetBIOS session — binary
    445,    # SMB — binary, --deep has its own probe
    593,    # RPC over HTTP — binary
    1434,   # SQL Server browser (UDP)
    1900,   # SSDP (UDP usually)
    5353,   # mDNS (UDP)
    5985,   # WinRM HTTP — won't speak unprompted
    49152,  # MS dynamic RPC
    49153, 49154, 49155, 49156, 49157,
})


def _grab_host_banners(host: Host, banner_timeout: float,
                       workers: int = 16) -> Host:
    """For each open port on host, attempt a banner IN PARALLEL.

    Skips ports in _BANNER_SKIP (known binary protocols where a banner
    attempt just wastes `banner_timeout` seconds).
    """
    if not host.ports:
        return host

    targets = [p for p in host.ports if p.number not in _BANNER_SKIP]
    if not targets:
        return host

    def grab(p: Port) -> None:
        try:
            p.banner = grab_banner(host.ip, p.number, timeout=banner_timeout)
        except Exception as e:
            log.debug("banner %s:%d failed: %s", host.ip, p.number, e)

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        list(pool.map(grab, targets))
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
    port_timeout: float = 0.4,
    banner_timeout: float = 1.0,
    host_workers: int = 16,
    skip_banners: bool = False,
    vuln_scan: bool = False,
    deep: bool = False,
    use_nmap: bool = False,
    auto_fallback: bool = False,
    use_searchsploit: bool = False,
    rich_intel: bool = False,
    epss_kev: bool = False,
    unmask: bool = False,
    udp_probe: bool = False,
    web_crawl_enabled: bool = False,
    shodan_enabled: bool = False,
    ssh_enum_enabled: bool = False,
    dns_enum_enabled: bool = False,
    service_intel_enabled: bool = False,
    http_audit_enabled: bool = False,
    osint_enabled: bool = False,
    netfabric_enabled: bool = False,
    nmap_timeout: int = 180,
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
    if use_nmap and not nmap_available():
        log.warning("--use-nmap requested but `nmap` binary not on PATH; skipping.")
        use_nmap = False

    # Auto-fallback is OPT-IN now (--auto-fallback flag). When enabled,
    # ports without a parsed product/version get handed to nmap NSE. Disabled
    # by default because nmap is slow and a /24 can spawn 60+ nmap processes.
    auto_nmap_fallback = (
        auto_fallback and vuln_scan and nmap_available() and not use_nmap
    )

    def pipeline(h: Host) -> Host:
        """Per-host pipeline. Discovery + ports + banners are sequential
        (downstream phases need the data). Enrichment phases that are
        INDEPENDENT of each other run in parallel via a sub-pool.

        Nmap runs ONCE for all hosts after this loop (post-pipeline phase).
        """
        try:
            # ── Sequential prelude (each step depends on the previous) ──
            _enrich(h)
            _scan_host_ports(h, ports or [], port_timeout)
            if not skip_banners and h.ports:
                _grab_host_banners(h, banner_timeout, workers=16)
            if deep and h.ports:
                deepen_host(h.ip, h.ports, workers=8)

            # ── Parallel enrichment phases (independent of each other) ──
            if h.ports:
                enrichment_tasks: list = []
                if unmask:
                    enrichment_tasks.append(("unmask",
                                              lambda: _unmask_host(h)))
                if udp_probe:
                    enrichment_tasks.append(("udp", lambda: _udp_probe_host(h)))
                if rich_intel:
                    enrichment_tasks.append(("rich_intel",
                                              lambda: _rich_intel_host(h)))
                if ssh_enum_enabled:
                    enrichment_tasks.append(("ssh_enum",
                                              lambda: _ssh_enum_host(h)))
                if web_crawl_enabled:
                    enrichment_tasks.append(("web_crawl",
                                              lambda: _web_crawl_host(h)))
                if service_intel_enabled:
                    enrichment_tasks.append(("service_intel",
                                              lambda: _service_intel_host(h)))
                if http_audit_enabled:
                    enrichment_tasks.append(("http_audit",
                                              lambda: _http_audit_host(h)))
                if enrichment_tasks:
                    with ThreadPoolExecutor(
                        max_workers=min(8, len(enrichment_tasks))
                    ) as sub_pool:
                        futs = [sub_pool.submit(fn) for _, fn in enrichment_tasks]
                        for i, f in enumerate(futs):
                            try:
                                f.result()
                            except Exception as e:
                                log.debug("enrichment %s %s failed: %s",
                                          enrichment_tasks[i][0], h.ip, e)

            # ── Vuln scan runs AFTER enrichment (needs fingerprints) ────
            if vuln_scan and h.ports:
                vuln_enrich_host(h)
        except Exception as e:  # one bad host shouldn't kill the scan
            log.warning("pipeline failed for %s: %s", h.ip, e)
        return h

    # Check searchsploit availability once
    if use_searchsploit and not searchsploit_available():
        log.warning("--use-searchsploit requested but `searchsploit` not "
                    "on PATH; skipping. (Install: apt install exploitdb)")
        use_searchsploit = False

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

    # ── Phase 3: ONE-SHOT nmap (after all hosts done) ───────────────────
    # Either --use-nmap (run on ALL open ports) or --auto-fallback (run on
    # ports without a fingerprinted product). Either way, ONE nmap invocation.
    if use_nmap and hosts:
        if progress:
            progress(f"nmap one-shot on {len([h for h in hosts if h.ports])} host(s)…")
        enrich_hosts_with_nmap(hosts, timeout=nmap_timeout)
    elif auto_nmap_fallback and hosts:
        # Build per-host port list of just the unfingerprinted ports
        per_host: dict[str, list[int]] = {}
        for h in hosts:
            ufp = [p.number for p in h.ports if not p.product_name]
            if ufp:
                per_host[h.ip] = ufp
        if per_host:
            if progress:
                total_ports = sum(len(v) for v in per_host.values())
                progress(
                    f"nmap fallback one-shot: {len(per_host)} host(s), "
                    f"{total_ports} unfingerprinted port(s)…"
                )
            # Pass only hosts with unfingerprinted ports
            fallback_hosts = [h for h in hosts if h.ip in per_host]
            enrich_hosts_with_nmap(
                fallback_hosts, ports_per_host=per_host, timeout=nmap_timeout
            )

    # ── Phase 4: searchsploit (after nmap so we have richest fingerprints) ─
    if use_searchsploit and hosts:
        if progress:
            num_fp_ports = sum(1 for h in hosts for p in h.ports if p.product_name)
            progress(f"searchsploit lookup for {num_fp_ports} fingerprinted port(s)…")
        with ThreadPoolExecutor(max_workers=min(host_workers, 16)) as pool:
            futs = [pool.submit(enrich_host_with_exploits, h) for h in hosts]
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception as e:
                    log.debug("searchsploit host enrich error: %s", e)

    # ── Phase 5: EPSS + KEV CVE prioritization ──────────────────────────
    if epss_kev and hosts:
        total_cves = sum(len(p.cves) for h in hosts for p in h.ports)
        if total_cves:
            if progress:
                progress(f"EPSS+KEV enrichment for {total_cves} CVE(s)…")
            try:
                enrich_hosts_with_epss_kev(hosts)
            except Exception as e:
                log.warning("EPSS/KEV enrichment failed: %s", e)

    # ── Phase 6: Shodan InternetDB (public IPs only) ────────────────────
    if shodan_enabled and hosts:
        if progress:
            progress(f"Shodan InternetDB lookup for {len(hosts)} host(s)…")
        try:
            enrich_hosts_with_shodan(hosts)
        except Exception as e:
            log.warning("Shodan enrichment failed: %s", e)

    # ── Phase 7: DNS enumeration (target-level, when target is a domain) ─
    dns_info = None
    if dns_enum_enabled:
        # Only run DNS enum if the original target looks like a domain
        is_domain = bool(target and target.replace(".", "").replace("-", "").isalnum()
                          is False) and not any(c.isdigit() for c in target.split(".")[0])
        # Simpler heuristic: contains a letter and no slashes
        is_domain = any(c.isalpha() for c in target) and "/" not in target
        if is_domain:
            if progress:
                progress(f"DNS enumeration for {target}…")
            try:
                dns_info = enum_dns(target, brute_subdomains=True)
            except Exception as e:
                log.warning("DNS enum failed: %s", e)

    # ── Phase 8: OSINT layer (target-level) ──────────────────────────────
    osint_info = None
    if osint_enabled:
        if progress:
            progress("OSINT lookup (crt.sh + ASN + RDAP)…")
        try:
            osint_info = run_osint(target, hosts)
        except Exception as e:
            log.warning("OSINT failed: %s", e)

    # ── Phase 9: Network fabric (DHCP + traceroute) ─────────────────────
    netfabric_info = None
    if netfabric_enabled:
        netfabric_info = {}
        if progress:
            progress("DHCP discover…")
        try:
            dhcp = dhcp_discover()
            if dhcp:
                netfabric_info["dhcp"] = dhcp
        except Exception as e:
            log.warning("DHCP discover failed: %s", e)
        # Traceroute to first few hosts (cap to keep scan time bounded)
        trace_targets = [h.ip for h in hosts if h.ports][:5]
        if trace_targets:
            if progress:
                progress(f"traceroute to {len(trace_targets)} host(s)…")
            try:
                netfabric_info["traceroute"] = traceroute_many(trace_targets)
            except Exception as e:
                log.warning("traceroute failed: %s", e)
        if not netfabric_info:
            netfabric_info = None

    return ScanResult(
        target=target,
        started_at=started_iso,
        finished_at=ScanResult.now_iso(),
        duration_s=round(time.perf_counter() - t0, 2),
        hosts=hosts,
        scanner_version=__version__,
        dns_info=dns_info,
        osint_info=osint_info,
        netfabric_info=netfabric_info,
    )
