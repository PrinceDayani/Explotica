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
from .banners import grab_banner, grab_banner_full
from .discovery import arp_scan, expand_targets, icmp_sweep, resolve_hostname
from .models import Host, Port, ScanResult
from .aio import run_async_scan
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
from .service_fp_db import match_response as fpdb_match
from .smb_scan import scan_smb
from .ssh_enum import enum_ssh
from .syn_scan import syn_scan, syn_scan_available
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

    TTL: only probed when we don't already have one AND we don't have a MAC.
    ARP-discovered hosts (have MAC) are on the local broadcast domain — running
    redundant ICMP echoes against all of them causes scapy MAC-resolution
    races and noisy warnings under high concurrency.
    """
    host.hostname = resolve_hostname(host.ip, timeout=0.3)
    host.vendor = oui_lookup(host.mac)
    # Skip ICMP TTL probe when we already have an ARP-derived MAC; we know
    # this host is local. (TTL would just confirm "Linux/Windows" which we
    # often get from OUI vendor + open-port fingerprints anyway.)
    if host.ttl is None and not host.mac:
        from .discovery import quick_ttl
        ttl = quick_ttl(host.ip, timeout=0.5)
        if ttl is not None:
            host.ttl = ttl
    if host.ttl is not None and host.os_hint is None:
        from .os_fingerprint import guess_os_from_ttl
        host.os_hint = guess_os_from_ttl(host.ttl)
    return host


# Phase 57: removed local _HTTP_PORTS / _HTTPS_PORTS hardcoded sets.
# Use port_classifier.is_http/is_https from the unified module instead.


def _service_intel_host(host: Host) -> None:
    """Run service_probes_v2 probes for ports we know how to deep-probe.
    Phase 56: only open ports — closed/filtered would just timeout."""
    if not host.ports:
        return
    for p in host.open_ports():
        if p.number not in SERVICE_PROBES:
            continue
        try:
            info = probe_service(host.ip, p.number)
            if info:
                p.service_intel = info
        except Exception as e:
            log.debug("service_intel %s:%d failed: %s", host.ip, p.number, e)


def _http_audit_host(host: Host) -> None:
    """Run http_audit (methods/CORS/GraphQL/WP) for each HTTP-ish port.
    Phase 57: dispatch via port_classifier (content + port hints unified)."""
    if not host.ports:
        return
    from .port_classifier import is_http_like, is_https
    for p in host.open_ports():
        if not is_http_like(p):
            continue
        tls = is_https(p)
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
    """Enumerate SSH algorithms on any port serving SSH.
    Phase 56: only open ports. SSH-detection-by-content (works for non-22)."""
    for p in host.open_ports():
        # SSH usually runs on 22 but can be anywhere; detect from banner or
        # from the content-based service identifier set by banners.py.
        if (p.number == 22 or p.service == "ssh"
                or (p.banner and p.banner.startswith(("SSH-", "deep: SSH-")))):
            try:
                info = enum_ssh(host.ip, p.number)
                if info:
                    p.ssh_info = info
            except Exception as e:
                log.debug("ssh_enum %s:%d failed: %s", host.ip, p.number, e)


def _web_crawl_host(host: Host) -> None:
    """Crawl every HTTP/HTTPS port on this host. Phase 57: dispatch via the
    unified port_classifier — handles content-based 'http' service identification
    so non-standard ports also get crawled."""
    from .port_classifier import is_http_like, is_https
    for p in host.open_ports():
        if not is_http_like(p):
            continue
        try:
            info = web_crawl(host.ip, p.number,
                              tls=is_https(p),
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
    # Phase 56: only unmask OPEN ports (probing closed/filtered is wasted RTT)
    candidates = [p for p in host.open_ports()
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
    open_ps = host.open_ports()
    if not open_ps:
        return

    # Phase 57: dispatch via unified port_classifier — handles content-based
    # identification, so HTTPS on port 31337 still gets the right enrichment.
    from .port_classifier import is_https, is_http, is_smb

    def enrich_port(p: Port) -> None:
        try:
            if is_https(p):
                tls = scan_tls(host.ip, p.number, timeout=3.0)
                if tls:
                    p.tls_info = tls
                http = scan_http(host.ip, p.number, tls=True, timeout=3.0)
                if http:
                    p.http_info = http
                    if http.get("tech_stack"):
                        p.tech_stack = http["tech_stack"]
            elif is_http(p):
                http = scan_http(host.ip, p.number, tls=False, timeout=3.0)
                if http:
                    p.http_info = http
                    if http.get("tech_stack"):
                        p.tech_stack = http["tech_stack"]
            elif is_smb(p):
                smb = scan_smb(host.ip, p.number, timeout=3.0)
                if smb:
                    p.smb_info = smb
        except Exception as e:
            log.debug("rich-intel %s:%d failed: %s", host.ip, p.number, e)

    with ThreadPoolExecutor(max_workers=min(8, len(open_ps))) as pool:
        list(pool.map(enrich_port, open_ps))


def _scan_host_ports(host: Host, ports: list[int], port_timeout: float,
                      *, include_closed: bool = True,
                      include_filtered: bool = True) -> Host:
    """State-aware port scan for one host. Mutates host in place.

    Phase 56: emits open + closed + filtered by default. Caller controls
    state filtering via include_* kwargs.
    """
    host.ports = scan_ports(host.ip, ports=ports, timeout=port_timeout,
                             include_closed=include_closed,
                             include_filtered=include_filtered)
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

    # Phase 56: only grab banners on OPEN ports — closed/filtered ports have
    # nothing to say. The state-aware scanner now emits all 3 states; we filter
    # here so we don't waste banner_timeout seconds per closed port.
    targets = [p for p in host.ports
               if p.state == "open" and p.number not in _BANNER_SKIP]
    if not targets:
        # Still apply IANA hints on open ports with no banner attempt
        from .ports import apply_iana_guess
        for p in host.ports:
            if p.state == "open":
                apply_iana_guess(p)
        return host

    def grab(p: Port) -> None:
        try:
            banner, service, product, version, probes = grab_banner_full(
                host.ip, p.number, timeout=banner_timeout
            )
            p.banner = banner
            # Phase 56: content-based service identification — overrides any
            # earlier port-number guess. Set ONLY when we have evidence.
            if service:
                p.service = service
                p.iana_guess = False
            if product and not p.product_name:
                p.product_name = product
            if version and not p.product_version:
                p.product_version = version
            if probes:
                p.probes_attempted = probes
        except Exception as e:
            log.debug("banner %s:%d failed: %s", host.ip, p.number, e)

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        list(pool.map(grab, targets))

    # Phase 56: after banner+fingerprint, tag any open ports that STILL have
    # no service as IANA guesses. This way the JSON is never empty, but the
    # iana_guess flag makes clear that it's just a polite hint.
    from .ports import apply_iana_guess
    for p in host.ports:
        if p.state == "open":
            apply_iana_guess(p)
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
    async_io: bool = False,
    syn_scan_enabled: bool = False,
    # Phase 35: passive-analysis modules (safe to auto-enable)
    honeypot_check: bool = False,
    web_security_check: bool = False,
    ics_check: bool = False,
    prioritize_scores: bool = False,
    # Phase 35: active opt-in modules
    check_default_creds: bool = False,
    check_takeover: bool = False,
    check_cloud: bool = False,
    cloud_keyword: Optional[str] = None,
    ad_enum_domain: Optional[str] = None,
    asrep_roast: bool = False,
    smtp_audit: bool = False,
    # Phase 36-38
    os_fp_db: bool = False,
    verify_cve_probes: bool = False,
    credentialed_scan_enabled: bool = False,
    ssh_credentials: Optional[dict] = None,
    # Phase 39-42
    winrm_credentialed: bool = False,
    winrm_credentials: Optional[dict] = None,
    compliance_frameworks: Optional[list[str]] = None,
    verify_cves_v2: bool = False,
    web_fuzz_enabled: bool = False,
    sqli_time_based: bool = False,
    nmap_timeout: int = 180,
    # Phase 56: state filtering — defaults emit all 3 states
    include_closed: bool = True,
    include_filtered: bool = True,
    # Phase 61: new module wiring
    db_fingerprint_enabled: bool = False,   # MySQL/MSSQL/PG/Mongo/Redis/etc.
    db_credentials: Optional[dict] = None,  # per-product creds OR VaultProfile
    snmp_inventory_enabled: bool = False,   # SNMP credentialed software inv
    snmp_creds: Optional[dict] = None,      # community / v3_*
    web_appscan_enabled: bool = False,      # OWASP-class scan
    web_appscan_login: Optional[dict] = None,
    container_scan_enabled: bool = False,
    kube_token: Optional[str] = None,
    subdomain_enum_enabled: bool = False,   # for domain targets
    subdomain_wordlist: Optional[list[str]] = None,
    # Phase 63: production safety
    checkpoint_path: Optional[str] = None,   # write partial JSON every N hosts
    checkpoint_every_n: int = 10,
    progress: ProgressCb = None,
) -> ScanResult:
    """Run a full scan and return a ScanResult.

    Concurrency model: each host's enrich → port-scan → banner pipeline runs
    sequentially within one worker thread; multiple hosts run in parallel.
    Tunable via host_workers.
    """
    # Phase 63: extra_findings declared up front so checkpoint mid-scan
    # captures the same mutable reference that downstream code populates.
    extra_findings: dict = {}
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

    # ── Phase 2-pre: stateless SYN scan (when --syn-scan and we can) ────
    syn_results: dict[str, list[int]] = {}
    if syn_scan_enabled and hosts and ports:
        # Phase 63: safe-mode gates SYN scan (raw sockets are IDS-visible)
        from .safety import safe_to_run as _gate
        if not _gate("syn_scan"):
            log.info("syn_scan skipped (safe-mode)")
            syn_scan_enabled = False
    if syn_scan_enabled and hosts and ports:
        if syn_scan_available():
            if progress:
                progress(f"stateless SYN scan: {len(hosts)} hosts × {len(ports)} ports…")
            try:
                syn_results = syn_scan(
                    [h.ip for h in hosts], ports,
                    timeout=4.0,
                    rate_pps=5000 if host_workers >= 128 else 2000,
                    retries=1,
                )
                if syn_results:
                    # Phase 57: SYN scan only tells us "open or not".
                    # No service identification here — that comes from the
                    # banner-grab pass later. We do NOT stamp an IANA-guess
                    # service at scan time; that would defeat Phase 56's
                    # iana_guess honesty contract.
                    from .models import Port
                    for h in hosts:
                        open_ports = syn_results.get(h.ip, [])
                        h.ports = [
                            Port(
                                number=p,
                                protocol="tcp",
                                state="open",
                                state_reason="SYN-ACK received",
                            )
                            for p in open_ports
                        ]
                    if progress:
                        total = sum(len(h.ports) for h in hosts)
                        progress(f"SYN scan found {total} open port(s)")
            except Exception as e:
                log.warning("SYN scan failed (%s) — falling back to TCP connect", e)
                syn_results = {}
        else:
            log.warning("--syn-scan requested but raw sockets unavailable "
                        "(need root + scapy). Falling back to TCP connect.")

    # ── Phase 2a: async I/O port + banner pre-pass (when --async-io) ─────
    # Single event loop scans ALL hosts × ALL ports + banners in one go.
    # The thread-based per-host pipeline below then skips port_scan +
    # banner_grab when this populated the data.
    # Phase 57: aio.run_async_scan now returns list[Port] (state-aware),
    # not list[int]. The result tuple is (probed_ports, banners_by_number).
    async_results: dict[str, tuple[list[Port], dict[int, str]]] = {}
    if async_io and hosts and ports:
        if progress:
            progress(f"async I/O: {len(hosts)} hosts × {len(ports)} ports in "
                     "one event loop…")
        try:
            ports_to_use = ports
            async_results = run_async_scan(
                [h.ip for h in hosts], ports_to_use,
                use_uvloop=True,
                port_timeout=port_timeout,
                banner_timeout=banner_timeout if not skip_banners else 0,
                grab_banners=not skip_banners,
                host_concurrency=min(host_workers * 2, 64),
                port_concurrency=2000 if host_workers >= 128 else 1000,
            )
            # Phase 57: merge async-discovered ports with SYN results. The
            # async scan now returns full Port objects with state, banner,
            # state_reason — no need to re-stamp port→service guesses here.
            from .banners import _identify_protocol
            for h in hosts:
                probed_ports, banner_map = async_results.get(h.ip, ([], {}))
                by_num: dict[int, Port] = {p.number: p for p in probed_ports}
                # Union with SYN-found open ports (in case async missed some)
                if syn_results:
                    for sp in syn_results.get(h.ip, []):
                        if sp not in by_num:
                            by_num[sp] = Port(
                                number=sp, protocol="tcp", state="open",
                                state_reason="SYN-ACK (no TCP-connect confirm)",
                            )
                # Apply banner content classification where available
                for num, port in by_num.items():
                    b = banner_map.get(num)
                    if b:
                        port.banner = b
                        # Best-effort content-based service identification
                        try:
                            svc, prod, ver = _identify_protocol(b.encode("utf-8",
                                                                          "ignore"))
                            if svc:
                                port.service = svc
                                port.iana_guess = False
                            if prod and not port.product_name:
                                port.product_name = prod
                            if ver and not port.product_version:
                                port.product_version = ver
                        except Exception:
                            pass
                h.ports = sorted(by_num.values(), key=lambda p: p.number)
            if progress:
                total_open = sum(len(h.ports) for h in hosts)
                progress(f"async I/O complete: {total_open} open port(s) across "
                         f"{len(hosts)} host(s)")
        except Exception as e:
            log.warning("async I/O failed (%s) — falling back to thread-based", e)
            async_results = {}

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

    # When async_io OR syn_scan ran, ports are already populated.
    async_populated = bool(async_results) or bool(syn_results)

    def pipeline(h: Host) -> Host:
        """Per-host pipeline. Discovery + ports + banners are sequential
        (downstream phases need the data). Enrichment phases that are
        INDEPENDENT of each other run in parallel via a sub-pool.

        Nmap runs ONCE for all hosts after this loop (post-pipeline phase).
        """
        try:
            # ── Sequential prelude (each step depends on the previous) ──
            _enrich(h)
            if not async_populated:
                _scan_host_ports(h, ports or [], port_timeout,
                                 include_closed=include_closed,
                                 include_filtered=include_filtered)
                if not skip_banners and h.ports:
                    _grab_host_banners(h, banner_timeout, workers=16)
            if deep and h.ports:
                deepen_host(h.ip, h.ports, workers=8)

            # ── Parallel enrichment phases (independent of each other) ──
            # Note: http_audit reads p.crawl_info, so it must run AFTER
            # web_crawl. We split into two waves:
            #   Wave A: everything except http_audit
            #   Wave B: http_audit (only after wave A completes)
            if h.ports:
                wave_a: list = []
                if unmask:
                    wave_a.append(("unmask", lambda: _unmask_host(h)))
                if udp_probe:
                    wave_a.append(("udp", lambda: _udp_probe_host(h)))
                if rich_intel:
                    wave_a.append(("rich_intel", lambda: _rich_intel_host(h)))
                if ssh_enum_enabled:
                    wave_a.append(("ssh_enum", lambda: _ssh_enum_host(h)))
                if web_crawl_enabled:
                    wave_a.append(("web_crawl", lambda: _web_crawl_host(h)))
                if service_intel_enabled:
                    wave_a.append(("service_intel",
                                    lambda: _service_intel_host(h)))
                if wave_a:
                    with ThreadPoolExecutor(
                        max_workers=min(8, len(wave_a))
                    ) as sub_pool:
                        futs = [sub_pool.submit(fn) for _, fn in wave_a]
                        for i, f in enumerate(futs):
                            try:
                                f.result()
                            except Exception as e:
                                log.debug("wave-A %s %s failed: %s",
                                          wave_a[i][0], h.ip, e)
                # Wave B: http_audit — now has crawl_info available
                if http_audit_enabled:
                    try:
                        _http_audit_host(h)
                    except Exception as e:
                        log.debug("http_audit %s failed: %s", h.ip, e)

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

    # Phase 63: checkpoint + shutdown integration
    from .checkpoint import Checkpoint
    from .shutdown import get_token as _get_shutdown
    _shutdown = _get_shutdown()
    _checkpoint = Checkpoint(checkpoint_path,
                               every_n_hosts=checkpoint_every_n)

    completed = 0
    with ThreadPoolExecutor(max_workers=host_workers) as pool:
        futures = {pool.submit(pipeline, h): h for h in hosts}
        for f in as_completed(futures):
            completed += 1
            try:
                h = f.result()
            except Exception as e:
                # Phase 63: per-host failure shouldn't kill the whole scan
                log.warning("pipeline error on host: %s", e)
                continue
            if progress:
                progress(
                    f"[{completed}/{len(hosts)}] {h.ip} "
                    f"— {len(h.ports)} open port(s)"
                )
            # Phase 63: checkpoint partial scan every N hosts
            if _checkpoint.enabled:
                _checkpoint.update({
                    "target": target,
                    "started_at": started_iso,
                    "in_progress": True,
                    "hosts_completed": completed,
                    "hosts_total": len(hosts),
                    "hosts": [h.to_dict() for h in hosts],
                    "extra_findings": extra_findings,
                })
            # Phase 63: respect graceful shutdown — stop spawning new work
            if _shutdown.is_set():
                log.warning("shutdown requested mid-scan — finishing batch")
                break

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
            # Phase 56: only nmap-probe OPEN ports (closed/filtered would waste time)
            ufp = [p.number for p in h.open_ports() if not p.product_name]
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

    # ── Phase 10: Extra-finding modules (Phase 35) ──────────────────────
    # Phase 63: extra_findings is declared up at the top of run_scan so the
    # checkpoint inside the per-host loop captures the same dict reference.

    if ics_check and hosts:
        if progress:
            progress("ICS protocol probes (Modbus/BACnet/DNP3/S7/EthIP)…")
        try:
            from .ics import probe_ics_host
            ics_results = {}
            for h in hosts:
                open_ps = h.open_ports()
                if not open_ps:
                    continue
                r = probe_ics_host(h.ip, [p.number for p in open_ps])
                if r:
                    ics_results[h.ip] = r
            if ics_results:
                extra_findings["ics"] = ics_results
        except Exception as e:
            log.warning("ICS check failed: %s", e)

    if web_security_check and hosts:
        if progress:
            progress("Web security analysis (JWT/CSP/cookies)…")
        try:
            from .web_security import analyze_response
            ws_results: dict = {}
            for h in hosts:
                host_ws: list = []
                from .port_classifier import is_https
                for p in h.open_ports():
                    if not p.http_info:
                        continue
                    headers = p.http_info.get("headers", {})
                    ws_result = analyze_response(headers, b"",
                                                  url_was_https=is_https(p))
                    if ws_result.get("issue_count"):
                        host_ws.append({"port": p.number, **ws_result})
                if host_ws:
                    ws_results[h.ip] = host_ws
            if ws_results:
                extra_findings["web_security"] = ws_results
        except Exception as e:
            log.warning("web security check failed: %s", e)

    if check_default_creds and hosts:
        # Phase 63: respect safe-mode (this is a LOCKOUT-RISK check)
        from .safety import safe_to_run as _gate
        if not _gate("default_creds"):
            log.info("default_creds skipped (safe-mode)")
        else:
            if progress:
                progress("Default credential checks…")
            try:
                from .default_creds import check_host_defaults
                dc_results: dict = {}
                for h in hosts:
                    # Phase 56: default-cred check should only target OPEN ports
                    ports = [p.number for p in h.open_ports()]
                    if ports:
                        found = check_host_defaults(h.ip, ports)
                        if found:
                            dc_results[h.ip] = found
                if dc_results:
                    extra_findings["default_creds"] = dc_results
            except Exception as e:
                log.warning("default_creds failed: %s", e)

    if smtp_audit and hosts:
        if progress:
            progress("SMTP audits (open relay + VRFY/EXPN)…")
        try:
            from .smtp_test import audit_smtp
            smtp_results: dict = {}
            for h in hosts:
                for p in h.ports:
                    if p.number in (25, 587, 465):
                        r = audit_smtp(h.ip, p.number)
                        if r:
                            smtp_results.setdefault(h.ip, {})[p.number] = r
            if smtp_results:
                extra_findings["smtp_audit"] = smtp_results
        except Exception as e:
            log.warning("smtp_audit failed: %s", e)

    if check_takeover and dns_info:
        if progress:
            progress("Subdomain takeover detection…")
        try:
            from .takeover import check_subdomains
            subdomains = [s["name"] for s in dns_info.get("subdomains_found", [])]
            if subdomains:
                takeovers = check_subdomains(subdomains)
                if takeovers:
                    extra_findings["takeover"] = takeovers
        except Exception as e:
            log.warning("takeover check failed: %s", e)

    if check_cloud and cloud_keyword:
        if progress:
            progress(f"Cloud asset discovery for '{cloud_keyword}'…")
        try:
            from .cloud_assets import discover_cloud_assets
            cloud = discover_cloud_assets(cloud_keyword)
            if cloud:
                extra_findings["cloud_assets"] = cloud
        except Exception as e:
            log.warning("cloud asset discovery failed: %s", e)

    if ad_enum_domain:
        if progress:
            progress(f"AD enumeration for {ad_enum_domain}…")
        try:
            from .ad_enum import run_ad_enum
            extra_findings["ad_enum"] = run_ad_enum(ad_enum_domain)
        except Exception as e:
            log.warning("AD enum failed: %s", e)

    if asrep_roast and ad_enum_domain:
        # Phase 63: safe-mode gates Kerberos roasting (generates failed
        # authentication logs in AD)
        from .safety import safe_to_run as _gate
        if not _gate("asrep_roast"):
            log.info("asrep_roast skipped (safe-mode)")
        else:
            if progress:
                progress(f"AS-REP roasting for {ad_enum_domain}…")
            try:
                from .kerberoast import run_roast
                extra_findings["asrep_roast"] = run_roast(ad_enum_domain)
            except Exception as e:
                log.warning("AS-REP roast failed: %s", e)

    if honeypot_check and hosts:
        if progress:
            progress("Honeypot detection (Cowrie/Kippo/Dionaea/Conpot)…")
        try:
            from .honeypot import detect_honeypot_in_scan
            scan_dict = {"hosts": [h.to_dict() for h in hosts]}
            hp = detect_honeypot_in_scan(scan_dict)
            if hp:
                extra_findings["honeypot_indicators"] = hp
        except Exception as e:
            log.warning("honeypot detection failed: %s", e)

    if os_fp_db and hosts:
        if progress:
            progress("Multi-signal OS fingerprinting…")
        try:
            from .os_fp_db import fingerprint_scan
            scan_dict = {"hosts": [h.to_dict() for h in hosts]}
            extra_findings["os_fingerprints"] = fingerprint_scan(scan_dict)
        except Exception as e:
            log.warning("OS fingerprint failed: %s", e)

    if verify_cve_probes and hosts:
        if progress:
            progress("Verification probes (Heartbleed/MS17-010/Shellshock/BlueKeep/Log4Shell…)")
        try:
            from .verify_probes import verify_scan
            scan_dict = {"hosts": [h.to_dict() for h in hosts]}
            verify_results = verify_scan(scan_dict)
            if verify_results:
                extra_findings["verified_cves"] = verify_results
        except Exception as e:
            log.warning("verify probes failed: %s", e)

    if credentialed_scan_enabled and ssh_credentials and hosts:
        if progress:
            progress(f"Credentialed SSH scan ({ssh_credentials.get('username','root')}@…)")
        try:
            from .creds_scan import credentialed_scan_hosts
            creds_results = credentialed_scan_hosts(hosts, ssh_credentials)
            if creds_results:
                extra_findings["credentialed"] = creds_results
        except Exception as e:
            log.warning("credentialed scan failed: %s", e)

    if winrm_credentialed and winrm_credentials and hosts:
        if progress:
            progress("Credentialed WinRM scan (Windows hosts)…")
        try:
            from .winrm_scan import winrm_scan_hosts
            winrm_results = winrm_scan_hosts(hosts, winrm_credentials)
            if winrm_results:
                extra_findings["winrm_credentialed"] = winrm_results
        except Exception as e:
            log.warning("WinRM scan failed: %s", e)

    if verify_cves_v2 and hosts:
        if progress:
            progress("Extended verification probes (Citrix/Confluence/Spring4Shell/MOVEit/F5/…)")
        try:
            from .verify_probes_v2 import verify_scan_v2
            scan_dict = {"hosts": [h.to_dict() for h in hosts]}
            v2_results = verify_scan_v2(scan_dict)
            if v2_results:
                extra_findings["verified_cves_v2"] = v2_results
        except Exception as e:
            log.warning("v2 verify probes failed: %s", e)

    # ── Phase 61 wiring: db_fingerprint / snmp_inventory / web_appscan /
    # container_scan / subdomain_enum — all gated on their respective flags.
    if db_fingerprint_enabled and hosts:
        if progress:
            progress("Deep database fingerprinting (MySQL/PG/MSSQL/Mongo/Redis/ES/...)")
        try:
            from .db_fingerprint import (fingerprint_host_databases,
                                            cve_lookup_for_databases)
            db_results: dict[str, dict] = {}
            for h in hosts:
                r = fingerprint_host_databases(
                    h.ip, h.ports, db_credentials=db_credentials
                )
                if r:
                    db_results[h.ip] = r
                    # Look up CVEs for fingerprinted DBs and attach to ports
                    cve_lookup_for_databases(h.ip, h.ports, r)
            if db_results:
                extra_findings["db_fingerprint"] = db_results
        except Exception as e:
            log.warning("db_fingerprint failed: %s", e)

    if snmp_inventory_enabled and hosts:
        if progress:
            progress("SNMP credentialed inventory (hrSWInstalled walk)…")
        try:
            from .snmp_inventory import snmp_inventory_hosts
            creds = snmp_creds or {"version": "2c", "community": "public"}
            snmp_results = snmp_inventory_hosts(hosts, creds)
            if snmp_results:
                extra_findings["snmp_inventory"] = snmp_results
        except Exception as e:
            log.warning("snmp_inventory failed: %s", e)

    if web_appscan_enabled and hosts:
        # Phase 63: web app fuzzing can trip WAFs / fill logs / lock accounts
        from .safety import safe_to_run as _gate
        if not _gate("web_appscan"):
            log.info("web_appscan skipped (safe-mode)")
        else:
            if progress:
                progress("OWASP-class web app scanner (form fuzz + API discovery)…")
            try:
                from .web_appscan import scan_hosts_webapps
                wa_results = scan_hosts_webapps(
                    hosts, include_time_based=sqli_time_based
                )
                if wa_results:
                    extra_findings["web_appscan"] = wa_results
            except Exception as e:
                log.warning("web_appscan failed: %s", e)

    if container_scan_enabled and hosts:
        if progress:
            progress("Container + K8s scanning (Docker daemon, CIS audit, Trivy)…")
        try:
            from .container_scan import scan_hosts_containers
            cont_results = scan_hosts_containers(
                hosts, kube_token=kube_token, run_trivy=True
            )
            if cont_results:
                extra_findings["container_scan"] = cont_results
        except Exception as e:
            log.warning("container_scan failed: %s", e)

    if subdomain_enum_enabled and hosts:
        # Only meaningful when target was a domain
        if "." in target and "/" not in target and progress:
            progress("Subdomain enumeration + takeover scan…")
        try:
            from .subdomain_extended import enumerate_subdomains
            if "." in target and "/" not in target:
                sub_results = enumerate_subdomains(
                    target, wordlist=subdomain_wordlist,
                    include_permutations=True
                )
                if sub_results:
                    extra_findings["subdomain_enum"] = sub_results
        except Exception as e:
            log.warning("subdomain_enum failed: %s", e)

    # Phase 61: combined-risk scoring once EPSS/KEV are populated
    if epss_kev and hosts:
        try:
            from .epss_kev import summarize_epss_kev_for_hosts
            extra_findings["risk_summary"] = summarize_epss_kev_for_hosts(hosts)
        except Exception as e:
            log.debug("risk summary failed: %s", e)

    if web_fuzz_enabled and hosts:
        # Phase 63: web fuzz sends injection payloads that may trip WAFs
        from .safety import safe_to_run as _gate
        if not _gate("web_fuzz"):
            log.info("web_fuzz skipped (safe-mode)")
            web_fuzz_enabled = False
    if web_fuzz_enabled and hosts:
        if progress:
            progress("Active web fuzzing (SQLi/XSS/path-traversal/SSRF/CRLF)…")
        try:
            from .web_fuzz import fuzz_scan
            scan_dict = {"hosts": [h.to_dict() for h in hosts]}
            fuzz_results = fuzz_scan(scan_dict, include_sqli_time=sqli_time_based)
            if fuzz_results:
                extra_findings["web_fuzz"] = fuzz_results
        except Exception as e:
            log.warning("web fuzzing failed: %s", e)

    if prioritize_scores and hosts:
        if progress:
            progress("Computing prioritization scores…")
        try:
            from .prioritize import score_scan_result
            scan_dict = {"hosts": [h.to_dict() for h in hosts]}
            extra_findings["prioritization"] = score_scan_result(scan_dict)
        except Exception as e:
            log.warning("prioritization failed: %s", e)

    if compliance_frameworks and hosts:
        if progress:
            progress(f"Compliance check: {', '.join(compliance_frameworks)}…")
        try:
            from .compliance import evaluate, ALL_FRAMEWORKS
            scan_dict = {
                "hosts": [h.to_dict() for h in hosts],
                "extra_findings": extra_findings,
            }
            comp: dict = {}
            for fw in compliance_frameworks:
                if fw.lower() in ALL_FRAMEWORKS:
                    comp[fw] = evaluate(scan_dict, framework=fw)
            if comp:
                extra_findings["compliance"] = comp
        except Exception as e:
            log.warning("compliance check failed: %s", e)

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
        extra_findings=extra_findings or None,
    )
