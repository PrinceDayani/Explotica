"""Network spider — recursive subnet discovery.

The web crawler follows hyperlinks. The network spider follows ROUTES.

Algorithm:
  1. Scan the seed subnet (e.g. 192.168.1.0/24)
  2. For each discovered router/gateway:
       a. SNMP-walk ipCidrRouteTable (public/private community)
       b. Pull traceroute hops if available
       c. Extract next-hop subnets
  3. For each newly-discovered subnet that's reachable from us:
       Queue it for scanning
  4. Recurse with depth limit (default 2 hops away)
  5. Build a topology graph: subnets ─ routers ─ subnets

Returns a discovered topology dict that can be fed back into run_scan for
each subnet, or rendered as a graph in the dashboard.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import subprocess
from typing import Optional

log = logging.getLogger(__name__)


# ── SNMP route table extraction ──────────────────────────────────────────
def snmp_walk_routes(host: str, community: str = "public",
                      timeout: float = 4.0) -> list[dict]:
    """Walk SNMP ipCidrRouteTable (OID 1.3.6.1.2.1.4.24.4.1) for route entries.

    Returns list of {dest, mask, next_hop, type, metric} dicts.
    Hand-rolled BER walk — no pysnmp dep.
    """
    # We use a single GetNextRequest per round-trip. For simplicity, we'll
    # try the broader ipRouteTable (OID 1.3.6.1.2.1.4.21) which is the
    # standard route table on most devices.

    # First, try a simpler approach: use snmpwalk binary if available
    routes = _snmpwalk_via_shell(host, community, timeout)
    if routes:
        return routes

    # Fall back to single SNMP query for sysDescr to confirm SNMP works,
    # but actual route extraction requires multi-PDU walk we don't implement
    from .udp_probes import probe_snmp
    r = probe_snmp(host, community=community, timeout=timeout)
    if r:
        return [{"note": "SNMP responsive but multi-PDU walk not implemented",
                  "sysDescr": r.get("sysDescr", "")[:120],
                  "community": community}]
    return []


def _snmpwalk_via_shell(host: str, community: str,
                          timeout: float = 6.0) -> list[dict]:
    """Use the `snmpwalk` binary (net-snmp) if installed."""
    import shutil
    if not shutil.which("snmpwalk"):
        return []
    try:
        out = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, "-t", "2", "-r", "1",
             host, "1.3.6.1.2.1.4.21"],  # ipRouteTable
            capture_output=True, text=True, timeout=timeout
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    if out.returncode != 0:
        return []
    routes_raw: dict[str, dict] = {}
    for line in out.stdout.splitlines():
        # Example: IP-MIB::ipRouteDest.10.0.0.0 = IpAddress: 10.0.0.0
        parts = line.split("=")
        if len(parts) != 2:
            continue
        key = parts[0].strip()
        val = parts[1].strip()
        # Extract destination IP from the OID suffix
        if ".ipRouteDest." in key or "ipRouteDest" in key:
            dest_key = key.rsplit(".", 4)[-4:] if "." in key else []
            if val.startswith("IpAddress:"):
                dest = val.split(":", 1)[1].strip()
                routes_raw.setdefault(dest, {})["dest"] = dest
        elif ".ipRouteMask." in key:
            ip_in_key = key.rsplit("ipRouteMask.", 1)[-1].strip()
            if val.startswith("IpAddress:"):
                routes_raw.setdefault(ip_in_key, {})["mask"] = val.split(":", 1)[1].strip()
        elif ".ipRouteNextHop." in key:
            ip_in_key = key.rsplit("ipRouteNextHop.", 1)[-1].strip()
            if val.startswith("IpAddress:"):
                routes_raw.setdefault(ip_in_key, {})["next_hop"] = val.split(":", 1)[1].strip()
    return [r for r in routes_raw.values() if r.get("dest")]


# ── Traceroute-based hop discovery ───────────────────────────────────────
def traceroute_discover(seed_ip: str, max_hops: int = 12,
                         timeout: float = 1.5) -> list[str]:
    """Run traceroute to discover intermediate router IPs."""
    from .netfabric import traceroute_to
    try:
        hops = traceroute_to(seed_ip, max_hops=max_hops, timeout=timeout)
        return [h["ip"] for h in (hops or []) if h.get("ip")]
    except Exception as e:
        log.debug("traceroute spider failed: %s", e)
        return []


# ── Subnet inference ─────────────────────────────────────────────────────
def _ip_to_implied_subnet(ip: str, prefix: int = 24) -> str:
    """Guess a /24 (or other prefix) containing this IP."""
    try:
        addr = ipaddress.IPv4Address(ip)
        # Mask to the /prefix
        network = ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False)
        return str(network)
    except (ValueError, ipaddress.AddressValueError):
        return ""


def _reachable(ip: str, timeout: float = 1.5) -> bool:
    """Check if a host is reachable via single ICMP echo (using scapy)."""
    try:
        from .discovery import quick_ttl
        return quick_ttl(ip, timeout=timeout) is not None
    except Exception:
        return False


# ── Spider orchestrator ──────────────────────────────────────────────────
def spider(seed_target: str, *,
            max_depth: int = 2,
            communities: Optional[list[str]] = None,
            timeout: float = 4.0,
            progress=None) -> dict:
    """Recursively discover networks reachable from the seed target.

    Returns a topology dict:
      {
        "subnets": [list of CIDR strings discovered],
        "routers": [list of router IPs discovered],
        "edges": [(router_ip, subnet_cidr) pairs],
        "depth_reached": int,
      }
    """
    communities = communities or ["public", "private", "community"]
    discovered_subnets: set[str] = set()
    discovered_routers: set[str] = set()
    edges: list[tuple[str, str]] = []
    queue: list[tuple[str, int]] = [(seed_target, 0)]
    visited: set[str] = set()
    max_depth_reached = 0

    while queue:
        current, depth = queue.pop(0)
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        max_depth_reached = max(max_depth_reached, depth)
        discovered_subnets.add(current)

        if progress:
            progress(f"spider: scanning {current} (depth {depth})")

        # Quick scan to find live hosts in this subnet
        from .discovery import arp_scan, expand_targets, icmp_sweep
        try:
            live_hosts = arp_scan(current, timeout=2.0)
        except Exception:
            live_hosts = []
        if not live_hosts:
            try:
                ips = expand_targets(current)
                live_hosts = icmp_sweep(ips[:256], timeout=1.0)
            except Exception:
                live_hosts = []

        if not live_hosts:
            continue

        # Identify likely routers: gateways from this subnet (usually .1 or .254)
        try:
            net = ipaddress.IPv4Network(current, strict=False)
            gateway_candidates = [str(net.network_address + 1),
                                   str(net.broadcast_address - 1)]
        except (ValueError, ipaddress.AddressValueError):
            gateway_candidates = []

        for h in live_hosts:
            if h.ip in gateway_candidates:
                discovered_routers.add(h.ip)

        # For each router, SNMP-walk for routes
        for router_ip in list(discovered_routers):
            if depth >= max_depth:
                continue
            for community in communities:
                if progress:
                    progress(f"spider: SNMP walk {router_ip} ({community})")
                routes = snmp_walk_routes(router_ip, community=community,
                                            timeout=timeout)
                if not routes:
                    continue
                for r in routes:
                    dest = r.get("dest", "")
                    mask = r.get("mask", "")
                    if not dest:
                        continue
                    # Skip obviously non-useful routes
                    if dest in ("0.0.0.0", "127.0.0.0", "255.255.255.255"):
                        continue
                    if dest.startswith("224.") or dest.startswith("169.254."):
                        continue
                    try:
                        if mask:
                            net = ipaddress.IPv4Network(f"{dest}/{mask}",
                                                          strict=False)
                        else:
                            # Imply /24 if mask missing
                            net = ipaddress.IPv4Network(f"{dest}/24",
                                                          strict=False)
                    except (ValueError, ipaddress.AddressValueError):
                        continue
                    if net.is_loopback or net.is_multicast:
                        continue
                    cidr = str(net)
                    if cidr in discovered_subnets:
                        continue
                    edges.append((router_ip, cidr))
                    if not _reachable_subnet(net):
                        log.debug("spider: %s not reachable, skipping", cidr)
                        continue
                    log.info("spider: discovered new subnet %s via %s",
                             cidr, router_ip)
                    queue.append((cidr, depth + 1))
                break  # found a working community, stop trying others

    return {
        "seed": seed_target,
        "subnets": sorted(discovered_subnets),
        "routers": sorted(discovered_routers),
        "edges": [{"router": r, "subnet": s} for r, s in edges],
        "depth_reached": max_depth_reached,
        "subnet_count": len(discovered_subnets),
        "router_count": len(discovered_routers),
    }


def _reachable_subnet(network: ipaddress.IPv4Network) -> bool:
    """Test if any host in the subnet responds to a quick ping."""
    # Probe gateway position first
    candidates = []
    try:
        candidates.append(str(network.network_address + 1))
        candidates.append(str(network.broadcast_address - 1))
    except Exception:
        pass
    for ip in candidates:
        if _reachable(ip, timeout=1.0):
            return True
    return False
