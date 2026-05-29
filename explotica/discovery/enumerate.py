"""Network enumeration — discover what's reachable from this host.

Phase 5a (this module):
  - List local interfaces with IP / netmask / gateway
  - Identify default gateway(s)
  - Derive the set of directly-connected subnets to scan

SNMP route walk lives in discovery/network_spider.py (Phase 46).
Traceroute lives in discovery/netfabric.py (Phase 13d).
mDNS sniff is not yet implemented.

Cross-platform via scapy's `conf.route` (the same kernel routing table the
OS uses for forwarding decisions). No psutil/netifaces dependency.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class Subnet:
    cidr: str                       # e.g. "192.168.1.0/24"
    interface: Optional[str] = None # e.g. "eth0", "Wi-Fi"
    local_ip: Optional[str] = None  # our IP on this subnet
    gateway: Optional[str] = None   # default gateway for this subnet, if any
    num_hosts: int = 0              # number of host addresses in the range

    def to_dict(self) -> dict:
        return {
            "cidr": self.cidr,
            "interface": self.interface,
            "local_ip": self.local_ip,
            "gateway": self.gateway,
            "num_hosts": self.num_hosts,
        }


@dataclass
class LocalNetwork:
    """Snapshot of everything we know about the host's network position."""
    subnets: list[Subnet] = field(default_factory=list)
    default_gateways: list[str] = field(default_factory=list)
    hostname: str = ""

    def to_dict(self) -> dict:
        return {
            "subnets": [s.to_dict() for s in self.subnets],
            "default_gateways": self.default_gateways,
            "hostname": self.hostname,
        }


# ── Internal helpers ──────────────────────────────────────────────────────


def _import_scapy_conf():
    """Lazy-import scapy.conf — heavy, and not all callers need it."""
    try:
        from scapy.config import conf as scapy_conf
        return scapy_conf
    except ImportError as e:
        raise RuntimeError(
            "scapy is required for enumeration. pip install -r requirements.txt"
        ) from e


def _int_to_ip(n: int) -> str:
    """scapy routes store IPs as 32-bit ints — convert back to dotted-quad."""
    try:
        return socket.inet_ntoa(n.to_bytes(4, "big"))
    except (OverflowError, OSError):
        return "0.0.0.0"


def _mask_to_prefix(mask_int: int) -> int:
    """4-octet netmask integer → CIDR prefix (count of leading 1 bits)."""
    if mask_int == 0:
        return 0
    # Convert to binary string and count contiguous leading 1s.
    binstr = bin(mask_int)[2:].zfill(32)
    return len(binstr) - len(binstr.lstrip("1"))


def _is_useful_subnet(cidr: ipaddress.IPv4Network) -> bool:
    """Filter out routing entries we never want to scan."""
    if cidr.is_loopback:
        return False
    if cidr.is_link_local:
        return False
    if cidr.is_multicast:
        return False
    if cidr.is_unspecified:
        return False
    # Reject the default route (0.0.0.0/0) and host routes (/32)
    if cidr.prefixlen == 0 or cidr.prefixlen == 32:
        return False
    return True


# ── Public API ────────────────────────────────────────────────────────────


def _route_entries_from_scapy(conf) -> list:
    """Get route table from scapy, reinitializing if needed."""
    # On some setups (especially when scapy logging was suppressed before
    # init), conf.route is None or empty. Try to force a re-read.
    if conf.route is None or not getattr(conf.route, "routes", None):
        try:
            from scapy.route import Route
            conf.route = Route()
        except Exception as e:
            log.warning("scapy Route() init failed: %s", e)
            return []
    return getattr(conf.route, "routes", []) or []


def _route_entries_from_shell() -> list:
    """Fallback: parse `ip route` (Linux) or `route print` (Windows) for routes.

    Returns list of tuples: (network_int, netmask_int, gateway_str, iface,
    output_ip, metric) to match scapy's format.

    Phase 66: cross-platform — Linux first, Windows fallback added.
    """
    import os as _os
    if _os.name == "nt":
        return _route_entries_windows()
    return _route_entries_linux()


def _route_entries_linux() -> list:
    """Linux: parse `ip -4 route` output."""
    import subprocess
    try:
        out = subprocess.run(["ip", "-4", "route"], capture_output=True,
                              text=True, timeout=4)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if out.returncode != 0:
        return []
    routes = []
    for line in out.stdout.splitlines():
        # Examples:
        #   default via 192.168.1.1 dev eth0 ...
        #   192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.42
        parts = line.split()
        if not parts:
            continue
        dest = parts[0]
        gw = "0.0.0.0"
        iface = ""
        out_ip = ""
        for i, tok in enumerate(parts):
            if tok == "via" and i + 1 < len(parts):
                gw = parts[i + 1]
            elif tok == "dev" and i + 1 < len(parts):
                iface = parts[i + 1]
            elif tok == "src" and i + 1 < len(parts):
                out_ip = parts[i + 1]
        try:
            if dest == "default":
                net = ipaddress.IPv4Network("0.0.0.0/0", strict=False)
            else:
                net = ipaddress.IPv4Network(dest, strict=False)
        except (ValueError, ipaddress.AddressValueError):
            continue
        net_int = int(net.network_address)
        mask_int = int(net.netmask)
        routes.append((net_int, mask_int, gw, iface, out_ip, 0))
    return routes


def _route_entries_windows() -> list:
    """Windows: parse `route print -4` output for IPv4 routes.

    Format under "IPv4 Route Table":
        Network Destination    Netmask          Gateway       Interface  Metric
        0.0.0.0                0.0.0.0          192.168.1.1   192.168.1.5    25
    """
    import subprocess
    try:
        out = subprocess.run(["route", "print", "-4"],
                              capture_output=True, text=True, timeout=6)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if out.returncode != 0:
        return []
    routes = []
    in_active_section = False
    for line in out.stdout.splitlines():
        stripped = line.strip()
        # Section detection
        if "Active Routes" in stripped:
            in_active_section = True
            continue
        if "Persistent Routes" in stripped or "===" in stripped:
            in_active_section = False
            continue
        if not in_active_section or not stripped:
            continue
        # Skip headers and dividers
        if stripped.startswith(("Network Destination", "----")):
            continue
        parts = stripped.split()
        if len(parts) < 5:
            continue
        try:
            # Format: dest, mask, gateway, interface, metric
            dest_str = parts[0]
            mask_str = parts[1]
            gw = parts[2]
            iface_ip = parts[3]
            try:
                metric = int(parts[4])
            except ValueError:
                metric = 0
            net = ipaddress.IPv4Network(dest_str + "/" + mask_str,
                                          strict=False)
            routes.append((int(net.network_address), int(net.netmask),
                            gw if gw != "On-link" else "0.0.0.0",
                            "",  # Windows route table doesn't expose iface name
                            iface_ip if iface_ip != "0.0.0.0" else "",
                            metric))
        except (ValueError, ipaddress.AddressValueError, IndexError):
            continue
    return routes


def list_subnets(max_hosts_per_subnet: int = 4096) -> LocalNetwork:
    """Inspect the host's routing table and return all directly-reachable subnets.

    Args:
      max_hosts_per_subnet: refuse subnets bigger than this (safety).
        Set high to allow /16, low to restrict to /20 and smaller.
    """
    net = LocalNetwork(hostname=socket.gethostname())

    # Try scapy first; fall back to `ip route` if it failed
    route_entries: list = []
    try:
        conf = _import_scapy_conf()
        route_entries = _route_entries_from_scapy(conf)
    except Exception as e:
        log.debug("scapy route lookup failed (%s) — falling back to shell", e)
    if not route_entries:
        log.info("Using `ip route` for subnet enumeration")
        route_entries = _route_entries_from_shell()
    if not route_entries:
        log.warning("Could not read routing table from any source")
        return net

    # Route format: (network_int, netmask_int, gateway_str, iface, output_ip, metric)
    seen: set[str] = set()
    for entry in route_entries:
        try:
            net_int, mask_int, gw, iface, out_ip, metric = entry[:6]
        except (ValueError, TypeError):
            continue

        prefix = _mask_to_prefix(mask_int)
        net_ip = _int_to_ip(net_int)
        try:
            cidr_obj = ipaddress.IPv4Network(f"{net_ip}/{prefix}", strict=False)
        except (ValueError, ipaddress.AddressValueError):
            continue

        if not _is_useful_subnet(cidr_obj):
            # Default route — still record the gateway
            if cidr_obj.prefixlen == 0 and gw and gw != "0.0.0.0":
                if gw not in net.default_gateways:
                    net.default_gateways.append(gw)
            continue

        cidr_str = str(cidr_obj)
        if cidr_str in seen:
            continue
        seen.add(cidr_str)

        if cidr_obj.num_addresses > max_hosts_per_subnet + 2:
            log.warning("Skipping %s (%d hosts > max_hosts_per_subnet=%d)",
                        cidr_str, cidr_obj.num_addresses, max_hosts_per_subnet)
            continue

        # Find the gateway for THIS subnet. The kernel route entry's gateway
        # is "0.0.0.0" for directly-connected nets; we want to overlay the
        # default gateway iff this subnet matches its scope.
        subnet_gateway = gw if gw and gw != "0.0.0.0" else None

        net.subnets.append(Subnet(
            cidr=cidr_str,
            interface=str(iface) if iface else None,
            local_ip=out_ip if out_ip else None,
            gateway=subnet_gateway,
            num_hosts=max(cidr_obj.num_addresses - 2, 0),
        ))

    # Attach the default gateway to whichever subnet contains it.
    for dgw in net.default_gateways:
        try:
            gw_ip = ipaddress.IPv4Address(dgw)
        except ValueError:
            continue
        for sn in net.subnets:
            if sn.gateway:  # already has one
                continue
            try:
                if gw_ip in ipaddress.IPv4Network(sn.cidr):
                    sn.gateway = dgw
                    break
            except ValueError:
                continue

    return net


def format_summary(net: LocalNetwork) -> str:
    """Human-readable one-screen summary of what we found."""
    if not net.subnets:
        return "(no scannable subnets discovered)"
    lines = [f"Host: {net.hostname}"]
    if net.default_gateways:
        lines.append(f"Default gateway(s): {', '.join(net.default_gateways)}")
    lines.append("Reachable subnets:")
    for sn in net.subnets:
        lines.append(
            f"  {sn.cidr:<20s} "
            f"iface={sn.interface or '?':<10s} "
            f"local={sn.local_ip or '?':<15s} "
            f"gw={sn.gateway or '-':<15s} "
            f"({sn.num_hosts} hosts)"
        )
    return "\n".join(lines)
