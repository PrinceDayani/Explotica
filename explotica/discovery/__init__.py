"""Discovery — host + port enumeration.

Layer:
  - discovery.discovery: ARP sweep + ICMP echo
  - discovery.ports: TCP-connect scanner (state-aware)
  - discovery.aio: async port scanner (high concurrency)
  - discovery.syn_scan: stateless SYN scanner (raw sockets, masscan-class)
  - discovery.enumerate: subnet enumeration (link-local + RFC1918 auto-detect)
  - discovery.netfabric: DHCP + traceroute
  - discovery.network_spider: recursive subnet discovery via SNMP routes
  - discovery.udp_probes: UDP-based service probes (SNMP, mDNS, etc.)
"""

from .ports import (
    ALL_TCP_PORTS, TOP_100_PORTS, IANA_SERVICE_HINTS,
    probe_tcp, scan_ports, apply_iana_guess,
)
from .syn_scan import syn_scan, syn_scan_available

__all__ = [
    # ports
    "ALL_TCP_PORTS", "TOP_100_PORTS", "IANA_SERVICE_HINTS",
    "probe_tcp", "scan_ports", "apply_iana_guess",
    # syn_scan
    "syn_scan", "syn_scan_available",
]
