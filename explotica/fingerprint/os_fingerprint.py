"""Passive OS fingerprinting from TTL values.

When you send a packet to a host, the host's initial TTL is set by its OS:
  - Linux / BSD: 64
  - Windows: 128
  - Cisco / network gear: 255
  - macOS modern: 64

The received TTL is initial − (router hops). So if you see TTL=58, the host
is probably Linux 6 hops away. If you see 124, probably Windows 4 hops away.

This isn't a perfect identification, but it's a cheap and useful hint
collected for free from any ICMP echo / ARP reply.
"""

from __future__ import annotations

from typing import Optional


def guess_os_from_ttl(ttl: int) -> Optional[dict]:
    """Return {os_family, hops_estimate, initial_ttl} based on observed TTL."""
    if ttl is None or ttl <= 0:
        return None
    # Common initial TTLs in descending order
    candidates = [255, 128, 64, 32]
    for initial in candidates:
        if ttl <= initial:
            hops = initial - ttl
            family = {
                255: "network device (Cisco/router/printer)",
                128: "Windows",
                64:  "Linux/BSD/macOS",
                32:  "older Windows/embedded",
            }.get(initial, "unknown")
            return {
                "os_family": family,
                "hops_estimate": hops,
                "initial_ttl": initial,
                "observed_ttl": ttl,
            }
    return None
