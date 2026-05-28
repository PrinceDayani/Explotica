"""UDP service probes — SNMP, mDNS, SSDP, NetBIOS-NS.

UDP services are invisible to our TCP scanner. This module sends targeted
queries to well-known UDP ports and parses responses.

Each probe returns a dict of findings, or None.
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Optional

log = logging.getLogger(__name__)


# ── SNMP v2c GetRequest for sysDescr.0 ────────────────────────────────────
def probe_snmp(host: str, community: str = "public",
               timeout: float = 2.0) -> Optional[dict]:
    """Query SNMP sysDescr.0 (1.3.6.1.2.1.1.1.0) with the given community.

    Hand-rolled BER encoding — no pysnmp dependency.
    """
    # BER-encoded SNMP v2c GetRequest for OID 1.3.6.1.2.1.1.1.0
    # Pre-built packet (only the community varies)
    community_bytes = community.encode("ascii")
    request_id = b"\x02\x01\x01"
    error_status = b"\x02\x01\x00"
    error_index = b"\x02\x01\x00"
    # Variable bindings sequence containing one binding for sysDescr.0
    var_bindings = (
        b"\x30\x10"                       # SEQUENCE, len 16
        b"\x30\x0e"                       # SEQUENCE, len 14
        b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"  # OID 1.3.6.1.2.1.1.1.0
        b"\x05\x00"                       # NULL
    )
    pdu = (
        b"\xa0"                            # GetRequest tag
        + bytes([len(request_id) + len(error_status) + len(error_index)
                + len(var_bindings)])
        + request_id + error_status + error_index + var_bindings
    )
    msg = (
        b"\x30"                            # SEQUENCE
        + bytes([3 + 2 + len(community_bytes) + len(pdu)])
        + b"\x02\x01\x01"                  # version: v2c (1)
        + b"\x04" + bytes([len(community_bytes)]) + community_bytes
        + pdu
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, (host, 161))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError) as e:
        log.debug("SNMP %s probe failed: %s", host, e)
        return None
    finally:
        sock.close()

    if not data or len(data) < 30:
        return None

    # Loose parse: find the OCTET STRING that follows the OID.
    # Look for the sysDescr OID bytes and grab the next OCTET STRING.
    needle = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
    idx = data.find(needle)
    if idx < 0:
        return None
    rest = data[idx + len(needle):]
    # Next TLV — we want type 0x04 (OCTET STRING)
    if not rest or rest[0] != 0x04:
        return None
    length = rest[1]
    if length & 0x80:  # long-form length
        nbytes = length & 0x7F
        length = int.from_bytes(rest[2:2 + nbytes], "big")
        value = rest[2 + nbytes:2 + nbytes + length]
    else:
        value = rest[2:2 + length]
    sysdescr = value.decode("utf-8", errors="replace").strip()
    return {
        "community": community,
        "sysDescr": sysdescr[:280],
        "responded": True,
    }


def probe_snmp_default(host: str, timeout: float = 2.0) -> Optional[dict]:
    """Try public then private community."""
    for comm in ("public", "private"):
        r = probe_snmp(host, community=comm, timeout=timeout)
        if r:
            return r
    return None


# ── mDNS (port 5353) — local-service discovery ────────────────────────────
def probe_mdns(host: str, timeout: float = 2.0) -> Optional[dict]:
    """Send mDNS query for _services._dns-sd._udp.local. — service catalog."""
    # DNS header: id=0, flags=0, qdcount=1, ancount=0, nscount=0, arcount=0
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    # Question: _services._dns-sd._udp.local. type PTR (12) class IN (1)
    name = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    qsuffix = struct.pack(">HH", 12, 1)
    query = header + name + qsuffix

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (host, 5353))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError) as e:
        log.debug("mDNS %s probe failed: %s", host, e)
        return None
    finally:
        sock.close()

    if not data or len(data) < 20:
        return None

    # Coarse: pull printable runs from the response — service names look like
    # _http._tcp.local., _airplay._tcp.local. etc.
    services: list[str] = []
    cur: list[int] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= 5:
                s = bytes(cur).decode("ascii", errors="ignore")
                if "_" in s and ".local" in s:
                    services.append(s)
            cur = []
    if len(cur) >= 5:
        services.append(bytes(cur).decode("ascii", errors="ignore"))
    return {
        "responded": True,
        "services": sorted(set(services))[:10],
    } if services else {"responded": True, "raw_bytes": len(data)}


# ── SSDP (port 1900 UDP) — UPnP service catalog ───────────────────────────
def probe_ssdp(host: str, timeout: float = 2.0) -> Optional[dict]:
    """SSDP M-SEARCH * — UPnP devices respond with HTTPMU-format messages."""
    payload = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, 1900))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError) as e:
        log.debug("SSDP %s probe failed: %s", host, e)
        return None
    finally:
        sock.close()

    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    server = None
    location = None
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
        elif line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
    return {
        "responded": True,
        "server": server,
        "location": location,
    }


# ── NetBIOS Name Service (port 137 UDP) — nbtstat-style ────────────────────
def probe_netbios_ns(host: str, timeout: float = 2.0) -> Optional[dict]:
    """Send NBT name-query for status — reveals workgroup/computer names."""
    # NBT name query for '*' (all names) — encoded as 'CKAAAAAAAAAAAAAAAAAA...'
    # transaction id 0xa6b6, flags 0, qdcount=1, ancount=0, nscount=0, arcount=0
    header = struct.pack(">HHHHHH", 0xA6B6, 0, 1, 0, 0, 0)
    # Encoded '*' as 32-char first-level + null
    name = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    # Type 0x21 (NBSTAT), class IN (1)
    suffix = struct.pack(">HH", 0x21, 1)
    pkt = header + name + suffix

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (host, 137))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError) as e:
        log.debug("NetBIOS-NS %s probe failed: %s", host, e)
        return None
    finally:
        sock.close()

    if not data or len(data) < 60:
        return None

    # Skip header (12) + name (34) + 4 fixed bytes = 50
    # Next: RR header (10 bytes), then names data starting with count byte
    offset = 56
    if offset >= len(data):
        return {"responded": True, "raw_bytes": len(data)}
    name_count = data[offset]
    offset += 1
    names: list[dict] = []
    for _ in range(min(name_count, 16)):
        if offset + 18 > len(data):
            break
        raw_name = data[offset:offset + 15].rstrip(b" \x00")
        name_str = raw_name.decode("ascii", errors="ignore")
        suffix = data[offset + 15]
        flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
        names.append({
            "name": name_str,
            "suffix": f"0x{suffix:02x}",
            "is_group": bool(flags & 0x8000),
        })
        offset += 18

    return {"responded": True, "names": names}


def probe_all_udp(host: str, timeout: float = 2.0) -> dict:
    """Run all UDP probes against a host. Returns dict of {probe_name: result}."""
    out: dict = {}
    for name, fn in (("snmp", probe_snmp_default),
                     ("mdns", probe_mdns),
                     ("ssdp", probe_ssdp),
                     ("netbios", probe_netbios_ns)):
        try:
            r = fn(host, timeout=timeout)
            if r:
                out[name] = r
        except Exception as e:
            log.debug("UDP %s probe on %s failed: %s", name, host, e)
    return out
