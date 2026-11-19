"""Passive mDNS (multicast DNS, 224.0.0.251:5353) sniffing.

Active mDNS service queries already live in the UDP scan machinery
(udp_payloads._mdns_services + udp_parsers.parse_mdns). This module adds the
passive side: join the mDNS multicast group and listen for the announcements
devices broadcast unprompted (printers, Chromecasts, NAS, AirPlay, ...), then
parse the answer records.

parse_mdns_packet() is a real DNS wire-format parser (header + answer records,
with name decompression) and is pure/offline-testable. sniff_mdns() is the
best-effort network listener; it never raises into a scan.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from typing import Optional

log = logging.getLogger(__name__)

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

_TYPE_A = 1
_TYPE_PTR = 12
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name starting at offset; returns (name, next_offset).

    Handles 0xC0 compression pointers. next_offset is the position just after
    the name in the record stream (pointers do not advance it past the 2-byte
    pointer). Guards against pointer loops.
    """
    labels: list[str] = []
    pos = offset
    jumped = False
    end_offset = offset
    seen = 0
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end_offset = pos
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end_offset = pos + 2
            jumped = True
            pos = ptr
            seen += 1
            if seen > 128:  # loop guard
                break
            continue
        pos += 1
        if pos + length > len(data):
            break
        labels.append(data[pos:pos + length].decode("ascii", "ignore"))
        pos += length
        if not jumped:
            end_offset = pos
    return ".".join(labels), end_offset


def parse_mdns_packet(data: bytes) -> Optional[dict]:
    """Parse an mDNS response into services / hosts / addresses.

    Returns a dict with any of: ptr (service instances), srv (host:port),
    addresses (A records as name->ip), txt (name->list). None if not a
    parseable DNS message.
    """
    if len(data) < 12:
        return None
    try:
        (_id, _flags, qd, an, ns, ar) = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return None
    total_rr = an + ns + ar
    if total_rr == 0:
        return None

    off = 12
    # Skip the question section.
    for _ in range(qd):
        _name, off = _decode_name(data, off)
        off += 4  # qtype + qclass
        if off > len(data):
            return None

    ptr: list[str] = []
    srv: list[dict] = []
    addresses: dict[str, str] = {}
    txt: dict[str, list] = {}

    for _ in range(total_rr):
        if off + 1 > len(data):
            break
        name, off = _decode_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        rdata_start = off
        off += rdlen
        if rtype == _TYPE_PTR:
            target, _ = _decode_name(data, rdata_start)
            if target:
                ptr.append(target)
        elif rtype == _TYPE_SRV and rdlen >= 6:
            _prio, _weight, port = struct.unpack(">HHH", rdata[:6])
            target, _ = _decode_name(data, rdata_start + 6)
            srv.append({"name": name, "target": target, "port": port})
        elif rtype == _TYPE_A and rdlen == 4:
            addresses[name] = socket.inet_ntoa(rdata)
        elif rtype == _TYPE_AAAA and rdlen == 16:
            try:
                addresses[name] = socket.inet_ntop(socket.AF_INET6, rdata)
            except OSError:
                pass
        elif rtype == _TYPE_TXT:
            items = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                i += 1
                if ln and i + ln <= len(rdata):
                    items.append(rdata[i:i + ln].decode("utf-8", "ignore"))
                i += ln
            if items:
                txt[name] = items

    result: dict = {"responded": True}
    if ptr:
        result["ptr"] = sorted(set(ptr))[:50]
    if srv:
        result["srv"] = srv[:50]
    if addresses:
        result["addresses"] = addresses
    if txt:
        result["txt"] = txt
    return result if len(result) > 1 else {"responded": True,
                                           "raw_bytes": len(data)}


def sniff_mdns(duration: float = 3.0, iface_ip: str = "0.0.0.0") -> dict:
    """Listen for mDNS announcements for `duration` seconds. Best-effort.

    Returns {"hosts": {ip: {...}}, "services": [...], "errors": [...]}.
    Never raises into a scan — failures are captured in "errors".
    """
    out: dict = {"hosts": {}, "services": [], "errors": []}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((iface_ip, MDNS_PORT))
        mreq = struct.pack("4s4s", socket.inet_aton(MDNS_ADDR),
                           socket.inet_aton(iface_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(0.5)
        deadline = time.monotonic() + duration
        services: set = set()
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(9000)
            except socket.timeout:
                continue
            parsed = parse_mdns_packet(data)
            if not parsed:
                continue
            host = out["hosts"].setdefault(addr[0], {})
            for key in ("ptr", "srv", "addresses", "txt"):
                if key in parsed:
                    host.setdefault(key, [] if key in ("ptr",) else {})
            if "ptr" in parsed:
                services.update(parsed["ptr"])
                host["ptr"] = sorted(set(host.get("ptr", []) + parsed["ptr"]))
            for k in ("srv", "addresses", "txt"):
                if k in parsed:
                    host[k] = parsed[k]
        out["services"] = sorted(services)[:100]
    except OSError as e:  # noqa: BLE001 — best-effort, never raise into a scan
        out["errors"].append(str(e))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return out
