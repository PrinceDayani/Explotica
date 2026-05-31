"""Second-hop UDP enrichment — the chains that put us ahead of nmap.

nmap reports "port open + a version string". Real device intelligence is a
*follow-up*: take what the first probe revealed and ask the next question.

  • SNMP: one GET told us sysDescr; a *walk* of sysName / sysContact /
    sysLocation / sysObjectID / sysUpTime profiles the device + its admin.
  • SSDP: the M-SEARCH reply gave us a LOCATION URL; fetching that XML yields
    manufacturer / modelName / modelNumber / serialNumber / UDN — the actual
    device identity, not just "some UPnP server".

These run only against already-open ports (a handful per host), are strictly
best-effort, and never raise into the scan. Build it out: IPMI RAKP hash
disclosure (CVE-2013-4786) and full mDNS PTR→SRV→TXT resolution are the natural
next links in this chain.
"""

from __future__ import annotations

import logging
import socket
from typing import Optional

from ..core.constants import USER_AGENT

log = logging.getLogger(__name__)


# ── SNMP: arbitrary-OID GET + a small device-profile walk ─────────────────────
def _encode_oid(arcs: tuple[int, ...]) -> bytes:
    """BER-encode an OID from its integer arcs."""
    first = 40 * arcs[0] + arcs[1]
    body = bytes([first])
    for arc in arcs[2:]:
        if arc < 128:
            body += bytes([arc])
        else:                                   # base-128, high bit continuation
            stack = []
            while arc > 0:
                stack.append(arc & 0x7F)
                arc >>= 7
            chunk = bytearray()
            for i, b in enumerate(reversed(stack)):
                chunk.append(b | (0x80 if i < len(stack) - 1 else 0x00))
            body += bytes(chunk)
    return body


def build_snmp_get(oid_arcs: tuple[int, ...], community: bytes = b"public",
                   request_id: bytes = b"\x13\x37\x13\x37") -> bytes:
    """Build a minimal SNMP v2c GetRequest for one OID (lengths assumed <128)."""
    oid = _encode_oid(oid_arcs)
    oid_tlv = b"\x06" + bytes([len(oid)]) + oid
    vb = b"\x30" + bytes([len(oid_tlv) + 2]) + oid_tlv + b"\x05\x00"
    vbs = b"\x30" + bytes([len(vb)]) + vb
    rid = b"\x02\x04" + request_id
    pdu_body = rid + b"\x02\x01\x00" + b"\x02\x01\x00" + vbs
    pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body
    body = (b"\x02\x01\x01"
            + b"\x04" + bytes([len(community)]) + community + pdu)
    return b"\x30" + bytes([len(body)]) + body


def _snmp_extract_value(data: bytes, oid: bytes) -> Optional[object]:
    """Find the OID in a response and decode the value TLV that follows it."""
    needle = b"\x06" + bytes([len(oid)]) + oid
    idx = data.find(needle)
    if idx < 0:
        return None
    rest = data[idx + len(needle):]
    if len(rest) < 2:
        return None
    vtype, vlen = rest[0], rest[1]
    if vlen & 0x80:                              # long-form length
        nb = vlen & 0x7F
        vlen = int.from_bytes(rest[2:2 + nb], "big")
        val = rest[2 + nb:2 + nb + vlen]
    else:
        val = rest[2:2 + vlen]
    if vtype == 0x04:                            # OCTET STRING
        return val.decode("utf-8", errors="replace").strip()[:200]
    if vtype in (0x02, 0x43, 0x41, 0x42):        # INTEGER / TimeTicks / counters
        return int.from_bytes(val, "big") if val else 0
    if vtype == 0x06:                            # OID → dotted string
        return _decode_oid(val)
    return None


def _decode_oid(val: bytes) -> str:
    if not val:
        return ""
    arcs = [val[0] // 40, val[0] % 40]
    cur = 0
    for b in val[1:]:
        cur = (cur << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(cur)
            cur = 0
    return ".".join(str(a) for a in arcs)


_SNMP_PROFILE = {
    "sysName": (1, 3, 6, 1, 2, 1, 1, 5, 0),
    "sysContact": (1, 3, 6, 1, 2, 1, 1, 4, 0),
    "sysLocation": (1, 3, 6, 1, 2, 1, 1, 6, 0),
    "sysObjectID": (1, 3, 6, 1, 2, 1, 1, 2, 0),
    "sysUpTimeTicks": (1, 3, 6, 1, 2, 1, 1, 3, 0),
}


def snmp_walk(ip: str, community: str = "public",
              timeout: float = 2.0) -> dict:
    """Profile a host over SNMP (the second hop after sysDescr)."""
    comm = community.encode("ascii")
    out: dict = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.connect((ip, 161))
        try:
            for name, arcs in _SNMP_PROFILE.items():
                try:
                    s.send(build_snmp_get(arcs, community=comm))
                    data = s.recv(2048)
                except (socket.timeout, OSError):
                    continue
                val = _snmp_extract_value(data, _encode_oid(arcs))
                if val not in (None, ""):
                    out[name] = val
        finally:
            s.close()
    except OSError as e:
        log.debug("snmp_walk %s failed: %s", ip, e)
    if "sysUpTimeTicks" in out and isinstance(out["sysUpTimeTicks"], int):
        secs = out["sysUpTimeTicks"] // 100
        out["sysUpTime"] = f"{secs // 86400}d {secs % 86400 // 3600}h"
    return out


# ── SSDP: fetch & parse the device-description XML at LOCATION ─────────────────
_SSDP_FIELDS = ("friendlyName", "manufacturer", "modelName", "modelNumber",
                "modelDescription", "serialNumber", "UDN")


def _xml_tag(xml: str, tag: str) -> Optional[str]:
    """Namespace-agnostic <tag>value</tag> extractor."""
    import re
    m = re.search(rf"<(?:\w+:)?{tag}>(.*?)</(?:\w+:)?{tag}>", xml,
                  re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:160] if m else None


def ssdp_fetch_device(location: str, timeout: float = 3.0) -> dict:
    """GET the SSDP LOCATION URL and pull the device-identity fields."""
    import urllib.request
    out: dict = {}
    try:
        req = urllib.request.Request(location, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            xml = r.read(65536).decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001 — network best-effort
        log.debug("ssdp_fetch_device %s failed: %s", location, e)
        return out
    for tag in _SSDP_FIELDS:
        v = _xml_tag(xml, tag)
        if v:
            out[tag] = v
    return out


# ── mDNS: follow-up PTR → SRV → TXT → A resolution ────────────────────────────
import struct


def _dns_read_name(data: bytes, off: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels: list[str] = []
    next_off = None
    jumps = 0
    n = len(data)
    while off < n and jumps < 16:
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:                # compression pointer
            if off + 1 >= n:
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if next_off is None:
                next_off = off + 2
            off = ptr
            jumps += 1
            continue
        labels.append(data[off + 1:off + 1 + length].decode("utf-8", "ignore"))
        off += 1 + length
    return ".".join(labels), (next_off if next_off is not None else off)


def _dns_parse_records(data: bytes) -> list[dict]:
    """Parse all RRs (answer + authority + additional) into typed dicts."""
    if len(data) < 12:
        return []
    qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    off = 12
    for _ in range(qd):                          # skip questions
        _, off = _dns_read_name(data, off)
        off += 4
    records: list[dict] = []
    for _ in range(an + ns + ar):
        if off + 1 > len(data):
            break
        name, off = _dns_read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        rec = {"name": name, "type": rtype}
        if rtype == 12:                          # PTR
            rec["ptr"], _ = _dns_read_name(data, off)
        elif rtype == 33 and len(rdata) >= 6:    # SRV
            prio, weight, port = struct.unpack(">HHH", rdata[:6])
            target, _ = _dns_read_name(data, off + 6)
            rec.update({"port": port, "target": target})
        elif rtype == 16:                        # TXT
            rec["txt"] = _parse_txt(rdata)
        elif rtype == 1 and len(rdata) == 4:     # A
            rec["a"] = ".".join(str(b) for b in rdata)
        elif rtype == 28 and len(rdata) == 16:   # AAAA
            rec["aaaa"] = rdata.hex()
        records.append(rec)
        off += rdlen
    return records


def _parse_txt(rdata: bytes) -> list[str]:
    out, i = [], 0
    while i < len(rdata):
        ln = rdata[i]
        out.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "ignore"))
        i += 1 + ln
    return [s for s in out if s]


def _mdns_query(service: str) -> bytes:
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    qname = b"".join(bytes([len(l)]) + l.encode()
                     for l in service.split(".") if l) + b"\x00"
    return header + qname + struct.pack(">HH", 12, 1)    # PTR / IN


def mdns_resolve(ip: str, service_types: list[str], timeout: float = 2.0,
                 max_services: int = 8) -> dict:
    """Follow up an mDNS catalog: PTR→SRV→TXT→A for each service type.

    Returns {service_type: [{instance, target, port, txt, addr}]}. Best-effort.
    """
    out: dict = {}
    for service in service_types[:max_services]:
        if not service.endswith(".local") and ".local" not in service:
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                s.connect((ip, 5353))
                s.send(_mdns_query(service))
                records: list[dict] = []
                while True:                          # drain multi-packet replies
                    try:
                        records.extend(_dns_parse_records(s.recv(4096)))
                    except (socket.timeout, OSError):
                        break
            finally:
                s.close()
        except OSError:
            continue
        instances = _assemble_instances(records)
        if instances:
            out[service] = instances
    return out


def _assemble_instances(records: list[dict]) -> list[dict]:
    """Stitch PTR/SRV/TXT/A records from one response into instance entries."""
    srv = {r["name"]: r for r in records if r["type"] == 33}
    txt = {r["name"]: r.get("txt") for r in records if r["type"] == 16}
    addrs = {r["name"]: r.get("a") for r in records if r["type"] == 1}
    instances: list[dict] = []
    seen = set()
    for r in records:
        names = [r["ptr"]] if r["type"] == 12 and "ptr" in r else []
        if r["type"] == 33:
            names.append(r["name"])
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            entry = {"instance": name}
            s = srv.get(name)
            if s:
                entry["port"] = s.get("port")
                entry["target"] = s.get("target")
                entry["addr"] = addrs.get(s.get("target"))
            if txt.get(name):
                entry["txt"] = txt[name][:12]
            instances.append(entry)
    return instances[:20]


# ── Orchestrator ──────────────────────────────────────────────────────────────
def enrich_udp_ports(ip: str, ports: list) -> None:
    """Run the second-hop chains against a host's OPEN udp ports, merging the
    results into each Port.service_intel. Mutates ports in place; best-effort.
    """
    for p in ports:
        if getattr(p, "state", None) != "open":
            continue
        try:
            if p.number == 161:
                walk = snmp_walk(ip)
                if walk:
                    intel = dict(p.service_intel or {})
                    snmp = dict(intel.get("snmp") or {"responded": True})
                    snmp["walk"] = walk
                    name = walk.get("sysName")
                    if name:
                        snmp.setdefault("finding",
                                        f"SNMP profile: {name}")
                    intel["snmp"] = snmp
                    p.service_intel = intel
            elif p.number == 1900:
                intel = dict(p.service_intel or {})
                ssdp = dict(intel.get("ssdp") or {})
                loc = ssdp.get("location")
                if loc:
                    dev = ssdp_fetch_device(loc)
                    if dev:
                        ssdp["device"] = dev
                        label = dev.get("modelName") or dev.get("friendlyName")
                        if label:
                            ssdp["finding"] = (
                                f"UPnP device: {dev.get('manufacturer','')} "
                                f"{label}").strip()
                        intel["ssdp"] = ssdp
                        p.service_intel = intel
            elif p.number == 623:
                # IPMI 2.0 → attempt the RAKP hash dump (CVE-2013-4786).
                intel = dict(p.service_intel or {})
                ipmi = dict(intel.get("ipmi") or {})
                if ipmi.get("ipmi_2_0", True):
                    from .ipmi_rakp import dump_hash
                    h = dump_hash(ip)
                    if h:
                        ipmi["rakp_hash"] = h
                        ipmi["finding"] = h["finding"]
                        ipmi["severity"] = "high"
                        intel["ipmi"] = ipmi
                        p.service_intel = intel
            elif p.number == 5353:
                # mDNS catalog → resolve each service type to host/port/props.
                intel = dict(p.service_intel or {})
                mdns = dict(intel.get("mdns") or {})
                svcs = mdns.get("services") or []
                if svcs:
                    resolved = mdns_resolve(ip, svcs)
                    if resolved:
                        mdns["resolved"] = resolved
                        intel["mdns"] = mdns
                        p.service_intel = intel
        except Exception as e:  # noqa: BLE001 — never break the scan
            log.debug("enrich %s:%d failed: %s", ip, p.number, e)
