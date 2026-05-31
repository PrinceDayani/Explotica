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
        except Exception as e:  # noqa: BLE001 — never break the scan
            log.debug("enrich %s:%d failed: %s", ip, p.number, e)
