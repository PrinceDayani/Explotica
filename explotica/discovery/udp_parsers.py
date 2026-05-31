"""UDP response parsers — turn raw reply bytes into structured intel.

nmap reports an open UDP port plus a version string it pattern-matched. We go
further: each parser extracts the *fields that matter for an assessment* and,
where relevant, raises a **security finding** (``findings`` key) — IPMI
null-user auth, NTP monlist amplification, open RPC services, anonymous SNMP,
etc. Those findings are what a report actually wants.

Every parser is defensive: malformed/partial datagrams return whatever could be
salvaged, never raise. ``parse_udp_response(proto, data)`` is the dispatch.
"""

from __future__ import annotations

import struct
from typing import Optional


# ── SNMP ──────────────────────────────────────────────────────────────────────
def parse_snmp(data: bytes) -> Optional[dict]:
    if len(data) < 16:
        return {"responded": True, "raw_bytes": len(data)}
    needle = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"   # sysDescr.0 OID
    idx = data.find(needle)
    out: dict = {"responded": True,
                 "finding": "SNMP responds to community 'public' "
                            "(anonymous read access)"}
    if idx < 0:
        return out
    rest = data[idx + len(needle):]
    if not rest or rest[0] != 0x04:                        # OCTET STRING
        return out
    length = rest[1]
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(rest[2:2 + n], "big")
        value = rest[2 + n:2 + n + length]
    else:
        value = rest[2:2 + length]
    out["sysDescr"] = value.decode("utf-8", errors="replace").strip()[:300]
    out["community"] = "public"
    return out


# ── NTP ───────────────────────────────────────────────────────────────────────
def parse_ntp(data: bytes) -> Optional[dict]:
    if len(data) < 4:
        return {"responded": True, "raw_bytes": len(data)}
    b0 = data[0]
    out = {"responded": True,
           "version": (b0 >> 3) & 0x07,
           "mode": b0 & 0x07,
           "stratum": data[1] if len(data) > 1 else None}
    return out


def parse_ntp_monlist(data: bytes) -> Optional[dict]:
    # A monlist reply at all means the host is a usable amplification reflector.
    if not data:
        return None
    n_entries = max(0, (len(data) - 8) // 72)
    return {
        "responded": True,
        "monlist_enabled": True,
        "response_bytes": len(data),
        "peer_entries": n_entries,
        "finding": ("NTP mode-7 monlist enabled — DDoS amplification "
                    "reflector (CVE-2013-5211); response %d bytes" % len(data)),
        "severity": "high",
    }


# ── DNS (version.bind) ────────────────────────────────────────────────────────
def _dns_skip_name(data: bytes, off: int) -> int:
    """Advance past a DNS name (labels or a compression pointer)."""
    n = len(data)
    while off < n:
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:        # compression pointer → 2 bytes total
            return off + 2
        off += 1 + length
    return off


def parse_dns_version(data: bytes) -> Optional[dict]:
    if len(data) < 12:
        return {"responded": True, "raw_bytes": len(data)}
    qd = int.from_bytes(data[4:6], "big")
    an = int.from_bytes(data[6:8], "big")
    out = {"responded": True}
    # Walk past the question section — the server echoes our "version.bind"
    # there, so parsing it as an answer would be a false "leak" every time.
    off = 12
    for _ in range(qd):
        off = _dns_skip_name(data, off) + 4   # + qtype(2) + qclass(2)
    if an <= 0 or off + 10 > len(data):
        return out                            # responded, but leaked nothing
    off = _dns_skip_name(data, off)
    if off + 10 > len(data):
        return out
    rtype = int.from_bytes(data[off:off + 2], "big")
    rdlen = int.from_bytes(data[off + 8:off + 10], "big")
    rdata = data[off + 10:off + 10 + rdlen]
    if rtype == 16 and rdata:                  # TXT: first byte is the length
        txt = rdata[1:1 + rdata[0]].decode("ascii", errors="ignore").strip()
        if txt:
            out["version_bind"] = txt[:120]
            out["finding"] = f"DNS leaks version.bind: {txt[:120]}"
    return out


# ── NetBIOS-NS node status ────────────────────────────────────────────────────
def parse_netbios(data: bytes) -> Optional[dict]:
    if len(data) < 57:
        return {"responded": True, "raw_bytes": len(data)}
    offset = 56
    name_count = data[offset]
    offset += 1
    names: list[dict] = []
    for _ in range(min(name_count, 24)):
        if offset + 18 > len(data):
            break
        raw = data[offset:offset + 15].rstrip(b" \x00")
        suffix = data[offset + 15]
        flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
        names.append({
            "name": raw.decode("ascii", errors="ignore"),
            "suffix": f"0x{suffix:02x}",
            "is_group": bool(flags & 0x8000),
        })
        offset += 18
    return {"responded": True, "names": names}


# ── SSDP / UPnP ───────────────────────────────────────────────────────────────
def parse_ssdp(data: bytes) -> Optional[dict]:
    text = data.decode("utf-8", errors="replace")
    out = {"responded": True}
    for line in text.splitlines():
        low = line.lower()
        if low.startswith("server:"):
            out["server"] = line.split(":", 1)[1].strip()
        elif low.startswith("location:"):
            out["location"] = line.split(":", 1)[1].strip()
        elif low.startswith("st:"):
            out["search_target"] = line.split(":", 1)[1].strip()
    return out


# ── mDNS ──────────────────────────────────────────────────────────────────────
def parse_mdns(data: bytes) -> Optional[dict]:
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
    if services:
        return {"responded": True, "services": sorted(set(services))[:20]}
    return {"responded": True, "raw_bytes": len(data)}


# ── RPC portmapper DUMP ───────────────────────────────────────────────────────
_RPC_PROG_NAMES = {
    100000: "portmapper", 100003: "nfs", 100005: "mountd", 100021: "nlockmgr",
    100024: "status", 100227: "nfs_acl", 100001: "rstatd", 100002: "rusersd",
    100011: "rquotad", 100068: "cmsd", 100083: "ttdbserverd", 100099: "autofs",
    391002: "sgi_fam", 600100069: "fypxfrd",
}


def parse_rpcbind(data: bytes) -> Optional[dict]:
    # Skip RPC reply header (xid, type, reply_stat, verf...) — locate the
    # variable-length list of (prog, vers, proto, port) quads. We do a tolerant
    # scan: find the accept_stat then walk 'value-follows' entries.
    if len(data) < 24:
        return {"responded": True, "raw_bytes": len(data)}
    services: list[dict] = []
    # The map list begins after: xid(4) mtype(4) reply_stat(4) verf_flavor(4)
    # verf_len(4) accept_stat(4) = 24 bytes for AUTH_NULL verf.
    off = 24
    n = len(data)
    while off + 4 <= n and len(services) < 64:
        follows = struct.unpack(">I", data[off:off + 4])[0]
        off += 4
        if follows != 1:
            break
        if off + 16 > n:
            break
        prog, vers, proto, port = struct.unpack(">IIII", data[off:off + 16])
        off += 16
        services.append({
            "program": prog,
            "name": _RPC_PROG_NAMES.get(prog, "unknown"),
            "version": vers,
            "proto": "tcp" if proto == 6 else "udp" if proto == 17 else proto,
            "port": port,
        })
    out = {"responded": True, "services": services}
    if any(s["name"] == "nfs" for s in services):
        out["finding"] = "RPC portmapper exposes NFS — check for world exports"
    return out


# ── IKE / ISAKMP ──────────────────────────────────────────────────────────────
_IKE_VENDOR_IDS = {
    b"\x4a\x13\x1c\x81\x07\x03\x58\x45": "RFC 3947 NAT-T",
    b"\x09\x00\x26\x89\xdf\xd6\xb7\x12": "XAUTH",
    b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9": "Dead Peer Detection",
}


def parse_ike(data: bytes) -> Optional[dict]:
    if len(data) < 28:
        return {"responded": True, "raw_bytes": len(data)}
    exch = data[18]
    out = {
        "responded": True,
        "isakmp": True,
        "exchange_type": exch,
        "finding": "IKE/IPsec VPN endpoint (ISAKMP responds on UDP/500)",
    }
    if exch == 5:                        # informational → likely no-proposal-chosen
        out["note"] = "responder rejected our transform set"
    vendors = []
    for vid, label in _IKE_VENDOR_IDS.items():
        if vid in data:
            vendors.append(label)
    if vendors:
        out["vendor_ids"] = vendors
    return out


# ── IPMI Get Channel Authentication Capabilities ──────────────────────────────
def parse_ipmi(data: bytes) -> Optional[dict]:
    # RMCP(4) + session(9) + msg_len(1) + msg... completion code at body[6].
    if len(data) < 22:
        return {"responded": True, "raw_bytes": len(data)}
    msg = data[14:]
    if len(msg) < 9:
        return {"responded": True, "ipmi": True}
    comp_code = msg[6]
    chan = msg[7]
    auth_byte = msg[8]
    out = {
        "responded": True,
        "ipmi": True,
        "channel": chan & 0x0F,
        "ipmi_2_0": bool(auth_byte & 0x80),
        "finding": "IPMI/BMC management interface exposed (UDP/623)",
        "severity": "medium",
    }
    if comp_code != 0:
        out["completion_code"] = f"0x{comp_code:02x}"
        return out
    # Auth-type support byte: bit0 none, bit1 MD2, bit2 MD5, bit4 straight-pwd.
    out["auth_none"] = bool(auth_byte & 0x01)
    out["auth_md5"] = bool(auth_byte & 0x04)
    if len(msg) > 9:
        caps = msg[9]
        out["null_user"] = bool(caps & 0x20)
        out["anonymous_login"] = bool(caps & 0x10)
        if caps & 0x30:
            out["finding"] = ("IPMI allows null/anonymous login — "
                              "credential-free BMC access")
            out["severity"] = "high"
    return out


# ── STUN ──────────────────────────────────────────────────────────────────────
def parse_stun(data: bytes) -> Optional[dict]:
    if len(data) < 20:
        return {"responded": True, "raw_bytes": len(data)}
    msg_type = struct.unpack(">H", data[0:2])[0]
    return {"responded": True, "stun": True,
            "binding_response": msg_type == 0x0101}


# ── memcached UDP ─────────────────────────────────────────────────────────────
def parse_memcached(data: bytes) -> Optional[dict]:
    text = data.decode("ascii", errors="replace")
    out = {"responded": True, "amplification_bytes": len(data)}
    for line in text.splitlines():
        if line.startswith("STAT version"):
            out["version"] = line.split(" ", 2)[-1].strip()
    if len(data) > 100:
        out["finding"] = ("memcached exposed on UDP — amplification reflector "
                          "(no-auth, CVE-2018-1000115)")
        out["severity"] = "high"
    return out


# ── MSSQL browser ─────────────────────────────────────────────────────────────
def parse_mssql_browser(data: bytes) -> Optional[dict]:
    if len(data) < 3:
        return {"responded": True, "raw_bytes": len(data)}
    body = data[3:].decode("ascii", errors="replace")
    instances: list[dict] = []
    for chunk in body.split(";;"):
        kv = chunk.split(";")
        d: dict = {}
        for i in range(0, len(kv) - 1, 2):
            d[kv[i]] = kv[i + 1]
        if d.get("ServerName") or d.get("InstanceName"):
            instances.append(d)
    return {"responded": True, "instances": instances}


# ── SIP ───────────────────────────────────────────────────────────────────────
def parse_sip(data: bytes) -> Optional[dict]:
    text = data.decode("utf-8", errors="replace")
    out = {"responded": True}
    for line in text.splitlines():
        low = line.lower()
        if low.startswith("server:") or low.startswith("user-agent:"):
            out["server"] = line.split(":", 1)[1].strip()
        elif line.startswith("SIP/2.0"):
            out["status"] = line.strip()
    return out


# ── chargen ───────────────────────────────────────────────────────────────────
def parse_chargen(data: bytes) -> Optional[dict]:
    return {
        "responded": True,
        "amplification_bytes": len(data),
        "finding": "chargen (UDP/19) enabled — classic amplification reflector",
        "severity": "medium",
    }


# ── Ubiquiti discovery ────────────────────────────────────────────────────────
def parse_ubiquiti(data: bytes) -> Optional[dict]:
    # Reply: version/cmd/len header, then TLVs (type:1, len:2, value).
    if len(data) < 4:
        return {"responded": True, "raw_bytes": len(data)}
    out: dict = {"responded": True, "ubiquiti": True}
    off = 4
    n = len(data)
    fields: list[str] = []
    mac = None
    while off + 3 <= n:
        ttype = data[off]
        tlen = int.from_bytes(data[off + 1:off + 3], "big")
        off += 3
        val = data[off:off + tlen]
        off += tlen
        if ttype in (0x01, 0x02) and len(val) >= 6:           # MAC (+ IP)
            mac = ":".join(f"{b:02x}" for b in val[:6])
        elif ttype in (0x03, 0x0b, 0x0c, 0x0d, 0x14):         # text fields
            s = val.decode("ascii", errors="ignore").strip("\x00 ").strip()
            if s and s.isprintable():
                fields.append(s)
    if mac:
        out["mac"] = mac
    if fields:
        out["info"] = sorted(set(fields))[:8]
    out["finding"] = ("Ubiquiti device leaks identity via discovery (UDP/10001): "
                      + (", ".join(out.get("info", [])[:3]) or mac or "device"))
    return out


# ── Steam / Source A2S_INFO ───────────────────────────────────────────────────
def parse_a2s(data: bytes) -> Optional[dict]:
    # 0xFFFFFFFF prefix + 'I' (0x49) header + protocol byte + C-strings.
    if len(data) < 6 or data[4] != 0x49:
        return {"responded": True, "raw_bytes": len(data)}
    body = data[6:]
    strings = body.split(b"\x00")
    out = {"responded": True, "game_server": True}
    if len(strings) >= 1:
        out["name"] = strings[0].decode("utf-8", errors="replace")[:80]
    if len(strings) >= 2:
        out["map"] = strings[1].decode("utf-8", errors="replace")[:40]
    if len(strings) >= 4:
        out["game"] = strings[3].decode("utf-8", errors="replace")[:40]
    return out


# ── Mumble / Murmur ping ──────────────────────────────────────────────────────
def parse_mumble(data: bytes) -> Optional[dict]:
    if len(data) < 24:
        return {"responded": True, "raw_bytes": len(data)}
    # bytes 0-3: version (0, major, minor, patch); 4-11: echoed ident;
    # 12-15 users, 16-19 max users, 20-23 bandwidth.
    version = f"{data[1]}.{data[2]}.{data[3]}"
    users = int.from_bytes(data[12:16], "big")
    maxusers = int.from_bytes(data[16:20], "big")
    return {"responded": True, "mumble": True, "version": version,
            "users": users, "max_users": maxusers}


# ── WS-Discovery ──────────────────────────────────────────────────────────────
def parse_ws_discovery(data: bytes) -> Optional[dict]:
    text = data.decode("utf-8", errors="replace")
    out = {"responded": True, "ws_discovery": True}
    types = _between(text, "<d:Types>", "</d:Types>") or _between(
        text, ":Types>", "</")
    xaddrs = _between(text, "<d:XAddrs>", "</d:XAddrs>") or _between(
        text, ":XAddrs>", "</")
    if types:
        out["types"] = types.strip()[:120]
    if xaddrs:
        out["xaddrs"] = xaddrs.strip()[:200]
        out["finding"] = f"WS-Discovery device at {xaddrs.strip()[:80]}"
    return out


def _between(text: str, start: str, end: str) -> Optional[str]:
    i = text.find(start)
    if i < 0:
        return None
    j = text.find(end, i + len(start))
    if j < 0:
        return None
    return text[i + len(start):j]


# ── generic ───────────────────────────────────────────────────────────────────
def parse_generic(data: bytes) -> Optional[dict]:
    return {"responded": True, "raw_bytes": len(data),
            "raw_hex": data[:48].hex()}


def _printable_run(data: bytes, minlen: int = 4) -> Optional[str]:
    best = ""
    cur: list[int] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= minlen and len(cur) > len(best):
                best = bytes(cur).decode("ascii", errors="ignore")
            cur = []
    if len(cur) >= minlen and len(cur) > len(best):
        best = bytes(cur).decode("ascii", errors="ignore")
    return best or None


_DISPATCH = {
    "snmp": parse_snmp,
    "ntp": parse_ntp,
    "ntp-monlist": parse_ntp_monlist,
    "dns": parse_dns_version,
    "netbios-ns": parse_netbios,
    "ssdp": parse_ssdp,
    "mdns": parse_mdns,
    "rpcbind": parse_rpcbind,
    "ike": parse_ike,
    "ipmi": parse_ipmi,
    "stun": parse_stun,
    "memcached": parse_memcached,
    "mssql-browser": parse_mssql_browser,
    "sip": parse_sip,
    "chargen": parse_chargen,
    "ubiquiti": parse_ubiquiti,
    "a2s": parse_a2s,
    "mumble": parse_mumble,
    "ws-discovery": parse_ws_discovery,
}


def parse_udp_response(proto: str, data: bytes) -> dict:
    """Dispatch raw reply bytes to the right parser. Always returns a dict."""
    if not data:
        return {"responded": True, "raw_bytes": 0}
    fn = _DISPATCH.get(proto, parse_generic)
    try:
        result = fn(data)
        return result if result is not None else parse_generic(data)
    except Exception:
        return parse_generic(data)
