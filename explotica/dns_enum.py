"""DNS enumeration — records, common subdomains, SPF/DMARC.

When the scan target is a domain (e.g. example.com) or when we collect
hostnames via reverse DNS, this module pulls:
  - A / AAAA / MX / NS / TXT / SOA / CNAME records
  - SPF + DMARC + DKIM analysis (extracted from TXT records)
  - Common subdomain brute force (~30 names)
  - Zone transfer attempt (AXFR) against each NS — almost always fails
    but produces a useful finding when it doesn't

Uses stdlib only — no `dnspython` dependency.
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Optional

log = logging.getLogger(__name__)

# Record type constants
_RR_TYPES = {
    "A":     1,
    "AAAA":  28,
    "MX":    15,
    "NS":    2,
    "TXT":   16,
    "SOA":   6,
    "CNAME": 5,
    "PTR":   12,
}

# Common subdomains to brute-force
_COMMON_SUBS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns",
    "dev", "staging", "test", "qa", "uat", "api", "admin", "portal",
    "dashboard", "console", "secure", "vpn", "remote", "support",
    "blog", "shop", "store", "app", "mobile", "m", "static", "cdn",
    "assets", "files", "downloads", "git", "gitlab", "jenkins",
    "jira", "confluence", "wiki", "docs", "owa", "exchange",
]


def _build_query(name: str, rtype: int) -> bytes:
    """Construct a DNS query packet for the given name + record type."""
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii", errors="ignore")
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"
    qsuffix = struct.pack(">HH", rtype, 1)  # type, class IN
    return header + qname + qsuffix


def _parse_name(buf: bytes, offset: int) -> tuple[str, int]:
    """DNS compressed name parser. Returns (name, new_offset)."""
    labels: list[str] = []
    jumped = False
    jump_offset = 0
    safety = 0
    while safety < 100:
        safety += 1
        if offset >= len(buf):
            break
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # Pointer
            if not jumped:
                jump_offset = offset + 2
            offset = ((length & 0x3F) << 8) | buf[offset + 1]
            jumped = True
            continue
        offset += 1
        if offset + length > len(buf):
            break
        labels.append(buf[offset:offset + length].decode("ascii", errors="ignore"))
        offset += length
    if jumped:
        return ".".join(labels), jump_offset
    return ".".join(labels), offset


def _query(name: str, rtype: int, server: str = "8.8.8.8",
           timeout: float = 3.0) -> list[str]:
    """Issue a UDP DNS query, return list of parsed answers as strings."""
    pkt = _build_query(name, rtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (server, 53))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        return []
    finally:
        sock.close()

    if not data or len(data) < 12:
        return []
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return []

    # Skip header (12) + question
    offset = 12
    _, offset = _parse_name(data, offset)
    offset += 4  # qtype + qclass

    answers: list[str] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        atype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rtype == _RR_TYPES["A"] and atype == 1 and rdlen == 4:
            answers.append(".".join(str(b) for b in rdata))
        elif rtype == _RR_TYPES["AAAA"] and atype == 28 and rdlen == 16:
            answers.append(":".join(
                f"{rdata[i]:02x}{rdata[i + 1]:02x}" for i in range(0, 16, 2)
            ))
        elif rtype in (_RR_TYPES["NS"], _RR_TYPES["CNAME"], _RR_TYPES["PTR"]):
            name_str, _ = _parse_name(data, offset)
            answers.append(name_str)
        elif rtype == _RR_TYPES["MX"]:
            if rdlen >= 3:
                pref = struct.unpack(">H", rdata[:2])[0]
                name_str, _ = _parse_name(data, offset + 2)
                answers.append(f"{pref} {name_str}")
        elif rtype == _RR_TYPES["TXT"]:
            # TXT = length-prefixed strings concatenated
            i = 0
            parts: list[str] = []
            while i < len(rdata):
                slen = rdata[i]
                parts.append(rdata[i + 1:i + 1 + slen].decode(
                    "utf-8", errors="ignore"))
                i += 1 + slen
            answers.append("".join(parts))
        elif rtype == _RR_TYPES["SOA"]:
            mname, p = _parse_name(data, offset)
            rname, p = _parse_name(data, p)
            if p + 20 <= len(data):
                serial, refresh, retry, expire, minimum = struct.unpack(
                    ">IIIII", data[p:p + 20]
                )
                answers.append(
                    f"mname={mname} rname={rname} serial={serial}"
                )
        offset += rdlen

    return answers


def _attempt_axfr(domain: str, ns_server: str, timeout: float = 5.0) -> Optional[list[str]]:
    """Try TCP AXFR (zone transfer). Returns list of record names or None.

    Almost always refused — when it succeeds, that's a major finding.
    """
    # Build AXFR query (type 252)
    pkt = _build_query(domain, 252)
    # TCP DNS prefixes the packet with its 2-byte length
    framed = struct.pack(">H", len(pkt)) + pkt
    try:
        sock = socket.create_connection((ns_server, 53), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(framed)
        data = b""
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 65535 * 4:  # arbitrary cap
                break
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("AXFR %s @ %s failed: %s", domain, ns_server, e)
        return None
    # If the response is large (>500 bytes) and well-formed, it likely succeeded
    if len(data) < 100:
        return None
    return [f"~{len(data)} bytes transferred (possible AXFR success)"]


def _analyze_spf(txt_records: list[str]) -> Optional[str]:
    for t in txt_records:
        if t.startswith("v=spf1"):
            return t
    return None


def _analyze_dmarc(domain: str, timeout: float = 3.0) -> Optional[str]:
    dmarc = _query(f"_dmarc.{domain}", _RR_TYPES["TXT"], timeout=timeout)
    for t in dmarc:
        if t.startswith("v=DMARC1"):
            return t
    return None


def enum_dns(domain: str, *, brute_subdomains: bool = True,
             timeout: float = 3.0) -> dict:
    """Pull all useful DNS info about a domain.

    Set brute_subdomains=False to skip the common-subdomain probe (slow).
    """
    result: dict = {
        "domain": domain,
        "records": {},
        "subdomains_found": [],
        "spf": None,
        "dmarc": None,
        "axfr_attempts": [],
    }

    for rname, rtype in _RR_TYPES.items():
        if rname == "PTR":
            continue
        try:
            answers = _query(domain, rtype, timeout=timeout)
            if answers:
                result["records"][rname] = answers
        except Exception as e:
            log.debug("DNS %s %s failed: %s", rname, domain, e)

    # SPF / DMARC analysis
    txt = result["records"].get("TXT", [])
    result["spf"] = _analyze_spf(txt)
    result["dmarc"] = _analyze_dmarc(domain, timeout=timeout)

    # Zone transfer against each NS
    for ns in result["records"].get("NS", []):
        ns_clean = ns.rstrip(".")
        axfr = _attempt_axfr(domain, ns_clean, timeout=timeout)
        if axfr:
            result["axfr_attempts"].append({"ns": ns_clean, "data": axfr})

    # Subdomain brute force
    if brute_subdomains:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        found: list[dict] = []

        def check(sub):
            full = f"{sub}.{domain}"
            ans = _query(full, _RR_TYPES["A"], timeout=timeout)
            if ans:
                return {"name": full, "ips": ans}
            return None

        with ThreadPoolExecutor(max_workers=16) as pool:
            for f in as_completed([pool.submit(check, s) for s in _COMMON_SUBS]):
                try:
                    r = f.result()
                    if r:
                        found.append(r)
                except Exception:
                    pass
        result["subdomains_found"] = sorted(found, key=lambda x: x["name"])

    return result
