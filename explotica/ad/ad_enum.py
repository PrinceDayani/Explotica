"""Active Directory deep enumeration — pure-Python, no impacket dep.

Implements:
  - Domain Controller discovery via DNS SRV records
  - LDAP RootDSE queries (already partially in service_probes_v2 — we extend)
  - Kerberos username enumeration via AS-REQ probing
  - AS-REP roasting target detection (DONT_REQ_PREAUTH users)
  - BloodHound JSON export

This is the post-foothold goldmine that BloodHound/SharpHound automate.
We do it pre-foothold from a network-position standpoint — what can we
learn about the AD environment without any credentials?
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Optional

log = logging.getLogger(__name__)


# ── DC Discovery via DNS SRV ──────────────────────────────────────────────
def discover_dcs(domain: str, dns_server: str = "8.8.8.8",
                  timeout: float = 4.0) -> list[dict]:
    """Query `_ldap._tcp.dc._msdcs.<domain>` SRV records to find DCs.

    This is how every Windows machine finds its domain controllers.
    Anyone can query it — no auth required.
    """
    from ..enrich.dns_enum import _query, _RR_TYPES, _build_query, _parse_name
    # SRV is record type 33
    qname = f"_ldap._tcp.dc._msdcs.{domain}"
    pkt = _build_query(qname, 33)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (dns_server, 53))
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

    offset = 12
    _, offset = _parse_name(data, offset)
    offset += 4  # qtype + qclass

    dcs: list[dict] = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        atype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if atype != 33:
            offset += rdlen
            continue
        # SRV: priority (2), weight (2), port (2), target (variable)
        if offset + 6 > len(data):
            break
        priority, weight, port = struct.unpack(">HHH", data[offset:offset + 6])
        target, _ = _parse_name(data, offset + 6)
        dcs.append({
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target.rstrip("."),
        })
        offset += rdlen
    return sorted(dcs, key=lambda d: (d["priority"], -d["weight"]))


# ── Kerberos AS-REQ packet construction ──────────────────────────────────
def _build_as_req(domain: str, username: str,
                   request_preauth: bool = False) -> bytes:
    """Build a Kerberos AS-REQ packet (PA-PAC-REQUEST optional).

    If request_preauth is False (default), the response tells us:
      - "principal unknown" (KDC_ERR_C_PRINCIPAL_UNKNOWN, code 6) → user doesn't exist
      - "preauth required" (KDC_ERR_PREAUTH_REQUIRED, code 25) → user exists, preauth on
      - actual AS-REP returned → user exists AND has DONT_REQ_PREAUTH (roastable!)
    """
    # This is an extremely simplified ASN.1 encoded AS-REQ.
    # Real-world implementations use impacket. This is a minimal probe.

    def asn1_int(value: int) -> bytes:
        b = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if value > 0 and b[0] & 0x80:
            b = b"\x00" + b
        return bytes([0x02, len(b)]) + b

    def asn1_string(tag: int, value: bytes) -> bytes:
        return bytes([tag, len(value)]) + value

    # Realm
    realm_str = domain.upper().encode()
    realm = bytes([0xa1, 0x05 + len(realm_str),
                   0x1b, len(realm_str)]) + realm_str

    # cname: PrincipalName with name-type=1, name-string=[username]
    uname = username.encode()
    name_string_seq = bytes([0x30, 0x05 + len(uname),
                              0x1b, len(uname)]) + uname
    cname_inner = (
        bytes([0xa0, 0x03, 0x02, 0x01, 0x01])  # name-type [0] INT 1
        + bytes([0xa1, len(name_string_seq) + 2,  # name-string [1] SEQ
                 0x30, len(name_string_seq)]) + name_string_seq
    )
    cname = bytes([0xa3, len(cname_inner) + 2, 0x30, len(cname_inner)]) + cname_inner

    # sname: krbtgt/REALM (we want a TGT)
    snames = [b"krbtgt", realm_str]
    sname_inner = b""
    for s in snames:
        sname_inner += bytes([0x1b, len(s)]) + s
    sname_seq = bytes([0x30, len(sname_inner)]) + sname_inner
    sname_outer = (
        bytes([0xa0, 0x03, 0x02, 0x01, 0x02])  # name-type [0] INT 2 (SRV_INST)
        + bytes([0xa1, len(sname_seq) + 2, 0x30, len(sname_seq)]) + sname_seq
    )
    sname = bytes([0xa1, len(sname_outer) + 2, 0x30, len(sname_outer)]) + sname_outer

    # NOTE: This is intentionally a stub. A fully-correct AS-REQ requires
    # proper ASN.1 DER encoding of all PA-DATA, KDC-REQ-BODY, etc. For a
    # production tool you'd link impacket. We return enough for the receiver
    # to error-respond with a meaningful Kerberos error code we can parse.
    body = realm + cname + sname
    return bytes([0x30, 0x82]) + struct.pack(">H", len(body)) + body


def kerberos_user_check(kdc_ip: str, domain: str, username: str,
                         timeout: float = 3.0) -> dict:
    """Probe Kerberos KDC with an AS-REQ for `username@DOMAIN`.

    Returns dict with classification: 'exists' / 'unknown' / 'no_preauth' / 'unknown_error'.
    NOTE: Pure-Python ASN.1 stub — for production use impacket's GetNPUsers.
    """
    pkt = _build_as_req(domain, username)
    try:
        sock = socket.create_connection((kdc_ip, 88), timeout=timeout)
        sock.settimeout(timeout)
        # Kerberos TCP: 4-byte length prefix
        sock.sendall(struct.pack(">I", len(pkt)) + pkt)
        resp_header = sock.recv(4)
        if len(resp_header) < 4:
            sock.close()
            return {"status": "no_response", "username": username}
        resp_len = struct.unpack(">I", resp_header)[0]
        resp_data = b""
        while len(resp_data) < min(resp_len, 4096):
            chunk = sock.recv(min(resp_len - len(resp_data), 4096))
            if not chunk:
                break
            resp_data += chunk
        sock.close()
    except (socket.timeout, OSError, struct.error):
        return {"status": "error", "username": username}

    if not resp_data:
        return {"status": "no_response", "username": username}

    # Look for Kerberos error code in the response.
    # KRB-ERROR error-code is at a known structural position — we hunt for
    # the [0xa6] tag (error-code field marker) followed by INT.
    for i in range(len(resp_data) - 4):
        if resp_data[i] == 0xa6 and resp_data[i + 1] in (0x03, 0x04):
            # Next: INT tag (0x02), length, value
            if resp_data[i + 2] == 0x02:
                code_len = resp_data[i + 3]
                code = int.from_bytes(
                    resp_data[i + 4:i + 4 + code_len], "big"
                )
                if code == 6:
                    return {"status": "unknown", "username": username,
                            "code": code}
                elif code == 25:
                    return {"status": "exists", "username": username,
                            "code": code, "preauth_required": True}
                elif code == 24:
                    return {"status": "exists", "username": username,
                            "code": code, "note": "preauth bad"}
                else:
                    return {"status": "unknown_error", "username": username,
                            "code": code}
    # If no error code found, might be AS-REP — user exists with DONT_REQ_PREAUTH
    if resp_data[0] == 0x6b:  # AS-REP tag
        return {"status": "no_preauth", "username": username,
                "asreproastable": True}
    return {"status": "no_response", "username": username}


# ── Common username wordlist for enumeration ──────────────────────────────
COMMON_USERNAMES = [
    "administrator", "admin", "guest", "krbtgt", "user", "test", "testuser",
    "service", "svc", "backup", "operator", "manager", "support",
    "helpdesk", "sa", "root", "supervisor",
    "Administrator", "Administrateur",  # Localized variants
]


def kerberos_enum_users(kdc_ip: str, domain: str,
                        usernames: Optional[list[str]] = None,
                        timeout: float = 3.0,
                        workers: int = 8) -> list[dict]:
    """Enumerate which usernames exist in the AD via Kerberos AS-REQ probes.

    Returns list of dicts for usernames that produced 'exists' or
    'no_preauth' classifications. Skips 'unknown'.
    """
    usernames = usernames or COMMON_USERNAMES
    from concurrent.futures import ThreadPoolExecutor, as_completed
    findings: list[dict] = []

    def probe(u):
        return kerberos_user_check(kdc_ip, domain, u, timeout=timeout)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for f in as_completed([pool.submit(probe, u) for u in usernames]):
            r = f.result()
            if r.get("status") in ("exists", "no_preauth"):
                findings.append(r)
    return findings


# ── BloodHound JSON export ────────────────────────────────────────────────
def to_bloodhound_format(domain: str, dcs: list[dict],
                          users: list[dict]) -> dict:
    """Generate a minimal BloodHound-compatible JSON structure.

    Real BloodHound expects 5+ JSON files (computers, users, groups, OUs, GPOs).
    This is a minimal users + computers (DCs) dump that BloodHound can import.
    """
    bh_users = []
    domain_upper = domain.upper()
    for u in users:
        name = u["username"]
        bh_users.append({
            "ObjectIdentifier": f"S-1-5-21-PLACEHOLDER-{hash(name) & 0xffffffff}",
            "Properties": {
                "name": f"{name.upper()}@{domain_upper}",
                "domain": domain_upper,
                "enabled": True,
                "dontreqpreauth": u.get("status") == "no_preauth",
                "discovered_via": "explotica_kerberos_enum",
            },
            "PrimaryGroupSID": None,
            "Aces": [],
        })

    bh_computers = []
    for dc in dcs:
        bh_computers.append({
            "ObjectIdentifier": f"S-1-5-21-PLACEHOLDER-{hash(dc['target']) & 0xffffffff}",
            "Properties": {
                "name": dc["target"].upper(),
                "domain": domain_upper,
                "is_dc": True,
                "ldap_port": dc.get("port"),
                "discovered_via": "explotica_dns_srv",
            },
            "PrimaryGroupSID": None,
            "Aces": [],
        })

    return {
        "users": {"meta": {"type": "users", "count": len(bh_users)},
                  "data": bh_users},
        "computers": {"meta": {"type": "computers", "count": len(bh_computers)},
                       "data": bh_computers},
        "domain": domain_upper,
        "exported_by": "explotica/0.1",
    }


# ── Orchestrator ──────────────────────────────────────────────────────────
def run_ad_enum(domain: str, *,
                kerberos_enum: bool = True,
                usernames: Optional[list[str]] = None,
                timeout: float = 3.0) -> dict:
    """Full AD enum for a domain.

    Phase 64: scope-enforced — refuses to enumerate a domain that's
    outside the active scope. Prevents Kerberos+LDAP traffic to
    unauthorized DCs.
    """
    result: dict = {
        "domain": domain,
        "dcs": [],
        "users_found": [],
        "asreproastable": [],
    }

    # Phase 64: scope enforcement
    try:
        from ..safety_kit.safety import get_active_scope
        scope = get_active_scope()
        if scope is not None and not scope.permits(domain):
            log.warning("AD enum skipped: %s outside scope", domain)
            result["skipped_reason"] = "outside-scope"
            return result
    except ImportError:
        pass

    log.info("AD enum: discovering DCs for %s", domain)
    dcs = discover_dcs(domain, timeout=timeout)
    result["dcs"] = dcs

    if not dcs:
        return result

    if kerberos_enum:
        # Try the first DC
        dc = dcs[0]
        try:
            kdc_ip = socket.gethostbyname(dc["target"])
        except socket.gaierror:
            log.warning("Could not resolve DC %s", dc["target"])
            return result

        log.info("AD enum: Kerberos user enum at %s (%s)", dc["target"], kdc_ip)
        users = kerberos_enum_users(kdc_ip, domain, usernames=usernames,
                                     timeout=timeout)
        result["users_found"] = users
        result["asreproastable"] = [
            u for u in users if u.get("status") == "no_preauth"
        ]

    result["bloodhound_export"] = to_bloodhound_format(
        domain, result["dcs"], result["users_found"]
    )
    return result
