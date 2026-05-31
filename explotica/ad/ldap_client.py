"""Authenticated LDAP v3 client — pure-Python, no external dependency.

Phase 70A. The codebase previously had only an *anonymous* RootDSE probe
(`service_probes_v2.probe_ldap_rootdse`). Every credentialed AD capability
worth having — real BloodHound collection, ADCS certificate-template
enumeration, delegation/ticket-risk analysis — needs to actually *bind* to
the directory and *read object attributes* (notably the binary `objectSid`,
`objectGUID`, and `nTSecurityDescriptor`). This module provides that.

What it implements:
  - A compact, self-contained BER codec for the LDAP subset (RFC 4511).
  - RFC 4515 string filter -> BER compiler (equality / presence / substring /
    and / or / not).
  - Simple bind (cleartext) — works over plain 389 and LDAPS 636.
  - NTLM bind (NTLMv2) over the SASL ``GSS-SPNEGO`` mechanism — the
    Kerberos-less authentication path Windows clients use. We send a bare
    NTLMSSP token, which Active Directory's GSS-SPNEGO acceptor takes as the
    initial context token (the same behaviour impacket relies on).
  - Paged search (control OID 1.2.840.113556.1.4.319) with cookie loop, so a
    50k-object directory streams back instead of hitting the server page cap.
  - Binary attribute decoders: objectSid -> S-1-5-…, objectGUID -> GUID
    string, Windows FILETIME -> aware datetime, userAccountControl -> flag set.

Honesty notes (consistent with the project's impacket-fallback pattern):
  - The BER/NTLMv2/decoder logic is exercised by offline unit tests against
    RFC 4511 / MS-NLMP §4.2.4 / known SID+GUID byte patterns.
  - The live bind/search path talks to a real DC and cannot be self-verified
    here; failures surface as `LdapError` with the server's resultCode rather
    than being swallowed.
  - MD4 is implemented in-module because OpenSSL 3.0 (default on current
    Windows 11 / most Linux) dropped it from ``hashlib`` — relying on
    ``hashlib.new('md4')`` is a silent production break.

This module deliberately does NOT depend on ldap3/impacket. If they are
installed a caller may prefer them, but Explotica must work on a bare Python.
"""

from __future__ import annotations

import hmac
import logging
import os
import socket
import ssl
import struct
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════
# BER codec (the LDAP subset of X.690)
# ══════════════════════════════════════════════════════════════════════════
# Tag bytes we use. class<<6 | constructed<<5 | number.
TAG_BOOL = 0x01
TAG_INT = 0x02
TAG_OCTET = 0x04
TAG_ENUM = 0x0A
TAG_SEQ = 0x30          # universal SEQUENCE, constructed
TAG_SET = 0x31          # universal SET, constructed


def ber_len(length: int) -> bytes:
    """Encode a definite-form BER length."""
    if length < 0x80:
        return bytes([length])
    b = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(value)) + value


def enc_int(value: int, tag: int = TAG_INT) -> bytes:
    """Encode a (non-negative, in practice) INTEGER in minimal two's complement."""
    if value == 0:
        v = b"\x00"
    else:
        length = (value.bit_length() + 8) // 8  # leave room for sign bit
        v = value.to_bytes(length, "big", signed=True)
        while len(v) > 1 and v[0] == 0x00 and not (v[1] & 0x80):
            v = v[1:]
    return ber_tlv(tag, v)


def enc_enum(value: int) -> bytes:
    return enc_int(value, tag=TAG_ENUM)


def enc_octet(value, tag: int = TAG_OCTET) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return ber_tlv(tag, value)


def enc_bool(value: bool, tag: int = TAG_BOOL) -> bytes:
    return ber_tlv(tag, b"\xff" if value else b"\x00")


def enc_seq(*items: bytes, tag: int = TAG_SEQ) -> bytes:
    return ber_tlv(tag, b"".join(items))


def enc_set(*items: bytes, tag: int = TAG_SET) -> bytes:
    return ber_tlv(tag, b"".join(items))


def decode_len(data: bytes, pos: int) -> tuple[int, int]:
    """Return (length, position-after-length)."""
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    length = int.from_bytes(data[pos:pos + n], "big")
    return length, pos + n


def decode_tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    """Decode one TLV. Return (tag, value_bytes, position-after-value)."""
    tag = data[pos]
    length, vpos = decode_len(data, pos + 1)
    return tag, data[vpos:vpos + length], vpos + length


def iter_tlv(data: bytes):
    """Iterate top-level TLVs of a constructed value."""
    pos = 0
    while pos < len(data):
        tag, value, pos = decode_tlv(data, pos)
        yield tag, value


def decode_int(value: bytes) -> int:
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=True)


# ══════════════════════════════════════════════════════════════════════════
# RFC 4515 string filter -> BER Filter
# ══════════════════════════════════════════════════════════════════════════
# Filter CHOICE context tags (constructed unless noted):
F_AND = 0xA0
F_OR = 0xA1
F_NOT = 0xA2
F_EQ = 0xA3
F_SUBSTR = 0xA4
F_GE = 0xA5
F_LE = 0xA6
F_PRESENT = 0x87        # primitive
F_APPROX = 0xA8


def _unescape(s: str) -> bytes:
    """RFC 4515 \\xx hex unescaping -> raw bytes."""
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 2 < len(s) + 1 and i + 2 <= len(s):
            out.append(int(s[i + 1:i + 3], 16))
            i += 3
        else:
            out += s[i].encode("utf-8")
            i += 1
    return bytes(out)


def compile_filter(expr: str) -> bytes:
    """Compile an RFC 4515 filter string into BER.

    Supports: (attr=value), (attr=*) presence, (attr=a*b*c) substrings,
    (&f1f2…), (|f1f2…), (!f), (attr>=v), (attr<=v).
    """
    expr = expr.strip()
    if not (expr.startswith("(") and expr.endswith(")")):
        expr = "(" + expr + ")"
    node, end = _parse_filter(expr, 0)
    return node


def _parse_filter(s: str, i: int) -> tuple[bytes, int]:
    assert s[i] == "(", f"expected '(' at {i}: {s!r}"
    i += 1
    if s[i] in "&|!":
        op = s[i]
        i += 1
        children: list[bytes] = []
        while s[i] == "(":
            child, i = _parse_filter(s, i)
            children.append(child)
        assert s[i] == ")", f"expected ')' at {i}"
        i += 1
        if op == "&":
            return ber_tlv(F_AND, b"".join(children)), i
        if op == "|":
            return ber_tlv(F_OR, b"".join(children)), i
        return ber_tlv(F_NOT, children[0]), i

    # leaf: attr OP value )
    j = i
    while s[j] not in "=<>~":
        j += 1
    attr = s[i:j]
    relop = s[j]
    if relop in "<>~":
        # >=, <=, ~=
        assert s[j + 1] == "=", "expected '=' after relop"
        j += 2
    else:
        j += 1
    k = s.index(")", j)
    raw_value = s[j:k]
    i = k + 1

    if relop == "=" and raw_value == "*":
        return ber_tlv(F_PRESENT, attr.encode("utf-8")), i
    if relop == "=" and "*" in raw_value:
        return _substring_filter(attr, raw_value), i

    val = _unescape(raw_value)
    ava = enc_octet(attr) + enc_octet(val)
    tag = {"=": F_EQ, ">": F_GE, "<": F_LE, "~": F_APPROX}[relop]
    return ber_tlv(tag, ava), i


def _substring_filter(attr: str, pattern: str) -> bytes:
    parts = pattern.split("*")
    subs = b""
    # initial
    if parts[0]:
        subs += enc_octet(_unescape(parts[0]), tag=0x80)
    # any (middle)
    for mid in parts[1:-1]:
        if mid:
            subs += enc_octet(_unescape(mid), tag=0x81)
    # final
    if parts[-1]:
        subs += enc_octet(_unescape(parts[-1]), tag=0x82)
    return ber_tlv(F_SUBSTR, enc_octet(attr) + ber_tlv(TAG_SEQ, subs))


# ══════════════════════════════════════════════════════════════════════════
# MD4 (pure Python — OpenSSL 3 dropped it from hashlib)
# ══════════════════════════════════════════════════════════════════════════
def md4(data: bytes) -> bytes:
    """RFC 1320 MD4. Returns the 16-byte digest."""
    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    msg = bytearray(data)
    orig_len_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len_bits)

    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d

        def F(x, y, z):
            return (x & y) | (~x & z)

        def G(x, y, z):
            return (x & y) | (x & z) | (y & z)

        def H(x, y, z):
            return x ^ y ^ z

        for i in range(4):
            k = i * 4
            a = lrot(a + F(b, c, d) + X[k], 3)
            d = lrot(d + F(a, b, c) + X[k + 1], 7)
            c = lrot(c + F(d, a, b) + X[k + 2], 11)
            b = lrot(b + F(c, d, a) + X[k + 3], 19)
        for i in range(4):
            a = lrot(a + G(b, c, d) + X[i] + 0x5A827999, 3)
            d = lrot(d + G(a, b, c) + X[i + 4] + 0x5A827999, 5)
            c = lrot(c + G(d, a, b) + X[i + 8] + 0x5A827999, 9)
            b = lrot(b + G(c, d, a) + X[i + 12] + 0x5A827999, 13)
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(0, 16, 4):
            a = lrot(a + H(b, c, d) + X[order[i]] + 0x6ED9EBA1, 3)
            d = lrot(d + H(a, b, c) + X[order[i + 1]] + 0x6ED9EBA1, 9)
            c = lrot(c + H(d, a, b) + X[order[i + 2]] + 0x6ED9EBA1, 11)
            b = lrot(b + H(c, d, a) + X[order[i + 3]] + 0x6ED9EBA1, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


# ══════════════════════════════════════════════════════════════════════════
# NTLM (NTLMv2) — MS-NLMP
# ══════════════════════════════════════════════════════════════════════════
NTLMSSP_SIG = b"NTLMSSP\x00"

# Negotiate flags we advertise (Unicode, NTLM, Always Sign, Target Info,
# Extended Session Security, 56/128-bit).
_NEG_FLAGS = (
    0x00000001  # NEGOTIATE_UNICODE
    | 0x00000200  # NEGOTIATE_NTLM
    | 0x00008000  # NEGOTIATE_ALWAYS_SIGN
    | 0x00080000  # NEGOTIATE_EXTENDED_SESSIONSECURITY
    | 0x00800000  # NEGOTIATE_TARGET_INFO
    | 0x20000000  # NEGOTIATE_56
    | 0x80000000  # NEGOTIATE_128
)


def ntlm_negotiate() -> bytes:
    """Build an NTLMSSP NEGOTIATE (Type 1) message."""
    return (
        NTLMSSP_SIG
        + struct.pack("<I", 1)            # MessageType = 1
        + struct.pack("<I", _NEG_FLAGS)
        + struct.pack("<HHI", 0, 0, 0)    # DomainName fields (empty)
        + struct.pack("<HHI", 0, 0, 0)    # Workstation fields (empty)
    )


def parse_challenge(msg: bytes) -> dict:
    """Parse an NTLMSSP CHALLENGE (Type 2). Returns server challenge + target info."""
    if not msg.startswith(NTLMSSP_SIG) or struct.unpack("<I", msg[8:12])[0] != 2:
        raise LdapError("not an NTLMSSP CHALLENGE message")
    server_challenge = msg[24:32]
    ti_len, _, ti_off = struct.unpack("<HHI", msg[40:48])
    target_info = msg[ti_off:ti_off + ti_len]
    return {"server_challenge": server_challenge, "target_info": target_info}


def _ntowf_v2(password: str, user: str, domain: str) -> bytes:
    nt_hash = md4(password.encode("utf-16-le"))
    ident = (user.upper() + domain).encode("utf-16-le")
    return hmac.new(nt_hash, ident, "md5").digest()


def ntlmv2_response(user: str, password: str, domain: str,
                    server_challenge: bytes, target_info: bytes, *,
                    client_challenge: bytes, timestamp: bytes
                    ) -> tuple[bytes, bytes, bytes]:
    """Compute the NTLMv2 NtChallengeResponse + LmChallengeResponse.

    Returns (nt_proof_str, nt_response, lm_response). Factored out of
    `ntlm_authenticate` so the cryptographic core can be unit-tested against
    the worked example in MS-NLMP §4.2.4 without constructing a full message.
    """
    responsekey_nt = _ntowf_v2(password, user, domain)
    # temp = Responserversion(1) HiVers(1) Reserved(6) timestamp(8)
    #        clientchallenge(8) Reserved(4) targetinfo Reserved(4)
    temp = (
        b"\x01\x01"
        + b"\x00" * 6
        + timestamp
        + client_challenge
        + b"\x00" * 4
        + target_info
        + b"\x00" * 4
    )
    nt_proof = hmac.new(responsekey_nt, server_challenge + temp, "md5").digest()
    nt_response = nt_proof + temp
    # LMv2 response (vestigial with extended session security, but well-formed).
    lm_proof = hmac.new(
        responsekey_nt, server_challenge + client_challenge, "md5"
    ).digest()
    lm_response = lm_proof + client_challenge
    return nt_proof, nt_response, lm_response


def ntlm_authenticate(user: str, password: str, domain: str,
                      challenge: dict, *,
                      client_challenge: Optional[bytes] = None,
                      timestamp: Optional[bytes] = None) -> bytes:
    """Build an NTLMSSP AUTHENTICATE (Type 3) message using NTLMv2.

    `client_challenge` and `timestamp` are injectable for deterministic
    testing against MS-NLMP §4.2.4; otherwise they are generated/derived.
    """
    server_challenge = challenge["server_challenge"]
    target_info = challenge["target_info"]
    if client_challenge is None:
        client_challenge = os.urandom(8)
    if timestamp is None:
        # Windows FILETIME: 100ns ticks since 1601-01-01.
        now = datetime.now(timezone.utc)
        ft = int((now - _FILETIME_EPOCH).total_seconds() * 10_000_000)
        timestamp = struct.pack("<Q", ft)

    _, nt_response, lm_response = ntlmv2_response(
        user, password, domain, server_challenge, target_info,
        client_challenge=client_challenge, timestamp=timestamp)

    domain_b = domain.encode("utf-16-le")
    user_b = user.encode("utf-16-le")
    ws_b = b""

    # Lay out payload after the fixed 64-byte header + 8-byte version block.
    base = 72
    chunks = []
    offset = base

    def field(payload: bytes):
        nonlocal offset
        hdr = struct.pack("<HHI", len(payload), len(payload), offset)
        chunks.append(payload)
        offset += len(payload)
        return hdr

    lm_f = field(lm_response)
    nt_f = field(nt_response)
    dom_f = field(domain_b)
    usr_f = field(user_b)
    ws_f = field(ws_b)
    sk_f = struct.pack("<HHI", 0, 0, offset)  # no exported session key

    version = b"\x0a\x00\x63\x45\x00\x00\x00\x0f"  # 10.0 build 17763, NTLM rev 15

    header = (
        NTLMSSP_SIG
        + struct.pack("<I", 3)            # MessageType = 3
        + lm_f + nt_f + dom_f + usr_f + ws_f + sk_f
        + struct.pack("<I", _NEG_FLAGS)
        + version
    )
    return header + b"".join(chunks)


# ══════════════════════════════════════════════════════════════════════════
# Binary attribute decoders
# ══════════════════════════════════════════════════════════════════════════
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def decode_sid(blob: bytes) -> str:
    """Decode a binary objectSid into S-1-… string form."""
    if len(blob) < 8:
        return ""
    revision = blob[0]
    sub_count = blob[1]
    authority = int.from_bytes(blob[2:8], "big")
    sid = f"S-{revision}-{authority}"
    pos = 8
    for _ in range(sub_count):
        if pos + 4 > len(blob):
            break
        sid += "-" + str(struct.unpack("<I", blob[pos:pos + 4])[0])
        pos += 4
    return sid


def decode_guid(blob: bytes) -> str:
    """Decode a binary objectGUID (mixed-endian) into canonical GUID string."""
    if len(blob) != 16:
        return ""
    a, b, c = struct.unpack("<IHH", blob[0:8])
    d = struct.unpack(">H", blob[8:10])[0]
    e = blob[10:16].hex()
    return f"{a:08x}-{b:04x}-{c:04x}-{d:04x}-{e}"


def decode_filetime(value) -> Optional[datetime]:
    """Decode a Windows FILETIME (string of ticks, or 8 raw bytes) -> datetime."""
    try:
        ticks = (struct.unpack("<Q", value)[0]
                 if isinstance(value, (bytes, bytearray)) and len(value) == 8
                 else int(value))
    except (ValueError, struct.error):
        return None
    if ticks in (0, 0x7FFFFFFFFFFFFFFF):
        return None  # "never" sentinels
    return _FILETIME_EPOCH + timedelta(microseconds=ticks / 10)


# userAccountControl flag bits (MS-ADTS 2.2.16).
UAC_FLAGS = {
    0x00000002: "ACCOUNTDISABLE",
    0x00000010: "LOCKOUT",
    0x00000020: "PASSWD_NOTREQD",
    0x00000200: "NORMAL_ACCOUNT",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT",
    0x00002000: "SERVER_TRUST_ACCOUNT",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00020000: "MNS_LOGON_ACCOUNT",
    0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION",       # unconstrained delegation
    0x00100000: "NOT_DELEGATED",
    0x00200000: "USE_DES_KEY_ONLY",
    0x00400000: "DONT_REQ_PREAUTH",             # AS-REP roastable
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",  # constrained w/ protocol transition
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",      # RODC
}


def decode_uac(value) -> dict:
    """Decode userAccountControl -> {"raw": int, "flags": [names]}."""
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return {"raw": None, "flags": []}
    return {"raw": raw, "flags": [name for bit, name in UAC_FLAGS.items()
                                  if raw & bit]}


# Attributes we always want back as raw bytes (not utf-8 decoded).
BINARY_ATTRS = {"objectsid", "objectguid", "ntsecuritydescriptor",
                "msds-allowedtodelegateto", "cacertificate",
                "usercertificate", "mspki-certificate-name-flag"}


# ══════════════════════════════════════════════════════════════════════════
# The client
# ══════════════════════════════════════════════════════════════════════════
class LdapError(Exception):
    pass


# RFC 4511 search scopes.
SCOPE_BASE = 0
SCOPE_ONELEVEL = 1
SCOPE_SUBTREE = 2

PAGED_CONTROL_OID = "1.2.840.113556.1.4.319"

_RESULT_MEANINGS = {
    0: "success", 1: "operationsError", 2: "protocolError",
    7: "authMethodNotSupported", 8: "strongerAuthRequired",
    14: "saslBindInProgress", 32: "noSuchObject", 49: "invalidCredentials",
    50: "insufficientAccessRights",
}


class LdapClient:
    """A minimal authenticated LDAP v3 client.

    Usage:
        c = LdapClient("dc01.corp.local", use_ssl=False)
        c.connect()
        c.bind_ntlm("CORP", "svc_user", "Passw0rd!")     # or bind_simple(...)
        base = c.root_dse()["defaultNamingContext"][0]
        for entry in c.paged_search(base, "(objectClass=user)",
                                    ["sAMAccountName", "objectSid"]):
            ...
        c.close()
    """

    def __init__(self, host: str, port: Optional[int] = None, *,
                 use_ssl: bool = False, timeout: float = 8.0):
        self.host = host
        self.use_ssl = use_ssl
        self.port = port or (636 if use_ssl else 389)
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._msgid = 0
        self.bound = False
        self.bound_as: Optional[str] = None

    # ── connection ──────────────────────────────────────────────────────
    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), self.timeout)
        raw.settimeout(self.timeout)
        if self.use_ssl:
            ctx = ssl._create_unverified_context()  # AD certs are usually self/AD-CA signed
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
        self.sock = raw

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _next_id(self) -> int:
        self._msgid += 1
        return self._msgid

    def _send(self, protocol_op: bytes, controls: bytes = b"") -> int:
        mid = self._next_id()
        msg = enc_int(mid) + protocol_op
        if controls:
            msg += controls
        self.sock.sendall(ber_tlv(TAG_SEQ, msg))
        return mid

    def _recv_message(self) -> tuple[int, int, bytes, bytes]:
        """Read one LDAPMessage. Return (msgid, op_tag, op_value, controls)."""
        hdr = self._recv_exact(2)
        if hdr[0] != TAG_SEQ:
            raise LdapError(f"unexpected top tag {hdr[0]:#x}")
        if hdr[1] < 0x80:
            length = hdr[1]
        else:
            n = hdr[1] & 0x7F
            length = int.from_bytes(self._recv_exact(n), "big")
        body = self._recv_exact(length)
        # body = INTEGER msgid, protocolOp, [controls]
        tag, mid_v, pos = decode_tlv(body, 0)
        msgid = decode_int(mid_v)
        op_tag, op_value, pos = decode_tlv(body, pos)
        controls = body[pos:]
        return msgid, op_tag, op_value, controls

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise LdapError("connection closed by server")
            buf += chunk
        return buf

    # ── binds ───────────────────────────────────────────────────────────
    def bind_simple(self, dn: str, password: str) -> dict:
        """Simple (cleartext) bind. Use over LDAPS in production."""
        auth = enc_octet(password, tag=0x80)  # simple [0]
        bind_req = ber_tlv(0x60, enc_int(3) + enc_octet(dn) + auth)
        self._send(bind_req)
        result = self._read_bind_result()
        if result["result_code"] != 0:
            raise LdapError(
                f"simple bind failed: {result['result_code']} "
                f"({result['meaning']}) {result.get('message','')}")
        self.bound = True
        self.bound_as = dn
        return result

    def bind_ntlm(self, domain: str, user: str, password: str) -> dict:
        """NTLMv2 bind via SASL GSS-SPNEGO (two round trips)."""
        # Round 1: send NEGOTIATE, expect saslBindInProgress + CHALLENGE.
        self._send(self._sasl_bind_op(ntlm_negotiate()))
        r1 = self._read_bind_result()
        if r1["result_code"] not in (0, 14):  # 14 = saslBindInProgress
            raise LdapError(
                f"NTLM negotiate rejected: {r1['result_code']} "
                f"({r1['meaning']})")
        if not r1.get("sasl_creds"):
            raise LdapError("server returned no NTLM challenge")
        challenge = parse_challenge(r1["sasl_creds"])

        # Round 2: send AUTHENTICATE.
        auth_msg = ntlm_authenticate(user, password, domain, challenge)
        self._send(self._sasl_bind_op(auth_msg))
        r2 = self._read_bind_result()
        if r2["result_code"] != 0:
            raise LdapError(
                f"NTLM bind failed: {r2['result_code']} ({r2['meaning']})")
        self.bound = True
        self.bound_as = f"{domain}\\{user}"
        return r2

    def _sasl_bind_op(self, sasl_token: bytes) -> bytes:
        # authentication CHOICE sasl [3] SaslCredentials ::= SEQ {mech, creds}
        sasl_creds = enc_octet("GSS-SPNEGO") + enc_octet(sasl_token)
        auth = ber_tlv(0xA3, sasl_creds)
        return ber_tlv(0x60, enc_int(3) + enc_octet("") + auth)

    def _read_bind_result(self) -> dict:
        msgid, op_tag, op_value, _ = self._recv_message()
        if op_tag != 0x61:  # BindResponse [APPLICATION 1]
            raise LdapError(f"expected BindResponse, got tag {op_tag:#x}")
        return self._parse_ldap_result(op_value, want_sasl=True)

    @staticmethod
    def _parse_ldap_result(value: bytes, *, want_sasl: bool = False) -> dict:
        # LDAPResult COMPONENTS: resultCode ENUM, matchedDN, errorMessage,
        # [3] referral OPTIONAL, then [7] serverSaslCreds OPTIONAL.
        pos = 0
        tag, rc_v, pos = decode_tlv(value, pos)
        result_code = decode_int(rc_v)
        tag, matched_v, pos = decode_tlv(value, pos)
        tag, msg_v, pos = decode_tlv(value, pos)
        out = {
            "result_code": result_code,
            "meaning": _RESULT_MEANINGS.get(result_code, f"code {result_code}"),
            "matched_dn": matched_v.decode("utf-8", "replace"),
            "message": msg_v.decode("utf-8", "replace"),
        }
        while pos < len(value):
            tag, v, pos = decode_tlv(value, pos)
            if tag == 0x87 and want_sasl:  # serverSaslCreds [7]
                out["sasl_creds"] = v
        return out

    # ── search ──────────────────────────────────────────────────────────
    def search(self, base_dn: str, filter_str: str,
               attributes: Optional[list[str]] = None, *,
               scope: int = SCOPE_SUBTREE, size_limit: int = 0,
               time_limit: int = 0) -> list[dict]:
        """One-shot (non-paged) search. Returns list of entry dicts."""
        return list(self._search_once(base_dn, filter_str, attributes or [],
                                      scope, size_limit, time_limit,
                                      cookie=b"", page_size=0)[0])

    def paged_search(self, base_dn: str, filter_str: str,
                     attributes: Optional[list[str]] = None, *,
                     scope: int = SCOPE_SUBTREE, page_size: int = 500,
                     max_entries: int = 0) -> list[dict]:
        """Paged search with cookie loop. Returns all entries.

        max_entries: stop after this many (0 = unlimited). Honest cap — if we
        truncate, the caller can see len() vs. the server total.
        """
        cookie = b""
        entries: list[dict] = []
        while True:
            page, cookie = self._search_once(
                base_dn, filter_str, attributes or [], scope,
                0, 0, cookie=cookie, page_size=page_size)
            entries.extend(page)
            if max_entries and len(entries) >= max_entries:
                log.info("paged_search hit max_entries cap (%d)", max_entries)
                return entries[:max_entries]
            if not cookie:
                break
        return entries

    def _search_once(self, base_dn, filter_str, attributes, scope,
                     size_limit, time_limit, *, cookie, page_size):
        attr_seq = b"".join(enc_octet(a) for a in attributes)
        req = ber_tlv(0x63, (                       # SearchRequest [APP 3]
            enc_octet(base_dn)
            + enc_enum(scope)
            + enc_enum(0)                           # derefAliases = never
            + enc_int(size_limit)
            + enc_int(time_limit)
            + enc_bool(False)                       # typesOnly
            + compile_filter(filter_str)
            + ber_tlv(TAG_SEQ, attr_seq)
        ))
        controls = b""
        if page_size:
            ctrl_val = ber_tlv(TAG_SEQ, enc_int(page_size) + enc_octet(cookie))
            control = ber_tlv(TAG_SEQ,
                              enc_octet(PAGED_CONTROL_OID)
                              + enc_octet(ctrl_val))
            controls = ber_tlv(0xA0, control)        # controls [0]
        self._send(req, controls)

        entries: list[dict] = []
        next_cookie = b""
        while True:
            msgid, op_tag, op_value, ctrls = self._recv_message()
            if op_tag == 0x64:                       # SearchResultEntry [APP 4]
                entries.append(self._parse_entry(op_value))
            elif op_tag == 0x65:                     # SearchResultDone [APP 5]
                res = self._parse_ldap_result(op_value)
                if res["result_code"] not in (0, 4):  # 4 = sizeLimitExceeded
                    raise LdapError(
                        f"search failed: {res['result_code']} "
                        f"({res['meaning']})")
                next_cookie = self._extract_page_cookie(ctrls)
                break
            elif op_tag == 0x73:                     # SearchResultReference
                continue                              # skip referrals
            else:
                log.debug("ignoring unexpected op tag %#x in search", op_tag)
        return entries, next_cookie

    @staticmethod
    def _parse_entry(value: bytes) -> dict:
        # SearchResultEntry ::= SEQ { objectName LDAPDN, attributes PAL }
        pos = 0
        tag, dn_v, pos = decode_tlv(value, pos)
        tag, attrs_v, pos = decode_tlv(value, pos)
        attributes: dict[str, list] = {}
        for _, attr_tlv in iter_tlv(attrs_v):
            apos = 0
            t, type_v, apos = decode_tlv(attr_tlv, apos)
            attr_name = type_v.decode("utf-8", "replace")
            t, vals_v, apos = decode_tlv(attr_tlv, apos)
            values = []
            is_binary = attr_name.lower() in BINARY_ATTRS
            for _, val in iter_tlv(vals_v):
                values.append(val if is_binary
                              else val.decode("utf-8", "replace"))
            attributes[attr_name] = values
        return {"dn": dn_v.decode("utf-8", "replace"),
                "attributes": attributes}

    @staticmethod
    def _extract_page_cookie(controls: bytes) -> bytes:
        if not controls:
            return b""
        # controls [0] SEQ OF Control
        tag, ctrl_seq, _ = decode_tlv(controls, 0)
        if tag != 0xA0:
            return b""
        for _, control in iter_tlv(ctrl_seq):
            pos = 0
            t, oid_v, pos = decode_tlv(control, pos)
            if oid_v.decode("utf-8", "replace") != PAGED_CONTROL_OID:
                continue
            # optional criticality boolean may precede the value
            t, v, pos = decode_tlv(control, pos)
            if t == TAG_BOOL:
                t, v, pos = decode_tlv(control, pos)
            # v is the controlValue OCTET STRING -> SEQ { size, cookie }
            cpos = 0
            t, _size, cpos = decode_tlv(v, cpos)
            t, cookie, cpos = decode_tlv(v, cpos)
            return cookie
        return b""

    # ── convenience ─────────────────────────────────────────────────────
    def root_dse(self) -> dict[str, list]:
        """Read the RootDSE (base scope, no auth required for this object)."""
        rows = self._search_once(
            "", "(objectClass=*)",
            ["defaultNamingContext", "configurationNamingContext",
             "rootDomainNamingContext", "dnsHostName", "supportedSASLMechanisms"],
            SCOPE_BASE, 0, 0, cookie=b"", page_size=0)[0]
        return rows[0]["attributes"] if rows else {}
