"""Tests for IPMI 2.0 RAKP hash disclosure (Phase 74, CVE-2013-4786).

The live handshake can't be tested without a BMC, but every packet builder and
parser is validated against synthetic captures here.
"""

from __future__ import annotations

import struct

from explotica.discovery import ipmi_rakp as K


def _open_session_response(managed_sid: int, status: int = 0) -> bytes:
    hdr = (b"\x06\x00\xff\x07" + bytes([0x06, 0x11])
           + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<H", 8))
    payload = bytes([0, status, 0, 0]) + struct.pack("<I", 0xA0A2A3A4) \
        + struct.pack("<I", managed_sid)
    return hdr + payload


def _rakp2(managed_rand=b"M" * 16, guid=b"G" * 16, auth=b"H" * 20,
           status: int = 0) -> bytes:
    payload = (bytes([0, status, 0, 0]) + b"\xa0\xa2\xa3\xa4"
               + managed_rand + guid + auth)
    return (b"\x06\x00\xff\x07" + bytes([0x06, 0x13]) + struct.pack("<I", 0)
            + struct.pack("<I", 0) + struct.pack("<H", len(payload)) + payload)


# ── Builders ──────────────────────────────────────────────────────────────────
def test_open_session_request_shape():
    pkt = K.open_session_request(0xA0A2A3A4)
    assert pkt[:4] == b"\x06\x00\xff\x07"        # RMCP header
    assert pkt[4] == 0x06                         # RMCP+ auth type
    assert pkt[5] == 0x10                         # payload type = open-session-req
    assert b"\x01\x00\x00\x00" in pkt             # RAKP-HMAC-SHA1 algo present


def test_rakp1_carries_username_and_type():
    pkt = K.rakp_message_1(0x11223344, b"C" * 16, "admin")
    assert pkt[5] == 0x12                          # payload type = RAKP msg 1
    assert b"admin" in pkt
    assert struct.pack("<I", 0x11223344) in pkt    # BMC session id echoed


# ── Parsers ───────────────────────────────────────────────────────────────────
def test_parse_open_session_response_ok():
    assert K.parse_open_session_response(
        _open_session_response(0x11223344)) == 0x11223344


def test_parse_open_session_response_rejects_error_and_short():
    assert K.parse_open_session_response(_open_session_response(1, status=2)) is None
    assert K.parse_open_session_response(b"\x00" * 10) is None


def test_parse_rakp2_extracts_fields():
    out = K.parse_rakp_message_2(_rakp2(auth=b"\xab" * 20))
    assert out["status_code"] == 0
    assert out["managed_rand"] == b"M" * 16
    assert out["managed_guid"] == b"G" * 16
    assert out["auth_code"] == b"\xab" * 20


def test_parse_rakp2_surfaces_bmc_rejection():
    out = K.parse_rakp_message_2(_rakp2(status=2))   # unknown username
    assert out["status_code"] == 2
    assert "auth_code" not in out


def test_parse_rakp2_short_is_none():
    assert K.parse_rakp_message_2(b"\x00" * 20) is None


# ── Hash assembly ─────────────────────────────────────────────────────────────
def test_hashcat_7300_salt_layout():
    out = K.build_hashcat_7300(
        0xA0A2A3A4, 0x11223344, b"C" * 16, b"M" * 16, b"G" * 16,
        "admin", b"\xab" * 20)
    salt = bytes.fromhex(out["salt_hex"])
    # console_sid LE + managed_sid LE come first.
    assert salt[:4] == struct.pack("<I", 0xA0A2A3A4)
    assert salt[4:8] == struct.pack("<I", 0x11223344)
    # then console nonce, BMC nonce, GUID, priv, ulen, username
    assert salt[8:24] == b"C" * 16
    assert salt[24:40] == b"M" * 16
    assert salt[40:56] == b"G" * 16
    assert salt.endswith(b"admin")
    assert out["hash_hex"] == "ab" * 20
    assert out["hashcat_7300"] == f"{out['salt_hex']}:{out['hash_hex']}"
    assert out["john_rakp"] == f"$rakp${out['salt_hex']}${out['hash_hex']}"
