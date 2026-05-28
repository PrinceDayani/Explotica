"""Native SNMP v1/v2c BER encoder/decoder + proper multi-PDU walk — Phase 59.

Replaces the snmpwalk-binary fallback in snmp_inventory.py and
network_spider.py with a pure-Python implementation.

The previous code:
  - snmp_inventory.py used the `snmpwalk` net-snmp binary via subprocess
  - network_spider.py only did a single GetNextRequest (not a real walk)

Why this matters:
  - Route extraction needs walking the full ipCidrRouteTable (can be 1000+
    entries on backbone routers) — single PDU never finishes
  - hrSWInstalledTable (software inventory) has hundreds of OIDs per host
  - Binary fallback adds 200ms subprocess overhead per call and won't work
    where net-snmp isn't installed

This module:
  - BER (DER subset) encoder/decoder for SNMP variable bindings
  - GetRequest / GetNextRequest / GetBulkRequest PDU constructors
  - walk(): proper RFC-1157 iterative GetNextRequest until end-of-MIB
  - bulk_walk(): RFC-3416 GetBulkRequest for v2c (fewer round-trips)

Limited to v1/v2c. SNMPv3 needs USM/auth/priv which is a much bigger
implementation — kept in snmp_inventory.py via the binary fallback for now.
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Iterator, Optional

log = logging.getLogger(__name__)


# ── BER type tags ───────────────────────────────────────────────────────
TAG_INTEGER     = 0x02
TAG_OCTET_STR   = 0x04
TAG_NULL        = 0x05
TAG_OID         = 0x06
TAG_SEQUENCE    = 0x30
TAG_IP_ADDR     = 0x40
TAG_COUNTER32   = 0x41
TAG_GAUGE32     = 0x42
TAG_TIMETICKS   = 0x43
TAG_OPAQUE      = 0x44
TAG_COUNTER64   = 0x46

# SNMP PDU types
PDU_GET_REQ     = 0xa0
PDU_GET_NEXT    = 0xa1
PDU_RESPONSE    = 0xa2
PDU_SET_REQ     = 0xa3
PDU_GET_BULK    = 0xa5

# Error-status values
ERR_NO_ERROR        = 0
ERR_TOO_BIG         = 1
ERR_NO_SUCH_NAME    = 2
ERR_BAD_VALUE       = 3
ERR_READ_ONLY       = 4
ERR_GEN_ERR         = 5


# ── BER encoding ────────────────────────────────────────────────────────
def _encode_length(length: int) -> bytes:
    """Encode a BER length field."""
    if length < 0x80:
        return bytes([length])
    body = b""
    while length > 0:
        body = bytes([length & 0xff]) + body
        length >>= 8
    return bytes([0x80 | len(body)]) + body


def encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def encode_integer(n: int) -> bytes:
    if n == 0:
        return encode_tlv(TAG_INTEGER, b"\x00")
    body = b""
    negative = n < 0
    if negative:
        n = (1 << ((n.bit_length() + 8) & ~7)) + n
    while n > 0:
        body = bytes([n & 0xff]) + body
        n >>= 8
    if not negative and body[0] & 0x80:
        body = b"\x00" + body
    return encode_tlv(TAG_INTEGER, body)


def encode_octet_string(data: bytes) -> bytes:
    return encode_tlv(TAG_OCTET_STR, data)


def encode_null() -> bytes:
    return encode_tlv(TAG_NULL, b"")


def encode_oid(oid: str) -> bytes:
    """Encode a dotted-OID string to BER.

    First two components are combined: first*40 + second.
    Subsequent components use 7-bit base-128 encoding.
    """
    parts = [int(p) for p in oid.lstrip(".").split(".") if p]
    if len(parts) < 2:
        return encode_tlv(TAG_OID, b"")
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p == 0:
            body += b"\x00"
        else:
            sub = b""
            while p > 0:
                sub = bytes([(p & 0x7f) | (0x80 if sub else 0)]) + sub
                p >>= 7
            body += sub
    return encode_tlv(TAG_OID, body)


def encode_sequence(*items: bytes) -> bytes:
    return encode_tlv(TAG_SEQUENCE, b"".join(items))


# ── BER decoding ────────────────────────────────────────────────────────
def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Returns (length, new_offset)."""
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


def decode_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Decode one TLV. Returns (tag, value_bytes, new_offset)."""
    if offset >= len(data):
        return (0, b"", offset)
    tag = data[offset]
    offset += 1
    length, offset = _decode_length(data, offset)
    return (tag, data[offset:offset + length], offset + length)


def decode_integer(value: bytes) -> int:
    if not value:
        return 0
    n = int.from_bytes(value, "big")
    if value[0] & 0x80:
        n -= 1 << (len(value) * 8)
    return n


def decode_oid(value: bytes) -> str:
    """Decode a BER-encoded OID back to a dotted string."""
    if not value:
        return ""
    first = value[0]
    parts = [first // 40, first % 40]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7f)
        if not (b & 0x80):
            parts.append(n)
            n = 0
    return ".".join(str(p) for p in parts)


def decode_value(tag: int, value: bytes):
    """Decode a varbind value to a Python type based on tag."""
    if tag == TAG_INTEGER:
        return decode_integer(value)
    if tag == TAG_OCTET_STR:
        # Try decoding as text first; fall back to hex
        try:
            text = value.decode("utf-8", "strict")
            if all(0x20 <= ord(c) < 0x7f or c in "\r\n\t" for c in text):
                return text
        except UnicodeDecodeError:
            pass
        return value
    if tag == TAG_NULL:
        return None
    if tag == TAG_OID:
        return decode_oid(value)
    if tag == TAG_IP_ADDR:
        if len(value) == 4:
            return ".".join(str(b) for b in value)
        return value
    if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64):
        return int.from_bytes(value, "big")
    return value


# ── SNMP message construction ───────────────────────────────────────────
def _build_message(community: str, version: int, pdu_type: int,
                    request_id: int, oids: list[str],
                    error_status: int = 0, error_index: int = 0,
                    non_repeaters: int = 0, max_repetitions: int = 10
                    ) -> bytes:
    """Build a complete SNMP message ready to send."""
    varbinds = b""
    for oid in oids:
        varbinds += encode_sequence(encode_oid(oid), encode_null())
    varbind_list = encode_sequence(varbinds)
    if pdu_type == PDU_GET_BULK:
        pdu_body = (encode_integer(request_id)
                     + encode_integer(non_repeaters)
                     + encode_integer(max_repetitions)
                     + varbind_list)
    else:
        pdu_body = (encode_integer(request_id)
                     + encode_integer(error_status)
                     + encode_integer(error_index)
                     + varbind_list)
    pdu = encode_tlv(pdu_type, pdu_body)
    message = encode_sequence(
        encode_integer(version),
        encode_octet_string(community.encode("utf-8")),
        pdu,
    )
    return message


def _parse_response(data: bytes) -> Optional[dict]:
    """Parse an SNMP Response and return {error_status, error_index, varbinds}."""
    tag, body, _ = decode_tlv(data, 0)
    if tag != TAG_SEQUENCE:
        return None
    offset = 0
    _ver_tag, _ver_val, offset = decode_tlv(body, offset)
    _comm_tag, _comm_val, offset = decode_tlv(body, offset)
    pdu_tag, pdu_body, _ = decode_tlv(body, offset)
    if pdu_tag != PDU_RESPONSE:
        return None
    offset = 0
    _, req_id_val, offset = decode_tlv(pdu_body, offset)
    _, err_status_val, offset = decode_tlv(pdu_body, offset)
    _, err_index_val, offset = decode_tlv(pdu_body, offset)
    _, varbind_list_val, _ = decode_tlv(pdu_body, offset)
    varbinds: list[tuple[str, object]] = []
    vb_offset = 0
    while vb_offset < len(varbind_list_val):
        vb_tag, vb_data, vb_offset = decode_tlv(varbind_list_val, vb_offset)
        if vb_tag != TAG_SEQUENCE:
            break
        inner = 0
        _, oid_val, inner = decode_tlv(vb_data, inner)
        val_tag, val_data, _ = decode_tlv(vb_data, inner)
        # Skip end-of-MIB-view markers (tag 0x82)
        if val_tag == 0x82:
            varbinds.append((decode_oid(oid_val), "<endOfMibView>"))
            continue
        oid_str = decode_oid(oid_val)
        py_val = decode_value(val_tag, val_data)
        varbinds.append((oid_str, py_val))
    return {
        "request_id": decode_integer(req_id_val),
        "error_status": decode_integer(err_status_val),
        "error_index": decode_integer(err_index_val),
        "varbinds": varbinds,
    }


# ── Public API ──────────────────────────────────────────────────────────
def get(host: str, oid: str, *, port: int = 161,
         community: str = "public", version: int = 1,  # 0=v1, 1=v2c
         timeout: float = 3.0, retries: int = 2) -> Optional[tuple[str, object]]:
    """Single SNMP GET. Returns (oid, value) or None."""
    msg = _build_message(community, version, PDU_GET_REQ, 1, [oid])
    resp = _send_recv(host, port, msg, timeout=timeout, retries=retries)
    if not resp:
        return None
    parsed = _parse_response(resp)
    if not parsed or parsed["error_status"] != ERR_NO_ERROR:
        return None
    if not parsed["varbinds"]:
        return None
    return parsed["varbinds"][0]


def walk(host: str, root_oid: str, *, port: int = 161,
          community: str = "public", version: int = 1,
          timeout: float = 3.0, retries: int = 2,
          max_oids: int = 5000) -> Iterator[tuple[str, object]]:
    """Iterative SNMP walk via GetNextRequest. Yields (oid, value).

    Stops when next OID is outside the root subtree or on end-of-MIB.
    """
    current = root_oid
    request_id = 1
    seen = 0
    while seen < max_oids:
        msg = _build_message(community, version, PDU_GET_NEXT,
                              request_id, [current])
        resp = _send_recv(host, port, msg, timeout=timeout, retries=retries)
        if not resp:
            return
        parsed = _parse_response(resp)
        request_id += 1
        if not parsed or parsed["error_status"] != ERR_NO_ERROR:
            return
        if not parsed["varbinds"]:
            return
        oid, value = parsed["varbinds"][0]
        # Stop if oid leaves the subtree
        if not oid.startswith(root_oid + ".") and oid != root_oid:
            return
        if value == "<endOfMibView>":
            return
        yield (oid, value)
        current = oid
        seen += 1


def bulk_walk(host: str, root_oid: str, *, port: int = 161,
                community: str = "public", timeout: float = 3.0,
                retries: int = 2, max_repetitions: int = 20,
                max_oids: int = 5000) -> Iterator[tuple[str, object]]:
    """SNMP v2c GetBulkRequest walk — fewer round-trips than walk().

    Sends GetBulk with max_repetitions=20 per request; iterates until
    we leave the subtree.
    """
    current = root_oid
    request_id = 1
    seen = 0
    while seen < max_oids:
        msg = _build_message(community, 1, PDU_GET_BULK,
                              request_id, [current],
                              non_repeaters=0,
                              max_repetitions=max_repetitions)
        resp = _send_recv(host, port, msg, timeout=timeout, retries=retries)
        if not resp:
            return
        parsed = _parse_response(resp)
        request_id += 1
        if not parsed or parsed["error_status"] != ERR_NO_ERROR:
            return
        produced_any = False
        for oid, value in parsed["varbinds"]:
            if not oid.startswith(root_oid + ".") and oid != root_oid:
                return
            if value == "<endOfMibView>":
                return
            yield (oid, value)
            current = oid
            produced_any = True
            seen += 1
            if seen >= max_oids:
                return
        if not produced_any:
            return


def _send_recv(host: str, port: int, msg: bytes, *,
                 timeout: float = 3.0, retries: int = 2) -> Optional[bytes]:
    """Send UDP packet with retries; return first response received."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        for _ in range(max(1, retries + 1)):
            try:
                sock.sendto(msg, (host, port))
                data, _ = sock.recvfrom(65535)
                return data
            except socket.timeout:
                continue
            except OSError as e:
                log.debug("snmp _send_recv error: %s", e)
                return None
        return None
    finally:
        sock.close()


# ── Convenience: walk-and-collect to dict ───────────────────────────────
def walk_to_dict(host: str, root_oid: str, *, port: int = 161,
                   community: str = "public", timeout: float = 3.0,
                   use_bulk: bool = True,
                   max_oids: int = 5000) -> dict[str, object]:
    """Walk a subtree and return {oid: value} dict."""
    iterator = (bulk_walk(host, root_oid, port=port, community=community,
                            timeout=timeout, max_oids=max_oids)
                if use_bulk else
                walk(host, root_oid, port=port, community=community,
                      timeout=timeout, max_oids=max_oids))
    return dict(iterator)
