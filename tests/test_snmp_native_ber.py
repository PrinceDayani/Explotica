"""Round-trip + known-vector tests for the native SNMP BER codec.

These functions were previously untested despite encoding/decoding the wire
format for every v1/v2c SNMP walk.
"""
import pytest

from explotica.protocols import snmp_native as s


@pytest.mark.parametrize("n", [0, 1, 42, 127, 128, 255, 256, 65535, 2147483647])
def test_integer_round_trip(n):
    tag, value, _ = s.decode_tlv(s.encode_integer(n))
    assert tag == s.TAG_INTEGER
    assert s.decode_integer(value) == n


@pytest.mark.parametrize("oid", [
    "1.3.6.1.2.1.1.1.0",   # sysDescr.0
    "1.3.6.1.2.1.1.5.0",   # sysName.0
    "1.3.6.1",
    "2.5",                 # exercises the 40*a+b first-byte rule
])
def test_oid_round_trip(oid):
    tag, value, _ = s.decode_tlv(s.encode_oid(oid))
    assert tag == s.TAG_OID
    assert s.decode_oid(value) == oid


def test_oid_known_vector():
    # sysDescr.0 standard DER encoding.
    assert s.encode_oid("1.3.6.1.2.1.1.1.0").hex() == "06082b06010201010100"


def test_octet_string_round_trip():
    tag, value, _ = s.decode_tlv(s.encode_octet_string(b"public"))
    assert tag == s.TAG_OCTET_STR
    assert value == b"public"


def test_sequence_wraps_items():
    seq = s.encode_sequence(s.encode_integer(1), s.encode_octet_string(b"x"))
    tag, _value, _ = s.decode_tlv(seq)
    assert tag == s.TAG_SEQUENCE


def test_long_length_encoding():
    # A value longer than 127 bytes forces multi-byte BER length encoding.
    blob = b"A" * 300
    tag, value, _ = s.decode_tlv(s.encode_octet_string(blob))
    assert tag == s.TAG_OCTET_STR
    assert value == blob
