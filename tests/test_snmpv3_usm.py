"""SNMPv3 USM key-derivation tests — RFC 3414 Appendix A.3 vectors."""
import hashlib
import hmac

from explotica.protocols import snmpv3_usm as usm

# RFC 3414 A.3: password "maplesyrup", engine id 0x00..02 (12 bytes).
_PASSWORD = "maplesyrup"
_ENGINE_ID = bytes.fromhex("000000000000000000000002")


def test_md5_localized_key_rfc3414_vector():
    # A.3.1 localized key (Kul).
    expected = bytes.fromhex("526f5eed9fcce26f8964c2930787d82b")
    assert usm.password_to_key_md5(_PASSWORD, _ENGINE_ID) == expected


def test_sha1_localized_key_rfc3414_vector():
    # A.3.2 localized key (Kul).
    expected = bytes.fromhex("6695febc9288e36282235fc7151f128497b38f3f")
    assert usm.password_to_key_sha1(_PASSWORD, _ENGINE_ID) == expected


def test_md5_key_length():
    assert len(usm.password_to_key_md5(_PASSWORD, _ENGINE_ID)) == 16


def test_sha1_key_length():
    assert len(usm.password_to_key_sha1(_PASSWORD, _ENGINE_ID)) == 20


def test_empty_password_rejected():
    import pytest
    with pytest.raises(ValueError):
        usm.password_to_key_md5("", _ENGINE_ID)


def test_auth_params_is_hmac96():
    key = usm.password_to_key_md5(_PASSWORD, _ENGINE_ID)
    msg = b"hello world message body"
    params = usm.auth_params(key, msg, "md5")
    assert len(params) == 12
    assert params == hmac.new(key, msg, hashlib.md5).digest()[:12]
