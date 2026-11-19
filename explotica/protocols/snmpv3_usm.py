"""SNMPv3 USM key derivation (RFC 3414).

The native SNMP module (snmp_native.py) handles v1/v2c; v3's User-based
Security Model needs USM key localization and HMAC authentication, which this
module provides. These are the pure, offline-verifiable building blocks (the
full v3 message exchange against a live agent builds on them).

Implements:
  - password_to_key_md5 / _sha1 : RFC 3414 Appendix A.2 (Ku), with the
    engine-id localization step (Kul).
  - auth_params : the HMAC-96 authentication parameter over a whole message
    (RFC 3414 6.3.1 / 7.3.1), truncated to 12 bytes.

Verified against the RFC 3414 Appendix A.3 test vectors in the test suite.
"""

from __future__ import annotations

import hashlib
import hmac

_ONE_MEGABYTE = 1048576


def _password_to_key(hash_name: str, password: bytes, engine_id: bytes) -> bytes:
    """RFC 3414 A.2: expand the password over 1 MB, hash, then localize.

    hash_name is "md5" or "sha1".
    """
    if not password:
        raise ValueError("SNMPv3 USM password must not be empty")
    h = hashlib.new(hash_name)
    plen = len(password)
    # Hash exactly 1,048,576 bytes of the password cycled byte-by-byte.
    count = 0
    index = 0
    while count < _ONE_MEGABYTE:
        block = bytearray(64)
        for i in range(64):
            block[i] = password[index % plen]
            index += 1
        h.update(block)
        count += 64
    ku = h.digest()
    # Localize with the authoritative engine id: Kul = H(Ku || engineID || Ku).
    return hashlib.new(hash_name, ku + engine_id + ku).digest()


def password_to_key_md5(password, engine_id: bytes) -> bytes:
    """Localized MD5 auth key (16 bytes) for a password + engine id."""
    pw = password.encode() if isinstance(password, str) else password
    return _password_to_key("md5", pw, engine_id)


def password_to_key_sha1(password, engine_id: bytes) -> bytes:
    """Localized SHA-1 auth key (20 bytes) for a password + engine id."""
    pw = password.encode() if isinstance(password, str) else password
    return _password_to_key("sha1", pw, engine_id)


def auth_params(localized_key: bytes, whole_msg: bytes,
                hash_name: str = "md5") -> bytes:
    """HMAC authentication parameter (first 12 bytes) over the whole message.

    Per RFC 3414, the msgAuthenticationParameters field is first zeroed, the
    HMAC of the resulting message is computed with the localized key, and the
    leading 12 bytes become the parameter. The caller is responsible for
    inserting the 12 zero bytes before calling and splicing the result back in.
    """
    digest = hmac.new(localized_key, whole_msg,
                      getattr(hashlib, hash_name)).digest()
    return digest[:12]
