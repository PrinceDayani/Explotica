"""Offline verification of the pure-Python LDAP client primitives.

We can't reach a live DC from CI, so these tests pin the parts that are
verifiable without one: the BER codec (round-trips), MD4 + NTLMv2 crypto
(against RFC 1320 / MS-NLMP §4.2.4 vectors), the RFC 4515 filter compiler,
and the binary attribute decoders (SID / GUID / FILETIME / UAC).
"""

import struct
from datetime import datetime, timezone

from explotica.ad import ldap_client as L


# ── BER codec ───────────────────────────────────────────────────────────
class TestBerCodec:
    def test_length_short_and_long(self):
        assert L.ber_len(5) == b"\x05"
        assert L.ber_len(127) == b"\x7f"
        assert L.ber_len(128) == b"\x81\x80"
        assert L.ber_len(256) == b"\x82\x01\x00"

    def test_integer_roundtrip(self):
        for n in (0, 1, 127, 128, 255, 256, 65535, 1234567):
            tag, val, end = L.decode_tlv(L.enc_int(n))
            assert tag == L.TAG_INT
            assert L.decode_int(val) == n

    def test_integer_high_bit_not_negative(self):
        # 128 must encode as 00 80, not 80 (which decodes as -128).
        assert L.decode_int(L.decode_tlv(L.enc_int(128))[1]) == 128
        assert L.decode_int(L.decode_tlv(L.enc_int(255))[1]) == 255

    def test_octet_and_seq_roundtrip(self):
        seq = L.enc_seq(L.enc_octet("cn"), L.enc_octet("admin"))
        tag, val, _ = L.decode_tlv(seq)
        assert tag == L.TAG_SEQ
        parts = [v for _, v in L.iter_tlv(val)]
        assert parts == [b"cn", b"admin"]

    def test_bool(self):
        assert L.enc_bool(True).endswith(b"\xff")
        assert L.enc_bool(False).endswith(b"\x00")


# ── RFC 4515 filter compiler ────────────────────────────────────────────
class TestFilterCompiler:
    def test_presence(self):
        out = L.compile_filter("(objectClass=*)")
        assert out[0] == L.F_PRESENT
        assert out.endswith(b"objectClass")

    def test_equality(self):
        out = L.compile_filter("(sAMAccountName=krbtgt)")
        assert out[0] == L.F_EQ
        assert b"sAMAccountName" in out and b"krbtgt" in out

    def test_and_with_children(self):
        out = L.compile_filter(
            "(&(objectCategory=person)(servicePrincipalName=*))")
        assert out[0] == L.F_AND
        # contains an equality child and a presence child
        assert L.F_EQ in out and L.F_PRESENT in out

    def test_substring(self):
        out = L.compile_filter("(cn=adm*svc)")
        assert out[0] == L.F_SUBSTR
        assert b"adm" in out and b"svc" in out

    def test_not(self):
        out = L.compile_filter("(!(userAccountControl=512))")
        assert out[0] == L.F_NOT


# ── MD4 (RFC 1320 vectors) ──────────────────────────────────────────────
class TestMD4:
    def test_empty(self):
        assert L.md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_abc(self):
        assert L.md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"

    def test_message_digest(self):
        assert (L.md4(b"message digest").hex()
                == "d9130a8164549fe818874806e1c7014b")


# ── NTLMv2 (MS-NLMP §4.2.4 worked example) ──────────────────────────────
class TestNTLMv2:
    USER = "User"
    DOMAIN = "Domain"
    PASSWORD = "Password"
    SERVER_CHALLENGE = bytes.fromhex("0123456789abcdef")
    CLIENT_CHALLENGE = b"\xaa" * 8
    # ServerName / target info from MS-NLMP §4.2.4.1.3.
    TARGET_INFO = bytes.fromhex(
        "02000c0044006f006d00610069006e00"   # MsvAvNbDomainName "Domain"
        "01000c0053006500720076006500720000000000")  # NbComputerName "Server" + EOL

    def test_ntowfv2_vector(self):
        # MS-NLMP §4.2.4.1.1 NTLMv2 hash.
        got = L._ntowf_v2(self.PASSWORD, self.USER, self.DOMAIN)
        assert got.hex() == "0c868a403bfd7a93a3001ef22ef02e3f"

    def test_ntproofstr_structure(self):
        # NtChallengeResponse must be NTProofStr(16) || temp; temp begins
        # with the responder-version stamp 0x01 0x01 and embeds the blob.
        nt_proof, nt_response, lm_response = L.ntlmv2_response(
            self.USER, self.PASSWORD, self.DOMAIN,
            self.SERVER_CHALLENGE, self.TARGET_INFO,
            client_challenge=self.CLIENT_CHALLENGE,
            timestamp=b"\x00" * 8)
        assert nt_response[:16] == nt_proof
        assert nt_response[16:18] == b"\x01\x01"
        assert len(nt_proof) == 16
        assert len(lm_response) == 24  # 16-byte proof + 8-byte client challenge
        # NTProofStr must be a deterministic function of the inputs.
        again = L.ntlmv2_response(
            self.USER, self.PASSWORD, self.DOMAIN,
            self.SERVER_CHALLENGE, self.TARGET_INFO,
            client_challenge=self.CLIENT_CHALLENGE, timestamp=b"\x00" * 8)[0]
        assert again == nt_proof

    def test_authenticate_message_well_formed(self):
        msg = L.ntlm_authenticate(
            self.USER, self.PASSWORD, self.DOMAIN,
            {"server_challenge": self.SERVER_CHALLENGE,
             "target_info": self.TARGET_INFO},
            client_challenge=self.CLIENT_CHALLENGE, timestamp=b"\x00" * 8)
        assert msg.startswith(L.NTLMSSP_SIG)
        assert struct.unpack("<I", msg[8:12])[0] == 3  # AUTHENTICATE
        # NtChallengeResponse field (offset 20): len/maxlen/offset.
        nt_len, _, nt_off = struct.unpack("<HHI", msg[20:28])
        nt_resp = msg[nt_off:nt_off + nt_len]
        # Recompute and confirm the embedded response matches.
        expected = L.ntlmv2_response(
            self.USER, self.PASSWORD, self.DOMAIN,
            self.SERVER_CHALLENGE, self.TARGET_INFO,
            client_challenge=self.CLIENT_CHALLENGE, timestamp=b"\x00" * 8)[1]
        assert nt_resp == expected

    def test_negotiate_message(self):
        neg = L.ntlm_negotiate()
        assert neg.startswith(L.NTLMSSP_SIG)
        assert struct.unpack("<I", neg[8:12])[0] == 1


# ── Binary attribute decoders ───────────────────────────────────────────
class TestDecoders:
    def test_decode_sid_well_known(self):
        # S-1-5-18 (Local System): rev=1, subcount=1, auth=5, sub=18.
        blob = bytes([1, 1]) + (5).to_bytes(6, "big") + struct.pack("<I", 18)
        assert L.decode_sid(blob) == "S-1-5-18"

    def test_decode_sid_domain_rid(self):
        # S-1-5-21-X-Y-Z-512 (Domain Admins) shape.
        subs = [21, 1111111111, 2222222222, 3333333333, 512]
        blob = bytes([1, len(subs)]) + (5).to_bytes(6, "big")
        blob += b"".join(struct.pack("<I", s) for s in subs)
        assert L.decode_sid(blob) == "S-1-5-21-1111111111-2222222222-3333333333-512"

    def test_decode_guid(self):
        blob = bytes.fromhex("33221100554477668899aabbccddeeff")
        # Mixed-endian: first 3 groups little-endian, last 2 big-endian.
        assert L.decode_guid(blob) == "00112233-4455-6677-8899-aabbccddeeff"

    def test_decode_filetime(self):
        # 2024-01-01T00:00:00Z as FILETIME ticks.
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        target = datetime(2024, 1, 1, tzinfo=timezone.utc)
        ticks = int((target - epoch).total_seconds() * 10_000_000)
        got = L.decode_filetime(str(ticks))
        assert got == target

    def test_decode_filetime_never(self):
        assert L.decode_filetime("0") is None
        assert L.decode_filetime(str(0x7FFFFFFFFFFFFFFF)) is None

    def test_decode_uac_flags(self):
        # 0x10200 = NORMAL_ACCOUNT(0x200) | DONT_EXPIRE_PASSWORD(0x10000)
        out = L.decode_uac(0x10200)
        assert "NORMAL_ACCOUNT" in out["flags"]
        assert "DONT_EXPIRE_PASSWORD" in out["flags"]

    def test_decode_uac_asrep_roastable(self):
        out = L.decode_uac(0x400200)  # NORMAL_ACCOUNT | DONT_REQ_PREAUTH
        assert "DONT_REQ_PREAUTH" in out["flags"]

    def test_decode_uac_unconstrained_delegation(self):
        out = L.decode_uac(0x80200)  # NORMAL_ACCOUNT | TRUSTED_FOR_DELEGATION
        assert "TRUSTED_FOR_DELEGATION" in out["flags"]
