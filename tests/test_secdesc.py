"""Offline verification of the security-descriptor / ACL-edge parser.

We hand-build self-relative SECURITY_DESCRIPTOR bytes (MS-DTYP) so the
ACE→BloodHound-edge mapping is verified without a live directory.
"""

import struct

from explotica.ad import secdesc as S


# ── byte builders ────────────────────────────────────────────────────────
def encode_sid(sid: str) -> bytes:
    parts = sid.split("-")
    rev = int(parts[1])
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    out = bytes([rev, len(subs)]) + authority.to_bytes(6, "big")
    out += b"".join(struct.pack("<I", s) for s in subs)
    return out


def encode_guid(guid: str) -> bytes:
    a, b, c, d, e = guid.split("-")
    return (struct.pack("<I", int(a, 16))
            + struct.pack("<H", int(b, 16))
            + struct.pack("<H", int(c, 16))
            + struct.pack(">H", int(d, 16))
            + bytes.fromhex(e))


def make_object_ace(mask: int, sid: str, object_type: str = None) -> bytes:
    body = struct.pack("<I", mask)
    obj_flags = 0x1 if object_type else 0x0
    body += struct.pack("<I", obj_flags)
    if object_type:
        body += encode_guid(object_type)
    body += encode_sid(sid)
    ace = bytes([S.ACCESS_ALLOWED_OBJECT_ACE_TYPE, 0x00]) + \
        struct.pack("<H", 4 + len(body)) + body
    return ace


def make_allowed_ace(mask: int, sid: str, inherited: bool = False) -> bytes:
    body = struct.pack("<I", mask) + encode_sid(sid)
    flags = 0x10 if inherited else 0x00
    ace = bytes([S.ACCESS_ALLOWED_ACE_TYPE, flags]) + \
        struct.pack("<H", 4 + len(body)) + body
    return ace


def make_sd(aces: list[bytes]) -> bytes:
    dacl_body = b"".join(aces)
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(dacl_body), len(aces), 0) + dacl_body
    # header is 20 bytes; place DACL right after it.
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20)
    return header + acl


PRINCIPAL = "S-1-5-21-1111111111-2222222222-3333333333-1105"


# ── tests ────────────────────────────────────────────────────────────────
class TestAceParsing:
    def test_generic_all(self):
        sd = make_sd([make_allowed_ace(S.GENERIC_ALL, PRINCIPAL)])
        edges = S.analyze_dacl(sd)
        assert {"principal_sid": PRINCIPAL, "edge": "GenericAll",
                "is_inherited": False} in edges

    def test_generic_all_short_circuits(self):
        # GenericAll should be the only edge even if other bits are set.
        sd = make_sd([make_allowed_ace(
            S.GENERIC_ALL | S.RIGHT_WRITE_DAC, PRINCIPAL)])
        edges = [e["edge"] for e in S.analyze_dacl(sd)]
        assert edges == ["GenericAll"]

    def test_writedacl_writeowner(self):
        sd = make_sd([make_allowed_ace(
            S.RIGHT_WRITE_DAC | S.RIGHT_WRITE_OWNER, PRINCIPAL)])
        edges = {e["edge"] for e in S.analyze_dacl(sd)}
        assert "WriteDacl" in edges and "WriteOwner" in edges

    def test_force_change_password(self):
        sd = make_sd([make_object_ace(
            S.ADS_RIGHT_DS_CONTROL_ACCESS, PRINCIPAL,
            S.GUID_FORCE_CHANGE_PASSWORD)])
        edges = {e["edge"] for e in S.analyze_dacl(sd)}
        assert edges == {"ForceChangePassword"}

    def test_all_extended_rights_when_no_object_type(self):
        sd = make_sd([make_object_ace(
            S.ADS_RIGHT_DS_CONTROL_ACCESS, PRINCIPAL)])
        edges = {e["edge"] for e in S.analyze_dacl(sd)}
        assert "AllExtendedRights" in edges

    def test_add_member(self):
        sd = make_sd([make_object_ace(
            S.ADS_RIGHT_DS_WRITE_PROP, PRINCIPAL, S.GUID_WRITE_MEMBER)])
        edges = {e["edge"] for e in S.analyze_dacl(sd)}
        assert "AddMember" in edges

    def test_dcsync_synthesis(self):
        # Two replication extended rights on the same principal -> DCSync.
        sd = make_sd([
            make_object_ace(S.ADS_RIGHT_DS_CONTROL_ACCESS, PRINCIPAL,
                            S.GUID_DS_REPL_GET_CHANGES),
            make_object_ace(S.ADS_RIGHT_DS_CONTROL_ACCESS, PRINCIPAL,
                            S.GUID_DS_REPL_GET_CHANGES_ALL),
        ])
        edges = {e["edge"] for e in S.analyze_dacl(sd)}
        assert "DCSync" in edges
        assert "GetChanges" in edges and "GetChangesAll" in edges

    def test_dcsync_not_synthesized_for_partial(self):
        sd = make_sd([make_object_ace(
            S.ADS_RIGHT_DS_CONTROL_ACCESS, PRINCIPAL,
            S.GUID_DS_REPL_GET_CHANGES)])
        edges = {e["edge"] for e in S.analyze_dacl(sd)}
        assert "DCSync" not in edges

    def test_inherited_flag_preserved(self):
        sd = make_sd([make_allowed_ace(S.GENERIC_ALL, PRINCIPAL,
                                       inherited=True)])
        edges = S.analyze_dacl(sd)
        assert edges[0]["is_inherited"] is True

    def test_read_only_mask_yields_no_edge(self):
        sd = make_sd([make_allowed_ace(S.GENERIC_READ, PRINCIPAL)])
        assert S.analyze_dacl(sd) == []

    def test_owner_parsed(self):
        sd = make_sd([make_allowed_ace(S.GENERIC_ALL, PRINCIPAL)])
        parsed = S.parse_security_descriptor(sd)
        assert parsed["dacl"]  # at least one ACE
        assert parsed["owner_sid"] is None  # offset 0 in our test SD

    def test_skip_low_priv(self):
        sd = make_sd([make_allowed_ace(S.GENERIC_ALL, "S-1-1-0")])  # Everyone
        assert S.analyze_dacl(sd, skip_low_priv=True) == []
        assert S.analyze_dacl(sd, skip_low_priv=False)  # kept by default
