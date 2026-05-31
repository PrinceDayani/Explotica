"""Windows security-descriptor / DACL / ACE parser (MS-DTYP).

This is the part that turns a flat object dump into an *attack graph*. A
BloodHound-grade collector is only as good as its ACL analysis: the edges
that matter (GenericAll, WriteDacl, ForceChangePassword, AddMember, DCSync…)
all live inside each object's binary `nTSecurityDescriptor`. We parse it the
way SharpHound does and map the access mask + object-type GUID of each ACE to
the corresponding BloodHound edge.

References:
  - MS-DTYP §2.4.6 SECURITY_DESCRIPTOR (self-relative form)
  - MS-DTYP §2.4.5 ACL, §2.4.4 ACE
  - MS-ADTS control-access-right GUIDs

Everything here is pure byte parsing — no network — so it is fully covered by
offline unit tests with hand-built descriptors.
"""

from __future__ import annotations

import struct
from typing import Optional

from .ldap_client import decode_sid, decode_guid


# ── Access mask bits (AD-relevant subset, MS-ADTS / MS-DTYP) ─────────────
ADS_RIGHT_DS_CREATE_CHILD = 0x00000001
ADS_RIGHT_DS_DELETE_CHILD = 0x00000002
ADS_RIGHT_DS_SELF = 0x00000008
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
RIGHT_DELETE = 0x00010000
RIGHT_WRITE_DAC = 0x00040000
RIGHT_WRITE_OWNER = 0x00080000
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

# ── ACE types we care about ──────────────────────────────────────────────
ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
ACCESS_DENIED_ACE_TYPE = 0x01
ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06

_ALLOW_TYPES = {ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE}

ACE_OBJECT_TYPE_PRESENT = 0x00000001
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002

# ── Extended-right / property-set GUIDs that imply a specific edge ───────
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_IN_FILTERED_SET = (
    "89e95b76-444d-4c62-991a-0facbeda640c")
GUID_WRITE_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"  # member attribute
GUID_WRITE_SPN = "f3a64788-5306-11d1-a9c5-0000f80367c1"      # servicePrincipalName
GUID_GMSA_PASSWORD = "9b026da6-0d3c-465c-8bee-5199d7165cba"  # msDS-ManagedPassword

# SIDs that BloodHound treats as "everyone/authenticated" — low-signal as
# ACL principals but still collected; callers may downweight.
WELL_KNOWN_LOW_PRIV = {
    "S-1-1-0",      # Everyone
    "S-1-5-11",     # Authenticated Users
    "S-1-5-7",      # Anonymous
}


class Ace:
    """One parsed access-control entry."""

    __slots__ = ("ace_type", "flags", "mask", "sid", "object_type",
                 "inherited_object_type")

    def __init__(self, ace_type, flags, mask, sid,
                 object_type=None, inherited_object_type=None):
        self.ace_type = ace_type
        self.flags = flags
        self.mask = mask
        self.sid = sid
        self.object_type = object_type
        self.inherited_object_type = inherited_object_type

    @property
    def is_allow(self) -> bool:
        return self.ace_type in _ALLOW_TYPES


def parse_security_descriptor(blob: bytes) -> dict:
    """Parse a self-relative SECURITY_DESCRIPTOR. Returns owner_sid + ACEs."""
    if len(blob) < 20:
        return {"owner_sid": None, "group_sid": None, "dacl": []}
    (revision, _sbz1, _control, off_owner, off_group,
     _off_sacl, off_dacl) = struct.unpack("<BBHIIII", blob[:20])
    owner_sid = decode_sid(blob[off_owner:]) if off_owner else None
    group_sid = decode_sid(blob[off_group:]) if off_group else None
    dacl = _parse_acl(blob, off_dacl) if off_dacl else []
    return {"owner_sid": owner_sid, "group_sid": group_sid, "dacl": dacl}


def _parse_acl(blob: bytes, offset: int) -> list[Ace]:
    if offset + 8 > len(blob):
        return []
    _rev, _sbz1, _size, ace_count, _sbz2 = struct.unpack(
        "<BBHHH", blob[offset:offset + 8])
    aces: list[Ace] = []
    pos = offset + 8
    for _ in range(ace_count):
        if pos + 4 > len(blob):
            break
        ace_type, ace_flags, ace_size = struct.unpack(
            "<BBH", blob[pos:pos + 4])
        body = blob[pos + 4:pos + ace_size]
        ace = _parse_ace(ace_type, ace_flags, body)
        if ace:
            aces.append(ace)
        if ace_size == 0:
            break
        pos += ace_size
    return aces


def _parse_ace(ace_type: int, ace_flags: int, body: bytes) -> Optional[Ace]:
    if ace_type in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
        if len(body) < 4:
            return None
        mask = struct.unpack("<I", body[:4])[0]
        sid = decode_sid(body[4:])
        return Ace(ace_type, ace_flags, mask, sid)
    if ace_type in (ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                    ACCESS_DENIED_OBJECT_ACE_TYPE):
        if len(body) < 8:
            return None
        mask, obj_flags = struct.unpack("<II", body[:8])
        pos = 8
        object_type = None
        inherited_type = None
        if obj_flags & ACE_OBJECT_TYPE_PRESENT:
            object_type = decode_guid(body[pos:pos + 16])
            pos += 16
        if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
            inherited_type = decode_guid(body[pos:pos + 16])
            pos += 16
        sid = decode_sid(body[pos:])
        return Ace(ace_type, ace_flags, mask, sid, object_type, inherited_type)
    return None


def ace_to_edges(ace: Ace) -> list[str]:
    """Map an allow-ACE's mask + object-type GUID to BloodHound edge names.

    Returns the list of edges this single ACE grants (an ACE can imply more
    than one, e.g. GenericAll subsumes everything). Deny ACEs and pure-read
    masks yield no offensive edges.
    """
    if not ace.is_allow:
        return []
    mask = ace.mask
    edges: list[str] = []

    if mask & GENERIC_ALL:
        return ["GenericAll"]
    if mask & RIGHT_WRITE_DAC:
        edges.append("WriteDacl")
    if mask & RIGHT_WRITE_OWNER:
        edges.append("WriteOwner")
    if mask & GENERIC_WRITE:
        edges.append("GenericWrite")

    ot = (ace.object_type or "").lower()

    # Extended rights (DS_CONTROL_ACCESS).
    if mask & ADS_RIGHT_DS_CONTROL_ACCESS:
        if not ot:
            edges.append("AllExtendedRights")
        elif ot == GUID_FORCE_CHANGE_PASSWORD:
            edges.append("ForceChangePassword")
        elif ot in (GUID_DS_REPL_GET_CHANGES_ALL,
                    GUID_DS_REPL_GET_CHANGES_IN_FILTERED_SET):
            edges.append("GetChangesAll")
        elif ot == GUID_DS_REPL_GET_CHANGES:
            edges.append("GetChanges")
        elif ot == GUID_GMSA_PASSWORD:
            edges.append("ReadGMSAPassword")

    # Validated/property writes.
    if mask & ADS_RIGHT_DS_WRITE_PROP:
        if not ot:
            if "GenericWrite" not in edges:
                edges.append("GenericWrite")
        elif ot == GUID_WRITE_MEMBER:
            edges.append("AddMember")
        elif ot == GUID_WRITE_SPN:
            edges.append("WriteSPN")
    if mask & ADS_RIGHT_DS_SELF and ot == GUID_WRITE_MEMBER:
        edges.append("AddSelf")

    return edges


def analyze_dacl(sd_blob: bytes, *, skip_low_priv: bool = False) -> list[dict]:
    """Parse a security descriptor and return BloodHound-style ACL edges.

    Each entry: {"principal_sid", "edge", "is_inherited"}. DCSync is
    synthesized when the same principal holds both GetChanges and
    GetChangesAll on the domain object (the canonical BloodHound rule).
    """
    sd = parse_security_descriptor(sd_blob)
    out: list[dict] = []
    repl: dict[str, set] = {}
    for ace in sd["dacl"]:
        if skip_low_priv and ace.sid in WELL_KNOWN_LOW_PRIV:
            continue
        edges = ace_to_edges(ace)
        for edge in edges:
            if edge in ("GetChanges", "GetChangesAll"):
                repl.setdefault(ace.sid, set()).add(edge)
            out.append({
                "principal_sid": ace.sid,
                "edge": edge,
                "is_inherited": bool(ace.flags & 0x10),  # INHERITED_ACE
            })
    # Synthesize DCSync where a principal has both replication rights.
    for sid, got in repl.items():
        if {"GetChanges", "GetChangesAll"} <= got:
            out.append({"principal_sid": sid, "edge": "DCSync",
                        "is_inherited": False})
    return out
