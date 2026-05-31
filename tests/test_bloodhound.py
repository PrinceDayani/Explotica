"""Offline verification of the BloodHound transformers + zip assembly.

The object→BloodHound functions are pure over LDAP-entry dicts, so we feed
them synthetic-but-realistic entries (with real binary objectSid bytes) and
assert the emitted format is BloodHound-CE-valid with real identifiers — and
that the unauthenticated path refuses to fabricate SIDs.
"""

import json
import struct
import zipfile

from explotica.ad import bloodhound as B
from tests.test_secdesc import encode_sid

DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"


def _ctx():
    return {"domain": "CORP.LOCAL", "domain_sid": DOMAIN_SID,
            "sid_index": {}, "dn_to_sid": {}}


def _user_entry(sam, uac, *, spns=None, dn=None):
    return {"dn": dn or f"CN={sam},CN=Users,DC=corp,DC=local",
            "attributes": {
                "objectSid": [encode_sid(f"{DOMAIN_SID}-1105")],
                "sAMAccountName": [sam],
                "userAccountControl": [str(uac)],
                "distinguishedName": [dn or f"CN={sam},CN=Users,DC=corp,DC=local"],
                "servicePrincipalName": spns or [],
                "primaryGroupID": ["513"],
            }}


class TestUserTransformer:
    def test_real_sid_emitted(self):
        bh = B.user_to_bh(_user_entry("alice", 0x200), _ctx())
        assert bh["ObjectIdentifier"] == f"{DOMAIN_SID}-1105"
        assert "PLACEHOLDER" not in bh["ObjectIdentifier"]

    def test_enabled_and_name(self):
        bh = B.user_to_bh(_user_entry("alice", 0x200), _ctx())
        assert bh["Properties"]["enabled"] is True
        assert bh["Properties"]["name"] == "ALICE@CORP.LOCAL"

    def test_disabled_account(self):
        bh = B.user_to_bh(_user_entry("bob", 0x202), _ctx())  # +ACCOUNTDISABLE
        assert bh["Properties"]["enabled"] is False

    def test_asrep_roastable_flag(self):
        bh = B.user_to_bh(_user_entry("svc", 0x400200), _ctx())  # DONT_REQ_PREAUTH
        assert bh["Properties"]["dontreqpreauth"] is True

    def test_unconstrained_delegation(self):
        bh = B.user_to_bh(_user_entry("svc", 0x80200), _ctx())  # TRUSTED_FOR_DELEGATION
        assert bh["Properties"]["unconstraineddelegation"] is True

    def test_hasspn(self):
        bh = B.user_to_bh(
            _user_entry("svc", 0x200, spns=["MSSQLSvc/db.corp.local:1433"]),
            _ctx())
        assert bh["Properties"]["hasspn"] is True
        assert bh["Properties"]["serviceprincipalnames"]

    def test_primary_group_sid(self):
        bh = B.user_to_bh(_user_entry("alice", 0x200), _ctx())
        assert bh["PrimaryGroupSID"] == f"{DOMAIN_SID}-513"


class TestGroupTransformer:
    def test_member_resolution(self):
        ctx = _ctx()
        ctx["dn_to_sid"]["cn=alice,cn=users,dc=corp,dc=local"] = f"{DOMAIN_SID}-1105"
        ctx["sid_index"][f"{DOMAIN_SID}-1105"] = "User"
        entry = {"attributes": {
            "objectSid": [encode_sid(f"{DOMAIN_SID}-512")],
            "sAMAccountName": ["Domain Admins"],
            "member": ["CN=alice,CN=Users,DC=corp,DC=local"],
            "distinguishedName": ["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
        }}
        bh = B.group_to_bh(entry, ctx)
        assert bh["ObjectIdentifier"] == f"{DOMAIN_SID}-512"
        assert bh["Members"] == [
            {"ObjectIdentifier": f"{DOMAIN_SID}-1105", "ObjectType": "User"}]


class TestZipAssembly:
    def test_zip_has_all_files_and_valid_json(self, tmp_path):
        collection = {"users": [B.user_to_bh(_user_entry("alice", 0x200), _ctx())],
                      "groups": [], "computers": [], "domains": [],
                      "ous": [], "gpos": [], "containers": []}
        out = str(tmp_path / "bh.zip")
        B.build_zip(collection, out)
        with zipfile.ZipFile(out) as zf:
            names = set(zf.namelist())
            assert names == {"users.json", "groups.json", "computers.json",
                             "domains.json", "ous.json", "gpos.json",
                             "containers.json"}
            users = json.loads(zf.read("users.json"))
            assert users["meta"]["type"] == "users"
            assert users["meta"]["count"] == 1
            assert users["meta"]["version"] == B.BLOODHOUND_JSON_VERSION
            assert users["data"][0]["ObjectIdentifier"] == f"{DOMAIN_SID}-1105"


class TestPartialExportHonesty:
    def test_partial_export_does_not_fabricate_sids(self):
        out = B.partial_export_from_enum(
            "corp.local",
            [{"target": "dc01.corp.local", "port": 389}],
            [{"username": "alice", "status": "no_preauth"}])
        assert out["partial"] is True
        assert "warning" in out
        # No fake S-1-5-21 SIDs anywhere — identifiers are clearly synthetic.
        blob = json.dumps(out)
        assert "S-1-5-21" not in blob
        assert "PLACEHOLDER" not in blob
        assert out["discovered_users"][0]["identifier"].startswith("synthetic:")

    def test_ad_enum_delegates_to_partial(self):
        from explotica.ad import ad_enum
        out = ad_enum.to_bloodhound_format(
            "corp.local", [], [{"username": "alice", "status": "no_preauth"}])
        assert out.get("partial") is True
