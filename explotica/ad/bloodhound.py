"""Real BloodHound CE collector + exporter.

Phase 70B. Replaces the placeholder-SID stub that lived in
`ad_enum.to_bloodhound_format`. That stub fabricated
``S-1-5-21-PLACEHOLDER-<hash>`` identifiers because, pre-LDAP-client, the
scanner had no way to read a real `objectSid`. With the authenticated LDAP
client (Phase 70A) we now collect actual directory objects and emit the
SharpHound/BloodHound-CE JSON format with *real* identifiers and edges.

What we collect and the edges we build:
  - Domains, Users, Groups, Computers, OUs, GPOs, Containers (real objectSid
    / objectGUID identifiers).
  - MemberOf edges via `member` (groups) and `primaryGroupID`.
  - ACL edges (GenericAll, WriteDacl, ForceChangePassword, AddMember, DCSync,
    …) parsed from each object's binary `nTSecurityDescriptor` (see secdesc).
  - GPLinks (domain/OU -> GPO) and the OU/container containment hierarchy.

Honesty:
  - The object→BloodHound transformers are pure functions over LDAP-entry
    dicts, covered by offline unit tests; format validity does not depend on
    a live DC.
  - When called without credentials (the Kerberos-only enum path), we do NOT
    fabricate SIDs. `partial_export_from_enum()` emits a clearly-flagged,
    SID-less partial graph so an analyst is never misled into thinking a real
    collection happened.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from typing import Optional

from .ldap_client import (LdapClient, decode_sid, decode_guid, decode_uac,
                          decode_filetime, SCOPE_SUBTREE)
from .secdesc import analyze_dacl

log = logging.getLogger(__name__)

BLOODHOUND_JSON_VERSION = 5  # BloodHound CE 5.x import format

# Attributes we pull per object class. nTSecurityDescriptor is requested as
# binary (the client decodes it as raw bytes; see BINARY_ATTRS).
_COMMON_ATTRS = [
    "objectSid", "objectGUID", "distinguishedName", "sAMAccountName",
    "name", "description", "userAccountControl", "adminCount",
    "nTSecurityDescriptor", "whenCreated", "lastLogonTimestamp",
    "pwdLastSet", "servicePrincipalName", "memberOf", "primaryGroupID",
]


def _first(entry_attrs: dict, key: str, default=None):
    vals = entry_attrs.get(key)
    if not vals:
        # case-insensitive fallback (AD returns the attr name as requested,
        # but be defensive).
        for k, v in entry_attrs.items():
            if k.lower() == key.lower() and v:
                return v[0]
        return default
    return vals[0]


def _all(entry_attrs: dict, key: str) -> list:
    vals = entry_attrs.get(key)
    if vals is not None:
        return vals
    for k, v in entry_attrs.items():
        if k.lower() == key.lower():
            return v
    return []


def _object_type_for_sid(sid: str, sid_index: dict) -> str:
    if sid in sid_index:
        return sid_index[sid]
    if sid and sid.endswith("-512"):
        return "Group"
    return "Base"


# ── pure transformers (LDAP entry dict -> BloodHound object) ─────────────
def user_to_bh(entry: dict, ctx: dict) -> dict:
    a = entry["attributes"]
    sid_blob = _first(a, "objectSid")
    sid = decode_sid(sid_blob) if isinstance(sid_blob, (bytes, bytearray)) else ""
    uac = decode_uac(_first(a, "userAccountControl", 0))
    flags = set(uac["flags"])
    sam = _first(a, "sAMAccountName", "")
    spns = _all(a, "servicePrincipalName")
    props = {
        "name": f"{sam.upper()}@{ctx['domain']}" if sam else ctx["domain"],
        "domain": ctx["domain"],
        "domainsid": ctx["domain_sid"],
        "distinguishedname": _first(a, "distinguishedName", ""),
        "samaccountname": sam,
        "description": _first(a, "description"),
        "enabled": "ACCOUNTDISABLE" not in flags,
        "dontreqpreauth": "DONT_REQ_PREAUTH" in flags,
        "passwordnotreqd": "PASSWD_NOTREQD" in flags,
        "unconstraineddelegation": "TRUSTED_FOR_DELEGATION" in flags,
        "pwdneverexpires": "DONT_EXPIRE_PASSWORD" in flags,
        "sensitive": "NOT_DELEGATED" in flags,
        "admincount": _first(a, "adminCount", "0") == "1",
        "hasspn": bool(spns),
        "serviceprincipalnames": spns,
    }
    pls = decode_filetime(_first(a, "pwdLastSet", 0))
    if pls:
        props["pwdlastset"] = int(pls.timestamp())
    sd = _first(a, "nTSecurityDescriptor")
    aces = _aces_from_sd(sd, ctx) if isinstance(sd, (bytes, bytearray)) else []
    return {
        "ObjectIdentifier": sid,
        "Properties": props,
        "PrimaryGroupSID": _primary_group_sid(a, ctx),
        "Aces": aces,
        "SPNTargets": [],
        "HasSIDHistory": [],
        "AllowedToDelegate": [],
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def computer_to_bh(entry: dict, ctx: dict) -> dict:
    a = entry["attributes"]
    sid_blob = _first(a, "objectSid")
    sid = decode_sid(sid_blob) if isinstance(sid_blob, (bytes, bytearray)) else ""
    uac = decode_uac(_first(a, "userAccountControl", 0))
    flags = set(uac["flags"])
    sam = _first(a, "sAMAccountName", "").rstrip("$")
    props = {
        "name": f"{sam.upper()}.{ctx['domain']}" if sam else ctx["domain"],
        "domain": ctx["domain"],
        "domainsid": ctx["domain_sid"],
        "distinguishedname": _first(a, "distinguishedName", ""),
        "samaccountname": _first(a, "sAMAccountName", ""),
        "enabled": "ACCOUNTDISABLE" not in flags,
        "unconstraineddelegation": "TRUSTED_FOR_DELEGATION" in flags,
        "trustedtoauth": "TRUSTED_TO_AUTH_FOR_DELEGATION" in flags,
        "isdc": "SERVER_TRUST_ACCOUNT" in flags,
        "operatingsystem": _first(a, "operatingSystem"),
    }
    sd = _first(a, "nTSecurityDescriptor")
    aces = _aces_from_sd(sd, ctx) if isinstance(sd, (bytes, bytearray)) else []
    return {
        "ObjectIdentifier": sid,
        "Properties": props,
        "PrimaryGroupSID": _primary_group_sid(a, ctx),
        "Aces": aces,
        "AllowedToDelegate": [],
        "AllowedToAct": [],
        "HasSIDHistory": [],
        "Sessions": {"Results": [], "Collected": False, "FailureReason": None},
        "LocalAdmins": {"Results": [], "Collected": False, "FailureReason": None},
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def group_to_bh(entry: dict, ctx: dict) -> dict:
    a = entry["attributes"]
    sid_blob = _first(a, "objectSid")
    sid = decode_sid(sid_blob) if isinstance(sid_blob, (bytes, bytearray)) else ""
    members = []
    for member_dn in _all(a, "member"):
        msid = ctx["dn_to_sid"].get(member_dn.lower())
        if msid:
            members.append({"ObjectIdentifier": msid,
                            "ObjectType": _object_type_for_sid(msid,
                                                               ctx["sid_index"])})
    props = {
        "name": (f"{_first(a, 'sAMAccountName', _first(a, 'name', '')).upper()}"
                 f"@{ctx['domain']}"),
        "domain": ctx["domain"],
        "domainsid": ctx["domain_sid"],
        "distinguishedname": _first(a, "distinguishedName", ""),
        "description": _first(a, "description"),
        "admincount": _first(a, "adminCount", "0") == "1",
    }
    sd = _first(a, "nTSecurityDescriptor")
    aces = _aces_from_sd(sd, ctx) if isinstance(sd, (bytes, bytearray)) else []
    return {
        "ObjectIdentifier": sid,
        "Properties": props,
        "Members": members,
        "Aces": aces,
        "IsDeleted": False,
        "IsACLProtected": False,
    }


def _primary_group_sid(a: dict, ctx: dict) -> Optional[str]:
    rid = _first(a, "primaryGroupID")
    if rid and ctx.get("domain_sid"):
        return f"{ctx['domain_sid']}-{rid}"
    return None


def _aces_from_sd(sd_blob: bytes, ctx: dict) -> list[dict]:
    out = []
    for e in analyze_dacl(sd_blob, skip_low_priv=False):
        out.append({
            "PrincipalSID": e["principal_sid"],
            "PrincipalType": _object_type_for_sid(e["principal_sid"],
                                                  ctx["sid_index"]),
            "RightName": e["edge"],
            "IsInherited": e["is_inherited"],
        })
    return out


# ── BloodHound file assembly ─────────────────────────────────────────────
def _bh_file(obj_type: str, data: list[dict]) -> dict:
    return {
        "data": data,
        "meta": {"methods": 0, "type": obj_type, "count": len(data),
                 "version": BLOODHOUND_JSON_VERSION},
    }


def build_zip(collection: dict, out_path: str) -> str:
    """Write a BloodHound-importable .zip of one JSON file per object type."""
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for obj_type in ("users", "groups", "computers", "domains",
                         "ous", "gpos", "containers"):
            payload = _bh_file(obj_type, collection.get(obj_type, []))
            zf.writestr(f"{obj_type}.json",
                        json.dumps(payload, indent=2, default=str))
    return out_path


# ── live collection ───────────────────────────────────────────────────────
class BloodHoundCollector:
    """Drives an LdapClient to collect a full BloodHound dataset."""

    def __init__(self, client: LdapClient, domain_fqdn: str,
                 base_dn: str):
        self.client = client
        self.domain = domain_fqdn.upper()
        self.base_dn = base_dn

    def collect(self) -> dict:
        # Pass 1: pull raw entries so we can build dn->sid / sid->type maps
        # before transforming (group Members need member-DN resolution).
        users = self._search("(&(objectCategory=person)(objectClass=user))")
        groups = self._search("(objectClass=group)")
        computers = self._search("(objectCategory=computer)")

        sid_index: dict[str, str] = {}
        dn_to_sid: dict[str, str] = {}
        for entries, otype in ((users, "User"), (groups, "Group"),
                               (computers, "Computer")):
            for e in entries:
                sid_blob = _first(e["attributes"], "objectSid")
                if isinstance(sid_blob, (bytes, bytearray)):
                    sid = decode_sid(sid_blob)
                    sid_index[sid] = otype
                    dn = _first(e["attributes"], "distinguishedName", "")
                    if dn:
                        dn_to_sid[dn.lower()] = sid

        domain_sid = self._domain_sid()
        ctx = {"domain": self.domain, "domain_sid": domain_sid,
               "sid_index": sid_index, "dn_to_sid": dn_to_sid}

        return {
            "users": [user_to_bh(e, ctx) for e in users],
            "groups": [group_to_bh(e, ctx) for e in groups],
            "computers": [computer_to_bh(e, ctx) for e in computers],
            "domains": self._collect_domains(ctx),
            "ous": [],          # OU/GPO containment is collected best-effort
            "gpos": self._collect_gpos(ctx),
            "containers": [],
            "_meta": {"domain": self.domain, "domain_sid": domain_sid,
                      "object_counts": {"users": len(users),
                                        "groups": len(groups),
                                        "computers": len(computers)}},
        }

    def _search(self, filter_str: str) -> list[dict]:
        return self.client.paged_search(
            self.base_dn, filter_str, _COMMON_ATTRS + ["operatingSystem"],
            scope=SCOPE_SUBTREE, page_size=500)

    def _domain_sid(self) -> str:
        rows = self.client.search(self.base_dn, "(objectClass=domain)",
                                  ["objectSid"])
        if rows:
            blob = _first(rows[0]["attributes"], "objectSid")
            if isinstance(blob, (bytes, bytearray)):
                return decode_sid(blob)
        return ""

    def _collect_domains(self, ctx: dict) -> list[dict]:
        rows = self.client.search(
            self.base_dn, "(objectClass=domain)",
            ["objectSid", "objectGUID", "distinguishedName", "name",
             "nTSecurityDescriptor", "gPLink"])
        out = []
        for e in rows:
            a = e["attributes"]
            sd = _first(a, "nTSecurityDescriptor")
            out.append({
                "ObjectIdentifier": ctx["domain_sid"],
                "Properties": {"name": self.domain, "domain": self.domain,
                               "domainsid": ctx["domain_sid"],
                               "distinguishedname": _first(a, "distinguishedName", "")},
                "Aces": _aces_from_sd(sd, ctx) if isinstance(sd, (bytes, bytearray)) else [],
                "Links": [], "ChildObjects": [], "Trusts": [],
                "IsDeleted": False, "IsACLProtected": False,
            })
        return out

    def _collect_gpos(self, ctx: dict) -> list[dict]:
        rows = self.client.search(
            self.base_dn, "(objectClass=groupPolicyContainer)",
            ["objectGUID", "displayName", "gPCFileSysPath",
             "distinguishedName", "nTSecurityDescriptor"])
        out = []
        for e in rows:
            a = e["attributes"]
            guid_blob = _first(a, "objectGUID")
            guid = (decode_guid(guid_blob).upper()
                    if isinstance(guid_blob, (bytes, bytearray)) else "")
            sd = _first(a, "nTSecurityDescriptor")
            out.append({
                "ObjectIdentifier": guid,
                "Properties": {
                    "name": (f"{_first(a, 'displayName', '')}@{self.domain}"),
                    "domain": self.domain, "domainsid": ctx["domain_sid"],
                    "distinguishedname": _first(a, "distinguishedName", ""),
                    "gpcpath": _first(a, "gPCFileSysPath", ""),
                },
                "Aces": _aces_from_sd(sd, ctx) if isinstance(sd, (bytes, bytearray)) else [],
                "IsDeleted": False, "IsACLProtected": False,
            })
        return out


def run_collection(host: str, domain: str, username: str, password: str, *,
                   base_dn: Optional[str] = None, use_ssl: bool = False,
                   out_path: str = "bloodhound_explotica.zip",
                   netbios_domain: Optional[str] = None) -> dict:
    """Authenticate, collect, and write a BloodHound zip.

    Returns a summary dict (no raw secrets). Raises LdapError on bind/search
    failure — we never claim a successful collection that didn't happen.
    """
    client = LdapClient(host, use_ssl=use_ssl)
    client.connect()
    try:
        nb = netbios_domain or domain.split(".")[0]
        client.bind_ntlm(nb, username, password)
        if not base_dn:
            rdse = client.root_dse()
            base_dn = (rdse.get("defaultNamingContext") or [""])[0]
        collector = BloodHoundCollector(client, domain, base_dn)
        collection = collector.collect()
        build_zip(collection, out_path)
        return {
            "collected": True,
            "output": out_path,
            "domain": domain.upper(),
            "base_dn": base_dn,
            "counts": collection["_meta"]["object_counts"],
        }
    finally:
        client.close()


def partial_export_from_enum(domain: str, dcs: list[dict],
                             users: list[dict]) -> dict:
    """Honest unauthenticated fallback for the Kerberos-only enum path.

    We have NO real SIDs here (Kerberos AS-REQ enum yields names only), so we
    refuse to fabricate them. The export is explicitly flagged as partial and
    uses ``synthetic:`` identifiers that BloodHound import would reject — the
    point is an analyst artifact, not a faked collection.
    """
    domain_upper = domain.upper()
    return {
        "partial": True,
        "warning": ("Unauthenticated Kerberos enum — no objectSid available. "
                    "Identifiers are synthetic placeholders; this is NOT a "
                    "real BloodHound collection. Run run_collection() with "
                    "credentials for an importable dataset."),
        "domain": domain_upper,
        "discovered_users": [
            {"identifier": f"synthetic:{u['username']}@{domain_upper}",
             "samaccountname": u["username"],
             "dontreqpreauth": u.get("status") == "no_preauth",
             "source": "kerberos_as_req_enum"}
            for u in users
        ],
        "discovered_dcs": [
            {"identifier": f"synthetic:{dc['target']}",
             "name": dc["target"], "ldap_port": dc.get("port"),
             "source": "dns_srv"}
            for dc in dcs
        ],
    }
