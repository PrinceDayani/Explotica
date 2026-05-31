"""AD Certificate Services (ADCS) enumeration + ESC misconfiguration audit.

Phase 70C. The limitations doc called this out explicitly:
"No certificate template enumeration (ESC1-ESC11) — major Active Directory
attack surface we don't cover." This module covers the LDAP-enumerable ESCs.

ADCS objects live under the Configuration naming context:
  CN=Public Key Services,CN=Services,CN=Configuration,<domain>
    ├─ CN=Certificate Templates   (pKICertificateTemplate objects)
    └─ CN=Enrollment Services      (pKIEnrollmentService — the CAs)

Each ESC is a precise boolean over real attributes — no exploitation, just a
read-only audit. References: SpecterOps "Certified Pre-Owned" + Certify.

  ESC1  Enrollee-supplies-subject + auth EKU + no approval/signature, and a
        low-priv principal can enroll → request a cert AS any user (incl DA).
  ESC2  Any-Purpose (or no) EKU + enrollable by low-priv → usable for auth.
  ESC3  Enrollment-Agent EKU enrollable → enroll on behalf of others.
  ESC4  Low-priv principal has write control (GenericAll/Write/WriteDacl/
        WriteOwner) over the template object → reconfigure it into ESC1.
  ESC6  CA has EDITF_ATTRIBUTESUBJECTALTNAME2 → SAN injection on any template.
        NOTE: this flag is a CA *registry* setting, not an LDAP attribute, so
        we flag it as requiring a CA-side check rather than claiming coverage.
  ESC7  Low-priv principal holds ManageCA / ManageCertificates on the CA.
  ESC8  CA web-enrollment (/certsrv) endpoint present → NTLM-relay to ADCS.

Honesty: analyzers are pure functions over parsed attribute dicts (offline
unit tests). ESC6 is reported as a *requires-verification* indicator. ESC8
detection is network-side (HTTP probe), separate from the LDAP audit.
"""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Optional

from .ldap_client import LdapClient, decode_sid, decode_guid, SCOPE_SUBTREE
from .secdesc import (parse_security_descriptor, GENERIC_ALL, GENERIC_WRITE,
                      RIGHT_WRITE_DAC, RIGHT_WRITE_OWNER,
                      ADS_RIGHT_DS_CONTROL_ACCESS, ADS_RIGHT_DS_WRITE_PROP)

log = logging.getLogger(__name__)

# ── EKU / Application-Policy OIDs that grant client authentication ───────
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT_CLIENT = "1.3.6.1.5.2.3.4"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

AUTH_EKUS = {EKU_CLIENT_AUTH, EKU_SMARTCARD_LOGON, EKU_PKINIT_CLIENT}

# ── msPKI-Certificate-Name-Flag ─────────────────────────────────────────
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000

# ── msPKI-Enrollment-Flag ───────────────────────────────────────────────
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002          # manager approval required
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000      # ESC9 precondition

# ── Certificate-enrollment extended-right GUIDs (MS-CRTD / MS-ADTS) ──────
GUID_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_AUTO_ENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
GUID_ALL_EXTENDED = ""  # DS_CONTROL_ACCESS with no object type = all rights

WRITE_MASK = GENERIC_ALL | GENERIC_WRITE | RIGHT_WRITE_DAC | RIGHT_WRITE_OWNER


def is_low_priv(sid: str) -> bool:
    """True for principals a low-privileged user effectively belongs to."""
    if sid in ("S-1-1-0", "S-1-5-11", "S-1-5-7"):  # Everyone/AuthUsers/Anon
        return True
    # Domain Users (-513), Domain Computers (-515), builtin Users (-545).
    return sid.endswith("-513") or sid.endswith("-515") or sid.endswith("-545")


def _has_eku(ekus: list[str], wanted: set) -> bool:
    return bool(set(ekus) & wanted)


def _is_auth_capable(ekus: list[str]) -> bool:
    """A template authenticates if it has an auth EKU, Any-Purpose, or NO EKU
    (no EKU == usable for any purpose)."""
    if not ekus:
        return True
    if EKU_ANY_PURPOSE in ekus:
        return True
    return _has_eku(ekus, AUTH_EKUS)


def enrollment_rights(sd_blob: bytes) -> dict:
    """Inspect a template's DACL for who can enroll / who can rewrite it.

    Returns {"enroll_principals", "low_priv_can_enroll",
             "write_principals", "low_priv_can_write"}.
    """
    enroll: list[str] = []
    write: list[str] = []
    if not sd_blob:
        return {"enroll_principals": [], "low_priv_can_enroll": False,
                "write_principals": [], "low_priv_can_write": False}
    sd = parse_security_descriptor(sd_blob)
    for ace in sd["dacl"]:
        if not ace.is_allow:
            continue
        ot = (ace.object_type or "").lower()
        # Enrollment: extended right with the enroll/autoenroll GUID, OR an
        # all-extended-rights ACE, OR GenericAll.
        if ace.mask & GENERIC_ALL:
            enroll.append(ace.sid)
            write.append(ace.sid)
            continue
        if ace.mask & ADS_RIGHT_DS_CONTROL_ACCESS and ot in (
                GUID_ENROLL, GUID_AUTO_ENROLL, ""):
            enroll.append(ace.sid)
        if ace.mask & WRITE_MASK or (
                ace.mask & ADS_RIGHT_DS_WRITE_PROP and not ot):
            write.append(ace.sid)
    return {
        "enroll_principals": sorted(set(enroll)),
        "low_priv_can_enroll": any(is_low_priv(s) for s in enroll),
        "write_principals": sorted(set(write)),
        "low_priv_can_write": any(is_low_priv(s) for s in write),
    }


def analyze_template(tpl: dict) -> list[dict]:
    """Evaluate a parsed certificate template for ESC1-ESC4.

    `tpl` keys: name, display_name, name_flag (int), enrollment_flag (int),
    ra_signature (int), ekus (list[str]), schema_version (int), sd_blob (bytes).
    Returns a list of finding dicts (possibly empty).
    """
    findings: list[dict] = []
    name = tpl.get("name", "?")
    name_flag = tpl.get("name_flag", 0)
    enroll_flag = tpl.get("enrollment_flag", 0)
    ra_sig = tpl.get("ra_signature", 0)
    ekus = tpl.get("ekus", []) or []
    rights = enrollment_rights(tpl.get("sd_blob", b""))

    manager_approval = bool(enroll_flag & CT_FLAG_PEND_ALL_REQUESTS)
    requires_signature = ra_sig and int(ra_sig) > 0
    supplies_subject = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    enrollable_low = rights["low_priv_can_enroll"]

    def base(esc, title, severity):
        return {"esc": esc, "template": name,
                "display_name": tpl.get("display_name"),
                "title": title, "severity": severity,
                "enroll_principals": rights["enroll_principals"],
                "manager_approval": manager_approval,
                "requires_signature": bool(requires_signature)}

    # ESC1: enrollee supplies subject + auth EKU + no approval/signature +
    #       low-priv can enroll.
    if (supplies_subject and _is_auth_capable(ekus) and not manager_approval
            and not requires_signature and enrollable_low):
        f = base("ESC1", "Enrollee-supplies-subject auth template enrollable "
                          "by low-privileged users — impersonate any principal",
                 "CRITICAL")
        f["ekus"] = ekus
        f["reason"] = ("CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set, authentication "
                       "EKU present, no manager approval, no RA signature, and "
                       "a low-priv principal has Enroll.")
        findings.append(f)

    # ESC2: Any-Purpose / no EKU, no approval/signature, low-priv enrollable.
    if ((EKU_ANY_PURPOSE in ekus or not ekus) and not manager_approval
            and not requires_signature and enrollable_low):
        f = base("ESC2", "Any-Purpose (or no) EKU template enrollable by "
                          "low-privileged users", "CRITICAL")
        f["ekus"] = ekus
        f["reason"] = ("Any-Purpose EKU (or no EKU) means the issued cert is "
                       "usable for client authentication.")
        findings.append(f)

    # ESC3: Enrollment-Agent EKU enrollable by low-priv.
    if EKU_ENROLLMENT_AGENT in ekus and not manager_approval and enrollable_low:
        f = base("ESC3", "Enrollment-Agent template enrollable by low-priv — "
                          "request certs on behalf of other users", "HIGH")
        f["ekus"] = ekus
        findings.append(f)

    # ESC4: low-priv principal has write control over the template object.
    if rights["low_priv_can_write"]:
        f = base("ESC4", "Template object writable by low-privileged users — "
                          "can be reconfigured into ESC1", "HIGH")
        f["write_principals"] = rights["write_principals"]
        findings.append(f)

    return findings


def analyze_ca(ca: dict) -> list[dict]:
    """Evaluate a parsed CA (pKIEnrollmentService) for ESC6/ESC7 indicators.

    `ca` keys: name, dns_host, sd_blob (bytes), templates (list[str]),
    edit_flags (Optional[int] — usually unavailable from LDAP).
    """
    findings: list[dict] = []
    name = ca.get("name", "?")

    # ESC7: low-priv principal with write/control over the CA object — a proxy
    # for ManageCA/ManageCertificates (those exact rights live in the CA's own
    # security descriptor, which for the enrollment-service object surfaces as
    # control ACEs here).
    sd_blob = ca.get("sd_blob", b"")
    if sd_blob:
        sd = parse_security_descriptor(sd_blob)
        weak = sorted({a.sid for a in sd["dacl"] if a.is_allow
                       and (a.mask & WRITE_MASK) and is_low_priv(a.sid)})
        if weak:
            findings.append({
                "esc": "ESC7", "ca": name, "dns_host": ca.get("dns_host"),
                "title": "CA object controllable by low-privileged principals "
                         "(potential ManageCA / ManageCertificates)",
                "severity": "HIGH", "principals": weak})

    # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 — honest: not an LDAP attribute.
    edit_flags = ca.get("edit_flags")
    if edit_flags is None:
        findings.append({
            "esc": "ESC6", "ca": name, "dns_host": ca.get("dns_host"),
            "title": "EDITF_ATTRIBUTESUBJECTALTNAME2 status UNKNOWN — verify on "
                     "the CA",
            "severity": "INFO", "requires_verification": True,
            "how_to_verify": ("certutil -config <CA> -getreg policy\\EditFlags "
                              "(look for EDITF_ATTRIBUTESUBJECTALTNAME2). If "
                              "set, any template allows SAN injection = domain "
                              "compromise.")})
    elif int(edit_flags) & 0x00040000:  # EDITF_ATTRIBUTESUBJECTALTNAME2
        findings.append({
            "esc": "ESC6", "ca": name, "dns_host": ca.get("dns_host"),
            "title": "EDITF_ATTRIBUTESUBJECTALTNAME2 ENABLED — SAN injection on "
                     "any template", "severity": "CRITICAL"})
    return findings


def probe_esc8_web_enrollment(host: str, timeout: float = 4.0) -> Optional[dict]:
    """ESC8 network-side indicator: is the ADCS web-enrollment endpoint up?

    The /certsrv endpoint with NTLM auth is the relay target. We only detect
    presence + whether NTLM is offered — we do NOT relay.
    """
    for scheme, port in (("https", 443), ("http", 80)):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            if scheme == "https":
                ctx = ssl._create_unverified_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            req = (f"GET /certsrv/ HTTP/1.1\r\nHost: {host}\r\n"
                   "User-Agent: explotica\r\nConnection: close\r\n\r\n").encode()
            sock.sendall(req)
            resp = sock.recv(4096)
            sock.close()
        except (socket.timeout, OSError, ssl.SSLError):
            continue
        if not resp:
            continue
        head = resp.decode("latin-1", "replace")
        status = head.split("\r\n", 1)[0]
        if " 401 " in status or " 200 " in status or "certsrv" in head.lower():
            ntlm = "WWW-Authenticate: NTLM" in head or "Negotiate" in head
            return {
                "esc": "ESC8", "host": host, "endpoint": f"{scheme}://{host}/certsrv/",
                "title": "ADCS web-enrollment endpoint reachable — NTLM-relay "
                         "to ADCS (ESC8) target",
                "severity": "HIGH" if ntlm else "MEDIUM",
                "ntlm_auth_offered": ntlm, "status_line": status.strip()}
    return None


# ── LDAP collection ───────────────────────────────────────────────────────
_TEMPLATE_ATTRS = [
    "cn", "displayName", "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "pKIExtendedKeyUsage",
    "msPKI-Certificate-Application-Policy", "msPKI-Template-Schema-Version",
    "nTSecurityDescriptor",
]
_CA_ATTRS = ["cn", "dNSHostName", "certificateTemplates", "nTSecurityDescriptor"]


def _i(attrs: dict, key: str, default=0) -> int:
    for k, v in attrs.items():
        if k.lower() == key.lower() and v:
            try:
                return int(v[0])
            except (ValueError, TypeError):
                return default
    return default


def _list(attrs: dict, key: str) -> list:
    for k, v in attrs.items():
        if k.lower() == key.lower():
            return v
    return []


def _str(attrs: dict, key: str, default=None):
    vals = _list(attrs, key)
    return vals[0] if vals else default


def _bin(attrs: dict, key: str) -> bytes:
    v = _str(attrs, key)
    return v if isinstance(v, (bytes, bytearray)) else b""


def parse_template_entry(entry: dict) -> dict:
    a = entry["attributes"]
    ekus = list(_list(a, "pKIExtendedKeyUsage")) or \
        list(_list(a, "msPKI-Certificate-Application-Policy"))
    return {
        "name": _str(a, "cn", "?"),
        "display_name": _str(a, "displayName"),
        "name_flag": _i(a, "msPKI-Certificate-Name-Flag"),
        "enrollment_flag": _i(a, "msPKI-Enrollment-Flag"),
        "ra_signature": _i(a, "msPKI-RA-Signature"),
        "ekus": [e for e in ekus if isinstance(e, str)],
        "schema_version": _i(a, "msPKI-Template-Schema-Version"),
        "sd_blob": _bin(a, "nTSecurityDescriptor"),
    }


def parse_ca_entry(entry: dict) -> dict:
    a = entry["attributes"]
    return {
        "name": _str(a, "cn", "?"),
        "dns_host": _str(a, "dNSHostName"),
        "templates": [t for t in _list(a, "certificateTemplates")
                      if isinstance(t, str)],
        "sd_blob": _bin(a, "nTSecurityDescriptor"),
        "edit_flags": None,  # not available via LDAP
    }


def run_adcs_audit(host: str, domain: str, username: str, password: str, *,
                   use_ssl: bool = False, config_nc: Optional[str] = None,
                   netbios_domain: Optional[str] = None,
                   probe_web_enrollment: bool = True) -> dict:
    """Authenticate, enumerate templates + CAs, and run the ESC audit."""
    client = LdapClient(host, use_ssl=use_ssl)
    client.connect()
    result: dict = {"domain": domain.upper(), "templates": [], "cas": [],
                    "findings": []}
    try:
        nb = netbios_domain or domain.split(".")[0]
        client.bind_ntlm(nb, username, password)
        if not config_nc:
            rdse = client.root_dse()
            config_nc = (rdse.get("configurationNamingContext") or [""])[0]
        pks = f"CN=Public Key Services,CN=Services,{config_nc}"
        tpl_base = f"CN=Certificate Templates,{pks}"
        ca_base = f"CN=Enrollment Services,{pks}"

        templates = client.search(tpl_base, "(objectClass=pKICertificateTemplate)",
                                   _TEMPLATE_ATTRS, scope=SCOPE_SUBTREE)
        cas = client.search(ca_base, "(objectClass=pKIEnrollmentService)",
                            _CA_ATTRS, scope=SCOPE_SUBTREE)

        for e in templates:
            tpl = parse_template_entry(e)
            result["templates"].append(tpl["name"])
            result["findings"].extend(analyze_template(tpl))
        for e in cas:
            ca = parse_ca_entry(e)
            result["cas"].append({"name": ca["name"], "dns_host": ca["dns_host"]})
            result["findings"].extend(analyze_ca(ca))
            if probe_web_enrollment and ca.get("dns_host"):
                esc8 = probe_esc8_web_enrollment(ca["dns_host"])
                if esc8:
                    result["findings"].append(esc8)
        return result
    finally:
        client.close()
