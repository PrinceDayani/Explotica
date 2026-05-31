"""Golden / Silver ticket RISK detection (Kerberos forgery enablers).

Phase 70D. The limitations doc lists "No Golden Ticket / Silver Ticket
detection." An honest network-side scanner must be precise about what that
can mean:

  - *Detecting an actively-used forged ticket* requires DC-side telemetry
    (Event 4769 encryption-downgrade, PAC validation anomalies) or deep
    traffic inspection. We are pre-foothold and network-positioned, so we
    CANNOT and DO NOT claim to detect a forgery in flight.

  - What we CAN detect, from a read-only authenticated LDAP bind, are the
    *conditions that enable* these forgeries and make them long-lived /
    stealthy. That is genuinely actionable and is what this module reports —
    clearly labelled as enabler/risk detection, not forgery detection.

Golden-ticket enablers:
  - krbtgt password age. A golden ticket forged from a stolen krbtgt hash
    stays valid until the krbtgt password is changed TWICE. An old krbtgt
    password therefore means: if that hash was ever exposed, forged TGTs are
    valid indefinitely. The age is the signal.
  - RC4 still permitted for krbtgt → RC4 golden tickets are easier to forge
    and harder to distinguish from legitimate downgrade.

Silver-ticket enablers:
  - Service / computer accounts whose Kerberos keys are RC4-only (or whose
    msDS-SupportedEncryptionTypes is unset, defaulting to RC4). A stolen
    service-account hash lets an attacker mint TGS tickets for that service
    offline, bypassing the DC entirely.

All analyzers are pure functions over LDAP-entry dicts plus an injected
reference time, so they are deterministic and offline-tested.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .ldap_client import LdapClient, decode_filetime, decode_uac, SCOPE_SUBTREE

log = logging.getLogger(__name__)

# msDS-SupportedEncryptionTypes bits (MS-KILE 2.2.7).
ENC_DES_CRC = 0x01
ENC_DES_MD5 = 0x02
ENC_RC4 = 0x04
ENC_AES128 = 0x08
ENC_AES256 = 0x10
ENC_AES = ENC_AES128 | ENC_AES256

# Golden-ticket krbtgt-age thresholds (days).
KRBTGT_AGE_HIGH = 365
KRBTGT_AGE_MEDIUM = 180
# Machine/service accounts should auto-rotate ~every 30d; long ages suggest
# rotation is disabled, widening the silver-ticket window.
MACHINE_AGE_STALE = 90


def etype_summary(value: Optional[int]) -> dict:
    """Summarise an msDS-SupportedEncryptionTypes value.

    A None/0 value means the attribute is unset — historically that is treated
    as RC4-capable, which is itself the risk.
    """
    if not value:
        return {"raw": value or 0, "unset": True, "rc4_capable": True,
                "aes_capable": False, "des_capable": False, "rc4_only": True}
    return {
        "raw": value,
        "unset": False,
        "rc4_capable": bool(value & ENC_RC4),
        "aes_capable": bool(value & ENC_AES),
        "des_capable": bool(value & (ENC_DES_CRC | ENC_DES_MD5)),
        "rc4_only": bool(value & ENC_RC4) and not (value & ENC_AES),
    }


def _age_days(filetime_value, now: datetime) -> Optional[int]:
    dt = decode_filetime(filetime_value)
    if dt is None:
        return None
    return (now - dt).days


def assess_krbtgt(entry: dict, now: datetime) -> Optional[dict]:
    """Golden-ticket enabler assessment for the krbtgt account entry.

    `entry`: {"attributes": {"pwdLastSet": [...],
                              "msDS-SupportedEncryptionTypes": [...]}}
    """
    a = entry["attributes"]
    pwd_last_set = _first(a, "pwdLastSet")
    enc = _first(a, "msDS-SupportedEncryptionTypes")
    age = _age_days(pwd_last_set, now) if pwd_last_set is not None else None
    etypes = etype_summary(int(enc) if enc not in (None, "") else None)

    if age is None:
        severity = "INFO"
        reason = "krbtgt pwdLastSet unreadable; cannot assess golden-ticket age."
    elif age >= KRBTGT_AGE_HIGH:
        severity = "HIGH"
        reason = (f"krbtgt password is {age} days old. Any krbtgt hash exposed "
                  f"in that window can forge golden tickets valid until krbtgt "
                  f"is rotated TWICE. Rotate krbtgt now (twice, 24h apart).")
    elif age >= KRBTGT_AGE_MEDIUM:
        severity = "MEDIUM"
        reason = (f"krbtgt password is {age} days old — exceeds the 180-day "
                  f"hygiene threshold for golden-ticket exposure window.")
    else:
        severity = "INFO"
        reason = (f"krbtgt password age {age} days is within hygiene range; "
                  f"still double-rotate after any suspected DC compromise.")

    if etypes["rc4_capable"]:
        reason += (" RC4 is permitted for krbtgt, making forged golden tickets "
                   "stealthier (encryption downgrade).")
    return {
        "kind": "golden_ticket_risk",
        "detection_type": "enabler",   # NOT an active-forgery detection
        "account": "krbtgt",
        "krbtgt_password_age_days": age,
        "encryption": etypes,
        "severity": severity,
        "title": "Golden-ticket exposure window (krbtgt password hygiene)",
        "reason": reason,
    }


def assess_silver_risk(entry: dict, now: datetime) -> Optional[dict]:
    """Silver-ticket enabler assessment for a service/computer account.

    Flags accounts whose Kerberos key is RC4-only (or unset→RC4) — a stolen
    hash for such an account allows offline TGS forgery for its services.
    Returns None when the account is AES-protected and not stale.
    """
    a = entry["attributes"]
    sam = _first(a, "sAMAccountName", "?")
    spns = _all(a, "servicePrincipalName")
    enc = _first(a, "msDS-SupportedEncryptionTypes")
    etypes = etype_summary(int(enc) if enc not in (None, "") else None)
    uac = decode_uac(_first(a, "userAccountControl", 0))
    is_computer = "WORKSTATION_TRUST_ACCOUNT" in uac["flags"] or \
        "SERVER_TRUST_ACCOUNT" in uac["flags"] or sam.endswith("$")

    pwd_age = (_age_days(_first(a, "pwdLastSet"), now)
               if _first(a, "pwdLastSet") is not None else None)
    stale_machine = (is_computer and pwd_age is not None
                     and pwd_age > MACHINE_AGE_STALE)

    if not etypes["rc4_only"] and not stale_machine:
        return None  # AES-protected and not stale → no silver-ticket flag

    reasons = []
    severity = "MEDIUM"
    if etypes["rc4_only"]:
        reasons.append("RC4-only Kerberos keys" if not etypes["unset"]
                       else "msDS-SupportedEncryptionTypes unset (defaults RC4)")
        if spns:
            severity = "HIGH"
            reasons.append(f"{len(spns)} SPN(s) present — a stolen hash forges "
                           f"TGS tickets for these services offline")
    if stale_machine:
        reasons.append(f"machine-account password {pwd_age} days old "
                       f"(>{MACHINE_AGE_STALE}d) — auto-rotation likely disabled")
        severity = "HIGH" if spns else severity

    return {
        "kind": "silver_ticket_risk",
        "detection_type": "enabler",
        "account": sam,
        "is_computer": is_computer,
        "spn_count": len(spns),
        "encryption": etypes,
        "password_age_days": pwd_age,
        "severity": severity,
        "title": "Silver-ticket enabler (forgeable service key)",
        "reason": "; ".join(reasons) + ".",
    }


def assess(krbtgt_entry: Optional[dict], service_entries: list[dict],
           now: Optional[datetime] = None) -> dict:
    """Run the full risk assessment over collected entries."""
    now = now or datetime.now(timezone.utc)
    findings: list[dict] = []
    if krbtgt_entry:
        kf = assess_krbtgt(krbtgt_entry, now)
        if kf:
            findings.append(kf)
    for e in service_entries:
        sf = assess_silver_risk(e, now)
        if sf:
            findings.append(sf)
    return {
        "findings": findings,
        "summary": {
            "golden_ticket_risks": sum(1 for f in findings
                                       if f["kind"] == "golden_ticket_risk"),
            "silver_ticket_risks": sum(1 for f in findings
                                       if f["kind"] == "silver_ticket_risk"),
        },
        "note": ("These are forgery ENABLERS detected from directory state, "
                 "not detections of active forged tickets (which require "
                 "DC-side event/PAC telemetry)."),
    }


# ── helpers (case-insensitive multi-valued attribute access) ────────────
def _first(attrs: dict, key: str, default=None):
    for k, v in attrs.items():
        if k.lower() == key.lower() and v:
            return v[0]
    return default


def _all(attrs: dict, key: str) -> list:
    for k, v in attrs.items():
        if k.lower() == key.lower():
            return v
    return []


# ── live collection ────────────────────────────────────────────────────────
def run_ticket_risk_audit(host: str, domain: str, username: str,
                          password: str, *, base_dn: Optional[str] = None,
                          use_ssl: bool = False,
                          netbios_domain: Optional[str] = None) -> dict:
    """Authenticate, collect krbtgt + service/computer accounts, assess risk."""
    attrs = ["sAMAccountName", "pwdLastSet", "msDS-SupportedEncryptionTypes",
             "servicePrincipalName", "userAccountControl"]
    client = LdapClient(host, use_ssl=use_ssl)
    client.connect()
    try:
        nb = netbios_domain or domain.split(".")[0]
        client.bind_ntlm(nb, username, password)
        if not base_dn:
            rdse = client.root_dse()
            base_dn = (rdse.get("defaultNamingContext") or [""])[0]
        krbtgt_rows = client.search(base_dn, "(sAMAccountName=krbtgt)", attrs,
                                    scope=SCOPE_SUBTREE)
        service_rows = client.paged_search(
            base_dn,
            "(|(servicePrincipalName=*)(objectCategory=computer))",
            attrs, scope=SCOPE_SUBTREE, page_size=500)
        result = assess(krbtgt_rows[0] if krbtgt_rows else None, service_rows)
        result["domain"] = domain.upper()
        return result
    finally:
        client.close()
