"""OSINT layer — external intel sources that don't touch the target.

  - crt.sh Certificate Transparency: every cert ever issued for a domain
  - team-cymru ASN lookup via DNS: ASN, prefix, country, ISP name
  - RDAP WHOIS: structured domain ownership data
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

CACHE_DIR = Path(
    os.environ.get("EXPLOTICA_CACHE_DIR",
                   Path.home() / ".cache" / "explotica" / "osint")
)
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_TTL = 7 * 24 * 3600


def _cache_read(key: str) -> Optional[dict]:
    p = CACHE_DIR / f"{key}.json"
    if not p.exists():
        return None
    if time.time() - p.stat().st_mtime > CACHE_TTL:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _cache_write(key: str, data: dict) -> None:
    try:
        (CACHE_DIR / f"{key}.json").write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


# ── crt.sh Certificate Transparency subdomain enumeration ────────────────
def crtsh_subdomains(domain: str, timeout: float = 15.0) -> Optional[dict]:
    """Query crt.sh for all SANs of certs issued to *.domain.

    Returns dict with sorted list of unique subdomains found.

    Phase 64: scope-enforced — refuses to enumerate a domain that's
    outside the active scope. Prevents OSINT leakage when scope is set.
    """
    # Phase 64: scope enforcement
    try:
        from ..safety_kit.safety import get_active_scope
        scope = get_active_scope()
        if scope is not None and not scope.permits(domain):
            log.warning("crt.sh skipped: %s outside scope", domain)
            return None
    except ImportError:
        pass

    key = f"crtsh_{domain.replace('.', '_')}"
    cached = _cache_read(key)
    if cached is not None:
        return cached

    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={
        "User-Agent": "explotica/0.7.0",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except Exception as e:
        log.warning("crt.sh fetch failed for %s: %s", domain, e)
        return None

    try:
        rows = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return None

    subs: set[str] = set()
    for row in rows:
        nv = row.get("name_value", "") or ""
        for name in nv.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and (name == domain or name.endswith("." + domain)):
                subs.add(name)
    result = {
        "domain": domain,
        "subdomain_count": len(subs),
        "subdomains": sorted(subs),
        "cert_rows": len(rows),
    }
    log.info("crt.sh: %s -> %d subdomain(s) from %d cert(s)",
             domain, len(subs), len(rows))
    _cache_write(key, result)
    return result


# ── team-cymru ASN lookup via DNS ────────────────────────────────────────
def cymru_asn_lookup(ip: str, timeout: float = 4.0) -> Optional[dict]:
    """Resolve <reversed-ip>.origin.asn.cymru.com TXT — returns ASN/prefix/country/ISP.

    Format: "AS-number | prefix | country | registry | allocation-date"
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback:
        return None

    rev = ".".join(reversed(ip.split(".")))
    qname = f"{rev}.origin.asn.cymru.com"
    try:
        socket.setdefaulttimeout(timeout)
        # Use stdlib resolver; query TXT records via getaddrinfo isn't possible,
        # so we build a raw DNS query.
        from .dns_enum import _query, _RR_TYPES
        answers = _query(qname, _RR_TYPES["TXT"], server="8.8.8.8",
                          timeout=timeout)
    except Exception as e:
        log.debug("cymru ASN %s failed: %s", ip, e)
        return None
    finally:
        socket.setdefaulttimeout(None)

    if not answers:
        return None
    record = answers[0]
    parts = [p.strip() for p in record.split("|")]
    if len(parts) < 4:
        return {"raw": record}
    result = {
        "asn": parts[0],
        "prefix": parts[1],
        "country": parts[2],
        "registry": parts[3],
        "allocated": parts[4] if len(parts) > 4 else None,
    }
    # Optional second lookup for ISP name: AS<num>.asn.cymru.com TXT
    asn_num = parts[0].split()[0] if parts[0] else ""
    if asn_num:
        try:
            isp_answers = _query(f"AS{asn_num}.asn.cymru.com",
                                  _RR_TYPES["TXT"], timeout=timeout)
            if isp_answers:
                isp_parts = [p.strip() for p in isp_answers[0].split("|")]
                if len(isp_parts) >= 5:
                    result["isp_name"] = isp_parts[4]
        except Exception:
            pass
    return result


# ── RDAP WHOIS (modern WHOIS replacement) ────────────────────────────────
def rdap_lookup(domain_or_ip: str, timeout: float = 10.0) -> Optional[dict]:
    """RDAP query via rdap.org — works for both domains and IPs."""
    is_ip = False
    try:
        ipaddress.ip_address(domain_or_ip)
        is_ip = True
    except ValueError:
        pass
    obj_type = "ip" if is_ip else "domain"
    url = f"https://rdap.org/{obj_type}/{urllib.parse.quote(domain_or_ip)}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "explotica/0.7.0",
        "Accept": "application/rdap+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        log.debug("RDAP %s failed: %s", domain_or_ip, e)
        return None

    # Distill the response to a flat-ish dict
    result: dict = {"query": domain_or_ip, "type": obj_type}
    if "handle" in data:
        result["handle"] = data["handle"]
    if "ldhName" in data:
        result["ldh_name"] = data["ldhName"]
    if "country" in data:
        result["country"] = data["country"]
    if "startAddress" in data:
        result["start_address"] = data["startAddress"]
    if "endAddress" in data:
        result["end_address"] = data["endAddress"]
    if "name" in data:
        result["name"] = data["name"]

    # Status flags
    statuses = data.get("status", [])
    if statuses:
        result["status"] = statuses

    # Events (registration, expiration, last update)
    events = data.get("events", [])
    if events:
        result["events"] = [
            {"action": e.get("eventAction"), "date": e.get("eventDate")}
            for e in events[:6]
        ]

    # Entities (registrars, abuse contacts)
    entities = data.get("entities", [])
    if entities:
        ent_list = []
        for ent in entities[:5]:
            ent_list.append({
                "handle": ent.get("handle"),
                "roles": ent.get("roles"),
            })
        result["entities"] = ent_list

    # Nameservers (for domain queries)
    nameservers = data.get("nameservers", [])
    if nameservers:
        result["nameservers"] = [
            ns.get("ldhName") for ns in nameservers if ns.get("ldhName")
        ]

    return result


# ── Aggregate ────────────────────────────────────────────────────────────
def run_osint(target: str, hosts) -> dict:
    """Run the full OSINT layer. Returns dict to attach to ScanResult."""
    out: dict = {}

    # Domain target -> crt.sh + RDAP domain
    is_domain = any(c.isalpha() for c in target) and "/" not in target
    if is_domain:
        try:
            ct = crtsh_subdomains(target)
            if ct:
                out["crtsh"] = ct
        except Exception as e:
            log.warning("crt.sh failed: %s", e)
        try:
            wh = rdap_lookup(target)
            if wh:
                out["rdap_domain"] = wh
        except Exception as e:
            log.warning("RDAP domain failed: %s", e)

    # Per-host ASN + RDAP IP — parallelized across hosts.
    out["asn_per_host"] = {}
    out["rdap_per_host"] = {}

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _asn(h):
        try:
            return (h.ip, cymru_asn_lookup(h.ip))
        except Exception as e:
            log.debug("ASN %s failed: %s", h.ip, e)
            return (h.ip, None)

    # ASN lookups in parallel — DNS is fast, network-bound
    with ThreadPoolExecutor(max_workers=16) as pool:
        for f in as_completed([pool.submit(_asn, h) for h in hosts]):
            ip, asn = f.result()
            if asn:
                out["asn_per_host"][ip] = asn

    # RDAP only for unique prefixes (one lookup per /24 of address space)
    seen_prefixes: set[str] = set()
    rdap_targets: list[str] = []
    for ip, asn in out["asn_per_host"].items():
        prefix = asn.get("prefix", "")
        if prefix and prefix not in seen_prefixes:
            seen_prefixes.add(prefix)
            rdap_targets.append(ip)

    def _rdap(ip):
        try:
            return (ip, rdap_lookup(ip))
        except Exception as e:
            log.debug("RDAP %s failed: %s", ip, e)
            return (ip, None)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for f in as_completed([pool.submit(_rdap, ip) for ip in rdap_targets]):
            ip, rdap = f.result()
            if rdap:
                out["rdap_per_host"][ip] = rdap

    return out
