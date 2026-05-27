"""Searchsploit integration — Exploit-DB lookups for identified products.

Searchsploit is the offline mirror of Exploit-DB shipped with Kali (and
installable via apt elsewhere). Given a product name + version, it returns
known exploits with title, path, type, platform, and EDB ID.

Why this matters: CVE lookups give you VULNERABILITIES (a flaw exists).
Searchsploit gives you EXPLOITS (working code that abuses the flaw). For
authorized testing, an exploit reference is far more actionable than a
CVE alone.

Output format (`searchsploit -j <query>`):
{
  "RESULTS_EXPLOIT": [
    {"Title": "...", "EDB-ID": "12345", "Path": "...",
     "Type": "remote", "Platform": "linux", ...},
    ...
  ],
  "RESULTS_SHELLCODE": [...]
}
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from concurrent.futures import Future
from threading import Lock
from typing import Optional

from .models import Exploit, Host, Port

log = logging.getLogger(__name__)


def searchsploit_available() -> bool:
    return shutil.which("searchsploit") is not None


# In-process cache — same (product, version) across hosts → one searchsploit call
_inflight_lock = Lock()
_inflight: dict[str, Future] = {}


def _lookup_uncached(query: str, timeout: int = 30) -> list[Exploit]:
    """Run searchsploit -j <query> and parse the JSON output."""
    cmd = ["searchsploit", "-j", query]
    log.info("searchsploit: %s", query)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        log.warning("searchsploit timed out for %s", query)
        return []
    except FileNotFoundError:
        log.warning("searchsploit not installed — skipping")
        return []

    if proc.returncode != 0 and not proc.stdout:
        log.debug("searchsploit non-zero exit for %s: %s",
                  query, proc.stderr[:120])
        return []

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as e:
        log.debug("searchsploit JSON parse failed for %s: %s", query, e)
        return []

    results: list[Exploit] = []
    for entry in data.get("RESULTS_EXPLOIT", []):
        edb_id = entry.get("EDB-ID")
        url = f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else None
        results.append(Exploit(
            title=entry.get("Title", "(no title)"),
            edb_id=str(edb_id) if edb_id else None,
            path=entry.get("Path"),
            type=entry.get("Type"),
            platform=entry.get("Platform"),
            author=entry.get("Author"),
            date=entry.get("Date_Published") or entry.get("Date"),
            url=url,
            source="searchsploit",
        ))
    return results


def lookup_exploits(product: str, version: Optional[str] = None,
                    timeout: int = 30) -> list[Exploit]:
    """Search Exploit-DB via searchsploit. Returns matching Exploit objects.

    Cached in-process so repeated lookups across hosts cost one query.
    """
    if not product:
        return []
    if not searchsploit_available():
        return []

    # Construct query string. Searchsploit does fuzzy matching, so include
    # version when we have it for tighter matches.
    query = f"{product} {version}" if version else product
    query = query.strip()

    with _inflight_lock:
        fut = _inflight.get(query)
        owner = False
        if fut is None:
            fut = Future()
            _inflight[query] = fut
            owner = True

    if owner:
        try:
            result = _lookup_uncached(query, timeout=timeout)
            fut.set_result(result)
        except Exception as e:
            fut.set_exception(e)

    try:
        return fut.result(timeout=60)
    except Exception as e:
        log.warning("searchsploit inflight error for %s: %s", query, e)
        return []


def enrich_port_with_exploits(port: Port, timeout: int = 30) -> None:
    """Look up exploits for a port's identified product, populate port.exploits."""
    if not port.product_name:
        return
    exploits = lookup_exploits(
        port.product_name,
        version=port.product_version,
        timeout=timeout,
    )
    if not exploits:
        return
    # Dedup by EDB-ID
    seen = {e.edb_id for e in port.exploits if e.edb_id}
    for e in exploits:
        if e.edb_id and e.edb_id in seen:
            continue
        port.exploits.append(e)
        if e.edb_id:
            seen.add(e.edb_id)


def enrich_host_with_exploits(host: Host, timeout: int = 30) -> None:
    """Walk a host's ports, look up exploits for each fingerprinted product."""
    for p in host.ports:
        try:
            enrich_port_with_exploits(p, timeout=timeout)
        except Exception as e:
            log.debug("searchsploit enrich %s:%d failed: %s",
                      host.ip, p.number, e)
