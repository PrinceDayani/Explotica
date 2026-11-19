"""Production safety — scope enforcement + authorization gate + safe-mode.

Phase 62 — production hardening.

Three pillars:
  1. Scope enforcement — block probes outside the user-declared target range
  2. Authorization gate — explicit confirmation required before active checks
  3. Safe-mode — disables every check that could cause harm

This module is intended to be IMPORTED EVERYWHERE active checks run. The
helpers below are dependency-free and cheap to call.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import sys
from typing import Optional

log = logging.getLogger(__name__)


# ── Scope enforcement ───────────────────────────────────────────────────
def _strip_zone(target: str) -> str:
    """Drop an IPv6 zone/scope id (``fe80::1%eth0`` → ``fe80::1``).

    ``ipaddress`` does not accept a zone suffix, but scanners pass link-local
    addresses with one. Non-IPv6 strings are returned unchanged.
    """
    if "%" in target and ":" in target:
        return target.split("%", 1)[0]
    return target


class ScopeViolation(RuntimeError):
    """Raised when an in-flight probe targets something outside the declared
    scope. Don't swallow this — surface it to the user."""


class Scope:
    """Tracks the set of IP networks + domain suffixes that scans are
    authorized to touch."""

    def __init__(self, *, networks: Optional[list[str]] = None,
                  domains: Optional[list[str]] = None,
                  strict: bool = True):
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.domains: set[str] = set()
        self.strict = strict
        self.violations: list[dict] = []
        for cidr in networks or []:
            self.add_network(cidr)
        for d in domains or []:
            self.add_domain(d)

    @classmethod
    def from_target(cls, target: str, strict: bool = True) -> "Scope":
        """Build a scope from a single --target argument.

        Accepts IPv4 and IPv6:
          - "192.168.1.0/24"     → adds the /24 network
          - "192.168.1.5"        → adds /32 host
          - "2001:db8::/32"      → adds the IPv6 /32 network
          - "::1"                → adds /128 host
          - "example.com"        → adds the bare domain + *.example.com
          - "auto"               → empty scope; caller adds discovered subnets
          - comma-separated mix  → multiple
        """
        s = cls(strict=strict)
        for piece in target.split(","):
            piece = piece.strip()
            if not piece or piece == "auto":
                continue
            if "/" in piece:
                s.add_network(piece)
                continue
            try:
                # A bare host (v4 or v6); ip_network turns it into /32 or /128.
                ipaddress.ip_address(piece)
                s.add_network(piece)
            except ValueError:
                s.add_domain(piece)
        return s

    def add_network(self, cidr: str) -> None:
        # Strip any IPv6 zone id first: ipaddress.ip_network rejects a scoped
        # address on some Python versions, which would otherwise leave the
        # scope empty (and an empty scope permits everything). permits()
        # strips the zone on the target side too, so matching stays correct.
        cidr = _strip_zone(cidr)
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net not in self.networks:
                self.networks.append(net)
        except ValueError:
            log.warning("invalid CIDR in scope: %s", cidr)

    def add_domain(self, domain: str) -> None:
        d = domain.lower().lstrip(".")
        if d:
            self.domains.add(d)

    def permits(self, target: str) -> bool:
        """Check whether `target` is inside the declared scope."""
        if not self.networks and not self.domains:
            return True
        try:
            addr = ipaddress.ip_address(_strip_zone(target))
            for net in self.networks:
                # Membership across address families raises; compare only
                # same-version network/address pairs.
                if addr.version == net.version and addr in net:
                    return True
        except ValueError:
            t = target.lower().lstrip(".")
            if t in self.domains:
                return True
            for d in self.domains:
                if t.endswith("." + d) or t == d:
                    return True

        violation = {"target": target, "reason": "outside-declared-scope"}
        self.violations.append(violation)
        if self.strict:
            log.error("SCOPE VIOLATION: target %s is outside declared scope.",
                      target)
            return False
        log.warning("scope-warn: %s outside scope but allowed (non-strict)",
                    target)
        return True

    def require(self, target: str) -> None:
        if not self.permits(target) and self.strict:
            raise ScopeViolation(
                "target " + str(target) + " is outside the declared scope."
            )

    def __repr__(self) -> str:
        return ("Scope(networks=" + str([str(n) for n in self.networks])
                + ", domains=" + str(sorted(self.domains))
                + ", strict=" + str(self.strict) + ")")


_active_scope: Optional[Scope] = None


def set_active_scope(scope: Scope) -> None:
    global _active_scope
    _active_scope = scope
    log.info("active scope: %s", scope)


def get_active_scope() -> Optional[Scope]:
    return _active_scope


def in_scope(target: str) -> bool:
    s = get_active_scope()
    if s is None:
        return True
    return s.permits(target)


def require_in_scope(target: str) -> None:
    s = get_active_scope()
    if s is not None:
        s.require(target)


# ── Safe-mode ───────────────────────────────────────────────────────────
class SafeMode:
    """Tracks which active-check categories are currently disabled."""

    BLOCKABLE_CHECKS = frozenset({
        "default_creds", "asrep_roast", "kerberoast",
        "web_fuzz", "web_appscan", "sqli_time",
        "smtp_relay", "takeover_post", "syn_scan",
        "active_probes",
    })

    def __init__(self, blocked: Optional[set[str]] = None):
        self.blocked: set[str] = set(blocked or [])

    @classmethod
    def safe_all(cls) -> "SafeMode":
        return cls(set(cls.BLOCKABLE_CHECKS))

    @classmethod
    def disabled(cls) -> "SafeMode":
        return cls(set())

    def is_blocked(self, check: str) -> bool:
        return check in self.blocked

    def gate(self, check: str, *, message: str = "") -> bool:
        """Return True if the check is ALLOWED to proceed."""
        if check in self.blocked:
            log.info("safe-mode: blocked '%s' %s", check, message)
            return False
        return True


_active_safe_mode: SafeMode = SafeMode.disabled()


def set_safe_mode(sm: SafeMode) -> None:
    global _active_safe_mode
    _active_safe_mode = sm


def get_safe_mode() -> SafeMode:
    return _active_safe_mode


def safe_to_run(check: str) -> bool:
    return _active_safe_mode.gate(check)


# ── Authorization gate ──────────────────────────────────────────────────
def _auth_banner_text(target: str, active_checks: list[str]) -> str:
    """Build banner text via string concatenation (avoids .format hook)."""
    sep = "=" * 75
    checks_lines = "\n".join("    - " + c for c in active_checks)
    parts = [
        "",
        sep,
        "                    EXPLOTICA - AUTHORIZATION REQUIRED",
        sep,
        "",
        "You are about to scan: " + target,
        "",
        "ACTIVE CHECKS ENABLED:",
        checks_lines,
        "",
        "By proceeding, you confirm:",
        "  * You have explicit written authorization to scan this target",
        "  * You understand active checks may trigger security alerts, account",
        "    lockouts, log noise, or service disruption",
        "  * You accept full legal responsibility for the scan",
        "",
        "Unauthorized scanning is illegal under the Computer Fraud and Abuse Act",
        "(US), the Computer Misuse Act (UK), and similar laws worldwide.",
        "",
        sep,
        "",
    ]
    return "\n".join(parts)


def show_authorization_banner(target: str, active_checks: list[str],
                                 *, force_yes: bool = False,
                                 stream=sys.stderr) -> bool:
    """Print the authorization banner and require explicit confirmation."""
    if not active_checks:
        return True

    stream.write(_auth_banner_text(target, active_checks))
    stream.flush()

    if os.environ.get("EXPLOTICA_I_AM_AUTHORIZED") == "1" or force_yes:
        stream.write("[auto-yes] EXPLOTICA_I_AM_AUTHORIZED=1\n")
        return True

    try:
        answer = input("Type 'I AM AUTHORIZED' to proceed: ").strip()
    except (EOFError, KeyboardInterrupt):
        stream.write("\n[aborted]\n")
        return False
    return answer == "I AM AUTHORIZED"


def classify_args_risk(args) -> tuple[list[str], list[str]]:
    """Inspect parsed CLI args. Return (low_risk_checks, active_checks)."""
    low_risk: list[str] = []
    active: list[str] = []

    passive_map = {
        "vuln_scan": "passive CVE matching (NVD lookup)",
        "epss_kev": "EPSS / KEV enrichment",
        "rich_intel": "TLS / HTTP / SMB enrichment (rate-limited)",
        "osint": "OSINT (crt.sh / WHOIS / ASN)",
        "shodan": "Shodan InternetDB lookup",
        "dns_enum": "DNS subdomain enumeration (passive)",
    }
    for k, label in passive_map.items():
        if getattr(args, k, False):
            low_risk.append(label)

    active_map = {
        "deep": "ACTIVE: deep version probes",
        "use_nmap": "ACTIVE: nmap NSE scripts",
        "syn_scan": "ACTIVE: SYN scan (raw sockets, IDS-visible)",
        "web_crawl": "ACTIVE: HTTP crawler (rate-limited)",
        "web_fuzz": "DANGEROUS: web fuzzing (injection payloads)",
        "web_appscan": "DANGEROUS: OWASP-class fuzzing (forms + APIs)",
        "sqli_time": "DANGEROUS: time-based SQL injection (5s delays)",
        "check_default_creds": "DANGEROUS: default credentials (LOCKOUT RISK)",
        "check_takeover": "ACTIVE: subdomain takeover HTTP requests",
        "smtp_audit": "ACTIVE: SMTP open-relay test",
        "ad_enum": "ACTIVE: AD enumeration (LDAP + Kerberos)",
        "asrep_roast": "DANGEROUS: AS-REP roast (FAILED AUTH LOGS)",
        "container_scan": "ACTIVE: Docker daemon + Trivy",
        "verify_cves": "ACTIVE: CVE verification probes",
        "verify_cves_v2": "ACTIVE: extended CVE verification probes",
    }
    for k, label in active_map.items():
        if getattr(args, k, False):
            active.append(label)

    if getattr(args, "all_the_things", False):
        active.append("DANGEROUS: --all-the-things enables EVERY active check")

    return (low_risk, active)


# ── Rate limiting ───────────────────────────────────────────────────────
class RateLimiter:
    """Simple token-bucket rate limiter.

    Thread-safe: acquire() serializes its timing update so a single limiter
    shared across worker threads enforces one global packets/sec budget rather
    than one-per-thread.
    """

    def __init__(self, pps: float):
        import threading
        import time
        self._time = time
        self._lock = threading.Lock()
        self.pps = max(0.1, pps)
        self.interval = 1.0 / self.pps
        self._last = 0.0

    def acquire(self) -> None:
        with self._lock:
            now = self._time.monotonic()
            wait = self._last + self.interval - now
            if wait > 0:
                self._last = now + wait
            else:
                self._last = now
                wait = 0.0
        if wait > 0:
            self._time.sleep(wait)


# Global budget shared across scan phases. None = unlimited (the default, so
# ordinary scans are not throttled). Set a real cap with --max-rate.
_default_rate_limiter: Optional[RateLimiter] = None


def set_global_rate_limit(pps: float) -> None:
    """Install (or clear) the global packets/sec budget. pps<=0 → unlimited."""
    global _default_rate_limiter
    _default_rate_limiter = RateLimiter(pps=pps) if pps and pps > 0 else None


def get_global_rate_limiter() -> Optional[RateLimiter]:
    return _default_rate_limiter


def acquire_global() -> None:
    """Block as needed to honour the global rate budget; no-op when unlimited.

    Safe and cheap to call on every network operation in the scan hot path.
    """
    rl = _default_rate_limiter
    if rl is not None:
        rl.acquire()
