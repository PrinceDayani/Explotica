"""Cross-module constants — single source of truth.

Phase 57 — created to eliminate the drift between 20+ files that each had
their own copy of the User-Agent string, scanner version, and default
timeouts. When you need to bump the version or change the UA string,
change it HERE. All callers must import from this module.

Don't add module-specific constants here — only things that genuinely
cross module boundaries.
"""

from __future__ import annotations

# ── Version ─────────────────────────────────────────────────────────────
# Bump this on release. Used in:
#   - HTTP User-Agent header
#   - ScanResult.scanner_version field
#   - report headers (HTML/PDF/MD)
#   - JSON output meta
SCANNER_VERSION = "0.7.0"  # Phase 57

# ── HTTP identity ───────────────────────────────────────────────────────
USER_AGENT = f"explotica/{SCANNER_VERSION}"

# Some modules want a more browser-like UA for crawling to avoid being
# served bot-specific responses. The web crawler / Playwright / web fuzzer
# can use this variant.
BROWSER_USER_AGENT = (
    f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) Chrome/120.0 Safari/537.36 explotica/{SCANNER_VERSION}"
)

# ── Default timeouts (seconds) — keyed by operation class ───────────────
# Modules SHOULD use these via:
#     from .constants import TIMEOUT
#     timeout = TIMEOUT["banner"]
# rather than scattering 1.5 / 2.0 / 3.0 / 5.0 literals across the codebase.
TIMEOUT = {
    "port_probe":     0.4,   # single TCP-connect probe
    "banner":         1.0,   # passive read for banner
    "deep_probe":     2.5,   # active version probe (TLS handshake, etc.)
    "http":           5.0,   # one HTTP request (audit, crawl, fuzz)
    "tls_handshake":  3.0,
    "snmp":           2.0,
    "discovery":      2.0,   # ARP / ICMP sweep wait
    "nmap":         180.0,   # single nmap invocation
    "ssh":            8.0,   # one SSH connection attempt
    "winrm":          8.0,
    "credentialed":  15.0,   # one shell command via SSH/WinRM
    "nvd":           20.0,   # NVD API request (rate-limited)
    "epss":           8.0,
    "shodan":         8.0,
    "playwright":    20.0,   # one full page load + JS settle
}

# ── Concurrency defaults (workers) ──────────────────────────────────────
# Each preset corresponds to a CLI mode that scales these proportionally.
CONCURRENCY = {
    "normal":     {"port": 1000, "banner": 32,  "host": 16},
    "aggressive": {"port": 2000, "banner": 64,  "host": 24},
    "ultra":      {"port": 3000, "banner": 96,  "host": 32},
    "turbo":      {"port": 5000, "banner": 128, "host": 48},
}
