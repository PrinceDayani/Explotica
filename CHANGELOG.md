# Changelog

All notable changes to Explotica are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — Phase 70: Active Directory deep-audit cluster

Closes four limitations-doc gaps with real, offline-verified implementations
(no mock/placeholder data):

### Added
- `explotica/ad/ldap_client.py` — pure-Python authenticated LDAP v3 client:
  BER codec, RFC 4515 filter compiler, simple + NTLMv2 (SASL GSS-SPNEGO) bind,
  paged search, and objectSid/objectGUID/FILETIME/UAC decoders. In-module MD4
  (OpenSSL 3 dropped it from hashlib). The keystone every credentialed AD
  capability needed.
- `explotica/ad/secdesc.py` — MS-DTYP security-descriptor/DACL/ACE parser
  mapping access masks + object-type GUIDs to BloodHound edges (GenericAll,
  WriteDacl, WriteOwner, ForceChangePassword, AddMember, AllExtendedRights,
  GetChanges/All -> synthesized DCSync, ReadGMSAPassword, WriteSPN).
- `explotica/ad/bloodhound.py` — real BloodHound-CE collector/exporter with
  genuine SIDs, group membership, ACL edges, GPOs, and an honest
  `partial_export_from_enum()` for the unauth path that refuses to fabricate
  SIDs.
- `explotica/ad/adcs.py` — ADCS ESC1-ESC8 audit over real msPKI attributes +
  enrollment ACLs; ESC8 web-enrollment network probe; ESC6 flagged for
  CA-registry verification (not falsely claimed).
- `explotica/ad/ticket_risk.py` — Golden/Silver ticket *enabler* detection
  (krbtgt password age, RC4-only service keys), honestly scoped as risk
  detection, not active-forgery detection.
- CLI: `--ad-creds`, `--ad-dc`, `--ad-ssl`, `--bloodhound[-out]`,
  `--adcs-audit`, `--ticket-risk`, with rich summary reporting.

### Changed
- `ad_enum.to_bloodhound_format` now delegates to the honest partial exporter
  instead of fabricating `S-1-5-21-PLACEHOLDER-<hash>` SIDs.

### Tests
- 82 new offline tests (BER/MD4/NTLMv2 vectors, ACE->edge mapping incl. DCSync,
  ESC condition logic, ticket-risk thresholds, no-fabrication guards). Suite:
  250 passing.

## [0.8.0] — Phase 62: Production Readiness

### Added
- `README.md` — full installation, usage, and architecture documentation
- `pyproject.toml` — proper PEP 517 packaging with `pip install -e .`
- `CHANGELOG.md` — release history
- `tests/` folder — pytest suite with 50+ unit tests covering safety,
  models, port classifier, ports, banners
- `explotica/safety.py` — scope enforcement (block probes outside declared
  target range), authorization gate (interactive confirmation for active
  checks), safe-mode (disable all damaging checks), rate limiter
- `explotica/logging_config.py` — env-driven log configuration
  (`EXPLOTICA_LOG_LEVEL`, `EXPLOTICA_LOG_FILE`, `EXPLOTICA_LOG_FORMAT`),
  with plain + JSON output formats
- `explotica/shutdown.py` — graceful shutdown on Ctrl+C, emergency dump
  of in-flight scan data to JSON before exit
- Entry points in `pyproject.toml`: `explotica`, `explotica-tui`,
  `explotica-dashboard`, `explotica-shell`

### Changed
- Optional dependencies organized into extras (`pip install explotica[all]`,
  `[databases]`, `[dashboard]`, `[tui]`, etc.)
- Bumped version to 0.8.0 across the codebase

### Production safety
- Scope enforcement: `--strict-scope` (default) refuses to probe IPs
  outside the declared `--target`. Use `--no-strict-scope` to allow.
- Authorization banner shown before any active checks
- `EXPLOTICA_I_AM_AUTHORIZED=1` env var bypasses banner (for CI/scheduled runs)

## [0.7.0] — Phase 61: Integration

### Added
- Wired all Phase 58/59/60 modules into `scanner.run_scan` + CLI
- 8 new CLI flags: `--db-fingerprint`, `--db-creds`, `--use-cred-vault`,
  `--snmp-inventory`, `--web-appscan`, `--container-scan`, `--kube-token`,
  `--subdomain-enum`

### Changed
- `db_fingerprint.fingerprint_mysql` → uses full `mysql_protocol` path
- `db_fingerprint.fingerprint_mssql` → uses full TDS 7.4 protocol
- `network_spider.snmp_walk_routes` → uses native multi-PDU `bulk_walk`
- `kerberoast.asrep_roast_user` → uses proper ASN.1 parser + multi-cipher
  hashcat formatter (correctly handles RC4/AES128/AES256)
- `ics.probe_ics_host` → dispatches to extended ICS protocols
  (OPC-UA, IEC-104, CIP, Niagara, CODESYS, FINS, Profinet)
- `takeover.TAKEOVER_FINGERPRINTS` → 77 services (was 10)
- `creds_scan.credentialed_scan_hosts` → accepts `VaultProfile` with
  priority-ordered credential rotation

## [0.7.0-pre] — Phases 58, 59, 60

### Added
- Phase 58: `credential_vault.py` (priority-ordered credential storage),
  cache TTL 1-day enforcement in `nvd.py`, EPSS combined risk scoring +
  trend analysis, `db_dispatch.json` data-driven dispatcher
- Phase 59: `mysql_protocol.py` (full handshake + capability negotiation +
  auth + COM_QUERY), `mssql_protocol.py` (full TDS 7.4 PRELOGIN + TLS upgrade +
  LOGIN7 + token-stream parsing), `snmp_native.py` (true multi-PDU
  GetBulkRequest walk)
- Phase 60: `ics_extended.py` (10 new ICS protocols),
  `kerberos_advanced.py` (proper ASN.1 DER parser + per-etype hashcat
  formatting), `subdomain_extended.py` (75-service takeover DB +
  permutation engine)

## [0.6.0] — Phases 53b, 53c, 54, 55, 57b

### Added
- Phase 53b: `db_fingerprint.py` — 9 database product families
- Phase 53c: `snmp_inventory.py` — SNMP v1/v2c/v3 walks
- Phase 54: `web_appscan.py` — OWASP-class form fuzzer + OpenAPI discovery
- Phase 55: `container_scan.py` — Docker + K8s + CIS audit + Trivy
- Phase 57b: completed User-Agent unification across all modules

## [0.5.0] — Phases 53a, 56, 57

### Added
- Phase 53a: SSH OS-dispatch for 9 OS families (Linux + Solaris + HP-UX +
  AIX + macOS + FreeBSD + OpenBSD + 4 network-device OSes)
- Phase 56: Scanner core honesty — full port range default, state-aware
  classification (open/closed/filtered), content-based banner cascade
- Phase 57: `constants.py` + `port_classifier.py` — single source of
  truth for port classification

## [0.4.0] — Phases 50, 51, 52

### Added
- Phase 50: TUI host action menu + concurrent process tracker
- Phase 51: Full scan setup screen + command palette
- Phase 52: TUI honesty — configurable actions, visible errors, diagnostics

## [0.3.0] — Phases 36–49

### Added
- Phases 36–49: Credentialed SSH/WinRM, OS fingerprint DB, 41 verify probes,
  compliance frameworks, web fuzzing, wizard, shell, network spider, TUI

## [0.2.0] — Phases 10–35

### Added
- Phases 10–35: Rich intel, protocol probes, web crawl, service probes,
  OSINT, network fabric, async I/O, SYN scan, dashboard, AD enum, Playwright,
  monitoring daemon, plugins, default creds, takeover, cloud, ICS,
  prioritization, Kerberos, SMTP, PDF/MD reports, honeypot detection

## [0.1.0] — Phases 1–9

### Added
- Initial scaffold: discovery, port scanning, banner grabbing
- Phase 1–9: NVD CVE matching, active probes, nmap NSE, multi-subnet auto,
  parallel probes, perf optimization, searchsploit, NVD cache + keepalive
