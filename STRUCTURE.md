# Explotica module structure

Phase 65 reorganization. 75 files moved from a flat directory into 14
topic-based sub-packages.

## Top-level (entry points + orchestration)

| File | Role |
|---|---|
| `explotica/__init__.py` | Package root — backward-compat re-exports |
| `explotica/__main__.py` | `python -m explotica` entry point |
| `explotica/scanner.py` | The orchestrator — coordinates the full pipeline |
| `explotica/cli.py` | CLI flag parsing + dispatch |

## Sub-packages

```
explotica/
├── core/          ← models, constants, port_classifier (ZERO deps; everything imports here)
├── safety_kit/    ← safety, shutdown, checkpoint, retry, logging_config
├── discovery/     ← discovery, aio, ports, syn_scan, network_spider, enumerate, netfabric, udp_probes
├── fingerprint/   ← banners, service_fp*, protocol_probes, os_fingerprint, os_fp_db, oui
├── vulns/         ← vulnscan, nvd, epss_kev, verify_probes*, searchsploit, nmap_wrap, prioritize
├── protocols/     ← mysql_protocol, mssql_protocol, snmp_native, kerberos_advanced
├── credentialed/  ← creds_scan, winrm_scan, db_fingerprint, snmp_inventory, credential_vault
├── enrich/        ← tls_scan, http_scan, http_audit, smb_scan, ssh_enum, dns_enum, web_crawler, playwright_crawler, osint, shodan_lite
├── active/        ← web_fuzz, web_appscan, web_security, default_creds, takeover, subdomain_extended, smtp_test, container_scan
├── ad/            ← ad_enum, kerberoast
├── specialized/   ← ics, ics_extended, cloud_assets, honeypot, compliance
├── output/        ← report, report_pdf, dashboard
├── ui/            ← tui, tui_config, shell, interactive
└── runtime/       ← daemon, plugins
```

## Dependency rules

Each sub-package may depend on:

| Sub-package | Can depend on |
|---|---|
| `core` | (nothing) |
| `safety_kit` | core |
| `discovery` | core, safety_kit |
| `fingerprint` | core, discovery |
| `vulns` | core, safety_kit, fingerprint |
| `protocols` | core, safety_kit |
| `credentialed` | core, safety_kit, protocols, vulns |
| `enrich` | core, safety_kit, fingerprint |
| `active` | core, safety_kit, fingerprint, enrich |
| `ad` | core, safety_kit, protocols |
| `specialized` | core, safety_kit, fingerprint |
| `output` | core |
| `ui` | core, safety_kit, output (+ anything for interactive use) |
| `runtime` | core, safety_kit |

`scanner.py` and `cli.py` at the top level are the only modules
allowed to import from *every* sub-package.

## Backward compatibility

The top-level `explotica/__init__.py` re-exports every moved module so
external user scripts keep working:

```python
# Old code still works:
from explotica.ports import scan_ports    # resolves via shim
from explotica.scanner import run_scan    # unchanged

# Equivalent new (preferred):
from explotica.discovery.ports import scan_ports
from explotica.core import Port           # via __all__ in core/__init__.py
```

## Public API per sub-package

Each sub-package's `__init__.py` declares `__all__` — that's the public
API. Anything not in `__all__` is internal and may change without notice.

Example:

```python
# explotica/core/__init__.py
__all__ = ["CVE", "Port", "Host", "ScanResult", ...]

# Usage:
from explotica.core import Port, Host  # always supported
from explotica.core.models import _internal_helper  # implicitly private
```

## Tools

```bash
# Find god modules + bottlenecks
python tools/dep_graph.py

# Generate visual dependency graph
python tools/dep_graph.py --dot graph.dot
dot -Tsvg graph.dot -o graph.svg
```

## Adding new modules

1. Pick the sub-package that fits the topic
2. Drop a new `.py` file inside that folder
3. Add its public symbols to that package's `__init__.py` `__all__`
4. Update `STRUCTURE.md` if a new sub-package is needed (rare)
