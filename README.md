# Explotica

**Comprehensive network vulnerability scanner** — discovery, port scanning, service
fingerprinting, CVE matching, and OWASP-class web application scanning, all in
one tool. Built in Python with state-of-the-art async I/O.

> ⚠️ **Authorized use only.** Scanning systems you do not own or have explicit
> permission to test is illegal in most jurisdictions. Read the
> [Authorization Policy](#authorization-policy) before first use.

[![Phase](https://img.shields.io/badge/phase-62-blue)](https://github.com/PrinceDayani/Explotica)
[![License](https://img.shields.io/badge/license-personal-orange)](#license)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)

---

## What it does

| Capability | Details |
|---|---|
| **Discovery** | ARP sweep (LAN), ICMP echo, TTL fingerprinting |
| **Port scanning** | TCP connect, async I/O, masscan-class SYN scanning, state-aware (open/closed/filtered) |
| **Service identification** | Content-based banner cascade — 14+ protocols, 30+ service fingerprints |
| **CVE matching** | NVD passive lookup + EPSS scores + CISA KEV catalog + 41 hand-written verification probes |
| **Database fingerprinting** | Full native protocols: MySQL (handshake+auth+query), MSSQL TDS 7.4, PostgreSQL, Oracle TNS, MongoDB, Redis, Memcached, Elasticsearch, CouchDB, InfluxDB |
| **Credentialed scanning** | SSH (9 OS families: Linux/Solaris/HP-UX/AIX/macOS/FreeBSD/OpenBSD/network devices), WinRM, SNMP v1/v2c/v3 |
| **Active checks** | nmap NSE wrapper, searchsploit, default credentials, subdomain takeover (77 service fingerprints) |
| **Web app scanning** | OWASP-class: form discovery + per-input fuzz (SQLi/XSS/SSRF/traversal) + OpenAPI discovery + session-aware |
| **Container scanning** | Docker daemon enum + 8-rule CIS Benchmark audit + Trivy DB integration + Kubernetes pod enum + kubelet exposure detection |
| **Industrial Control Systems** | Modbus, BACnet, DNP3, S7, EthIP, OPC-UA, IEC-104, CIP, Niagara Fox, CODESYS, FINS |
| **Active Directory** | BloodHound-class enumeration, AS-REP roast (RC4/AES128/AES256 hashcat output), Kerberoast |
| **Network topology** | Recursive subnet discovery via SNMP route tables + traceroute |
| **Output** | JSON, HTML (Cytoscape graph), PDF, Markdown, BloodHound JSON |
| **Interfaces** | CLI, Textual TUI, FastAPI dashboard, REPL shell, wizard mode |

## Installation

### Quick start (Kali / Ubuntu / Debian)

```bash
git clone https://github.com/PrinceDayani/Explotica
cd Explotica
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Optional system tools

For maximum coverage, install:

```bash
# nmap (for --use-nmap NSE scripts)
sudo apt install nmap

# net-snmp (fallback for SNMP v3 walks)
sudo apt install snmp

# searchsploit (Exploit-DB references)
sudo apt install exploitdb

# trivy (container image vulnerability scanning)
# Follow https://aquasecurity.github.io/trivy/
```

### Browser-based crawling (optional)

```bash
playwright install chromium
```

### Database driver dependencies (optional, per database)

```bash
pip install pymysql      # MySQL/MariaDB auth
pip install psycopg2     # PostgreSQL auth
pip install pymssql      # MSSQL auth
pip install pymongo      # MongoDB auth
pip install redis        # Redis (passive enrichment)
```

## Authorization Policy

**Before you scan anything:**

1. ✅ Confirm you have **explicit written permission** from the asset owner
2. ✅ Document the scope in writing (target IP ranges, allowed times, allowed checks)
3. ✅ Notify your security team / incident response before starting
4. ✅ Read the warnings about active checks (`--check-default-creds`,
   `--check-takeover`, `--web-fuzz`, `--ad-enum`, `--asrep-roast`)

**Active checks that could cause harm:**

| Flag | Risk |
|---|---|
| `--check-default-creds` | Account lockout on multiple failed attempts |
| `--asrep-roast` | Generates failed authentication logs |
| `--check-takeover` | Sends HTTP requests to potentially-third-party services |
| `--web-fuzz` / `--web-appscan` | May trigger WAF blocks, fill error logs, lock accounts |
| `--syn-scan` (raw sockets) | IDS detection; may be illegal without authorization |
| `--container-scan` (Trivy) | Pulls image data from registries |

**Use `--safe-mode` to disable all checks that can write/modify state.**

## Quick examples

```bash
# Discovery only — fastest, safest
explotica 192.168.1.0/24 --no-arp

# Vulnerability scan with CVE matching
explotica 192.168.1.0/24 --vuln-scan --epss-kev --json scan.json

# Deep scan with active version probes + nmap NSE
explotica 192.168.1.0/24 --deep --use-nmap --use-searchsploit

# Full-coverage everything (authorized use only)
explotica 10.0.0.0/24 --full-coverage --json scan.json

# Database-aware scan with credentials
explotica 192.168.1.0/24 --db-fingerprint \
  --db-creds "mysql:root:s3cret,postgres:admin:p4ss" \
  --json scan.json

# Web application scan
explotica example.com --web-appscan --sqli-time --json scan.json

# Container + K8s
explotica 10.0.0.0/24 --container-scan --kube-token "$KUBE_TOKEN"

# Re-analyze existing scan (no network)
explotica --from-json scan.json --prioritize --report-html report.html
```

## Interfaces

### CLI

```bash
explotica --help
```

300+ flags grouped by phase. Use `--full-coverage` as a safe-by-default preset.

### Textual TUI

```bash
explotica --tui scan.json
```

6-tab interactive view (Hosts/CVEs/Ports/Exploits/Compliance/Extra). Per-host
action menu with concurrent process tracker. Edit action presets in
`~/.config/explotica/actions.json`.

### REPL shell

```bash
explotica --shell
```

38 commands. Auto-loads recent scans. Helpful for incident-response triage.

### Web dashboard

```bash
explotica --dashboard scan.json
```

FastAPI + Cytoscape network graph at `http://localhost:8765`.

### Wizard

```bash
explotica --interactive
```

Tiered prompts for new users. Generates a CLI invocation you can save.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for diagrams.

```
Discovery → Port scan → Banner cascade → Service fingerprint
                                       ↓
                          CVE match (NVD) + EPSS + KEV
                                       ↓
        ┌──────────────────────────────┼──────────────────────────────┐
   Active probes              Enrichment                    Risk scoring
   (--deep)                   (--rich-intel)                 (--prioritize)
        │                              │                              │
        └──────────────────────────────┼──────────────────────────────┘
                                       ↓
                          Output (JSON / HTML / PDF / MD)
```

## Production deployment

### Memory

For a /24 with full port range (`--ports all`), peak memory ~600 MB. Bump
`ulimit -n` to 8192+ on Linux to avoid file-descriptor exhaustion under
high concurrency (`--ultra` or `--turbo`).

### Rate limiting

Active checks honor a soft throttle. Per-target probe rate caps at
~10 packets/sec by default. Override with `--rate-pps N` (use responsibly).

### Cache

CVE / EPSS / KEV / Shodan data is cached for 24 hours under
`~/.cache/explotica/`. Delete to force refresh.

### Logging

```bash
export EXPLOTICA_LOG_LEVEL=DEBUG  # or INFO/WARNING/ERROR
export EXPLOTICA_LOG_FILE=/var/log/explotica.log
```

### Scheduled scans

Use the daemon mode for continuous monitoring:

```bash
explotica --daemon --target 192.168.1.0/24 --interval 6h \
  --slack-webhook "$SLACK_URL"
```

Daemon stores history in SQLite (`~/.local/share/explotica/history.db`)
and posts diff-alerts when new ports/services/CVEs appear.

## Plugins

Explotica supports plugins via entry points. See
[explotica/plugins.py](explotica/plugins.py).

```python
# my_plugin/setup.py
setup(
    name="my-explotica-plugin",
    entry_points={
        "explotica.modules": [
            "my_check = my_plugin.module:run",
        ],
    },
)
```

## Limitations vs Nessus

| Capability | Explotica | Nessus Pro |
|---|---|---|
| Discovery / port scan | ✅ (faster) | ✅ |
| CVE plugin coverage | ~5–10k effective | 200,000+ |
| Authenticated scanning | 12+ targets | Many more (databases, Solaris+AIX++) |
| Compliance content | 18 rules | 100+ audit policies |
| Web app scanning | OWASP-class basics | Tenable WAS ($$$) |
| Container scanning | Docker + K8s + Trivy | Yes (registry + runtime) |
| AD enumeration | BloodHound-class | Plugin-based |
| ICS scanning | 16 protocols | Tenable.ot ($$$) |
| Network spider | ✅ | ❌ |
| Honeypot detection | ✅ | ❌ |
| Free + open source | ✅ | ❌ |
| Enterprise support | ❌ | ✅ |

## Contributing

This is a personal project but PRs are welcome. Please:

1. Run the test suite: `pytest tests/`
2. Follow the existing module style (see `explotica/scanner.py`)
3. Add tests for new functionality
4. Update CHANGELOG.md

## License

Personal-use project. See LICENSE.

## Disclaimer

This tool is provided for **authorized security testing only**. The authors
accept no liability for misuse. Network scanning of systems you do not own
or have explicit permission to test is illegal in many jurisdictions
including under the Computer Fraud and Abuse Act (US), the Computer Misuse
Act (UK), and similar laws worldwide. **You are solely responsible for
ensuring you have authorization before using this tool.**
