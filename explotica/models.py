"""Data models — the contract every layer (scanner, CLI, web, TUI) agrees on."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class CVE:
    """One vulnerability matched against a service version."""
    id: str                         # e.g. CVE-2021-44228
    severity: str = "UNKNOWN"       # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    cvss: Optional[float] = None    # numeric base score, e.g. 9.8
    summary: Optional[str] = None
    published: Optional[str] = None
    source: str = "NVD"             # NVD / nmap / manual
    # Prioritization signals (Phase 10):
    epss_score: Optional[float] = None      # 0.0-1.0; probability of exploitation in next 30 days
    epss_percentile: Optional[float] = None # rank among all CVEs
    in_kev: bool = False                    # CISA Known Exploited Vulnerabilities catalog

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Exploit:
    """A weaponized vulnerability — links to Exploit-DB / Metasploit."""
    title: str                       # Human-readable name
    edb_id: Optional[str] = None     # Exploit-DB ID, e.g. "49908"
    path: Optional[str] = None       # Local path inside searchsploit DB
    type: Optional[str] = None       # "remote" / "local" / "dos" / "webapps"
    platform: Optional[str] = None   # "linux" / "windows" / "multiple"
    author: Optional[str] = None
    date: Optional[str] = None
    url: Optional[str] = None        # External link (exploit-db.com URL)
    source: str = "searchsploit"     # searchsploit / msf / manual

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: str = "open"                # open / closed / filtered / unknown
    state_reason: Optional[str] = None  # "syn-ack" / "RST" / "timeout" / "ICMP host-unreachable" / etc.
    service: Optional[str] = None
    # Phase 56: did the service name come from evidence (banner/fingerprint)
    # or from a hardcoded IANA port→name lookup? Critical for honest output.
    iana_guess: bool = False           # True when service is just a port-number guess
    banner: Optional[str] = None
    # Phase 56: which banner probes were attempted (debug + audit)
    probes_attempted: list[str] = field(default_factory=list)
    # Version + vuln data (populated by --vuln-scan / --deep / --use-nmap)
    product_vendor: Optional[str] = None   # e.g. "proftpd"
    product_name: Optional[str] = None     # e.g. "proftpd"
    product_version: Optional[str] = None  # e.g. "1.3.6"
    cves: list[CVE] = field(default_factory=list)
    exploits: list[Exploit] = field(default_factory=list)
    # Rich intel (Phase 10) — dict to keep the schema flexible:
    tls_info: Optional[dict] = None         # cipher list, cert, protocols, weak flags
    http_info: Optional[dict] = None        # headers, tech stack, paths, sec headers
    smb_info: Optional[dict] = None         # shares, signing, dialect, NULL session
    tech_stack: list[str] = field(default_factory=list)  # human-readable tech labels
    # Phase 12: extra intelligence on a port
    ssh_info: Optional[dict] = None         # KEXINIT algorithms, weak-alg flags
    crawl_info: Optional[dict] = None       # web crawler findings on this HTTP port
    # Phase 13: high-impact service probes + HTTP audits
    service_intel: Optional[dict] = None    # RDP NTLM / LDAP / Docker / k8s / ES / Mongo
    http_audit_info: Optional[dict] = None  # methods, CORS, GraphQL, WP user enum

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "protocol": self.protocol,
            "state": self.state,
            "state_reason": self.state_reason,
            "service": self.service,
            "iana_guess": self.iana_guess,
            "banner": self.banner,
            "probes_attempted": self.probes_attempted,
            "product_vendor": self.product_vendor,
            "product_name": self.product_name,
            "product_version": self.product_version,
            "cves": [c.to_dict() for c in self.cves],
            "exploits": [e.to_dict() for e in self.exploits],
            "tls_info": self.tls_info,
            "http_info": self.http_info,
            "smb_info": self.smb_info,
            "tech_stack": self.tech_stack,
            "ssh_info": self.ssh_info,
            "crawl_info": self.crawl_info,
            "service_intel": self.service_intel,
            "http_audit_info": self.http_audit_info,
        }


@dataclass
class Host:
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    is_up: bool = True
    response_ms: Optional[float] = None
    ports: list[Port] = field(default_factory=list)
    # Phase 11 additions:
    os_hint: Optional[dict] = None         # {os_family, hops_estimate, initial_ttl, observed_ttl}
    ttl: Optional[int] = None              # raw observed TTL
    udp_services: Optional[dict] = None    # {snmp, mdns, ssdp, netbios} → result dicts

    def open_ports(self) -> list[Port]:
        """Subset of self.ports where state == 'open'. Phase 56: enrichment
        functions should use this instead of iterating self.ports directly,
        since closed/filtered ports are now included in self.ports."""
        return [p for p in self.ports if p.state == "open"]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "is_up": self.is_up,
            "response_ms": self.response_ms,
            "ports": [p.to_dict() for p in self.ports],
            "os_hint": self.os_hint,
            "ttl": self.ttl,
            "udp_services": self.udp_services,
        }


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    duration_s: float
    hosts: list[Host] = field(default_factory=list)
    scanner_version: str = "0.1.0"
    dns_info: Optional[dict] = None  # populated when target is a domain
    osint_info: Optional[dict] = None  # crt.sh + ASN + RDAP WHOIS
    netfabric_info: Optional[dict] = None  # DHCP discover + traceroute hops
    # Generic catch-all for additional modules (honeypot detection,
    # prioritization, AD enum, AS-REP roast, default creds, takeover,
    # cloud assets, ICS, web security analysis, etc.)
    extra_findings: Optional[dict] = None

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": self.duration_s,
            "scanner_version": self.scanner_version,
            "hosts": [h.to_dict() for h in self.hosts],
            "dns_info": self.dns_info,
            "osint_info": self.osint_info,
            "netfabric_info": self.netfabric_info,
            "extra_findings": self.extra_findings,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        hosts = [
            Host(
                ip=h["ip"],
                mac=h.get("mac"),
                vendor=h.get("vendor"),
                hostname=h.get("hostname"),
                is_up=h.get("is_up", True),
                response_ms=h.get("response_ms"),
                os_hint=h.get("os_hint"),
                ttl=h.get("ttl"),
                udp_services=h.get("udp_services"),
                ports=[
                    Port(
                        number=p["number"],
                        protocol=p.get("protocol", "tcp"),
                        state=p.get("state", "open"),
                        state_reason=p.get("state_reason"),
                        service=p.get("service"),
                        iana_guess=p.get("iana_guess", False),
                        probes_attempted=p.get("probes_attempted", []),
                        banner=p.get("banner"),
                        product_vendor=p.get("product_vendor"),
                        product_name=p.get("product_name"),
                        product_version=p.get("product_version"),
                        cves=[
                            CVE(
                                id=c["id"],
                                severity=c.get("severity", "UNKNOWN"),
                                cvss=c.get("cvss"),
                                summary=c.get("summary"),
                                published=c.get("published"),
                                source=c.get("source", "NVD"),
                                epss_score=c.get("epss_score"),
                                epss_percentile=c.get("epss_percentile"),
                                in_kev=c.get("in_kev", False),
                            )
                            for c in p.get("cves", [])
                        ],
                        tls_info=p.get("tls_info"),
                        http_info=p.get("http_info"),
                        smb_info=p.get("smb_info"),
                        tech_stack=p.get("tech_stack", []),
                        ssh_info=p.get("ssh_info"),
                        crawl_info=p.get("crawl_info"),
                        service_intel=p.get("service_intel"),
                        http_audit_info=p.get("http_audit_info"),
                        exploits=[
                            Exploit(
                                title=e["title"],
                                edb_id=e.get("edb_id"),
                                path=e.get("path"),
                                type=e.get("type"),
                                platform=e.get("platform"),
                                author=e.get("author"),
                                date=e.get("date"),
                                url=e.get("url"),
                                source=e.get("source", "searchsploit"),
                            )
                            for e in p.get("exploits", [])
                        ],
                    )
                    for p in h.get("ports", [])
                ],
            )
            for h in data.get("hosts", [])
        ]
        return cls(
            target=data["target"],
            started_at=data["started_at"],
            finished_at=data["finished_at"],
            duration_s=data.get("duration_s", 0.0),
            hosts=hosts,
            scanner_version=data.get("scanner_version", "unknown"),
            dns_info=data.get("dns_info"),
            osint_info=data.get("osint_info"),
            netfabric_info=data.get("netfabric_info"),
            extra_findings=data.get("extra_findings"),
        )
