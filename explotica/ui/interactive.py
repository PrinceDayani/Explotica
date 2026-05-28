"""Interactive setup wizard — guided scan configuration.

Invoked via `--interactive` (or no positional args). Walks the user through
a tiered series of prompts:

  Tier 1 — required: scan target type + value
  Tier 2 — preset: pick a profile (Discovery / Standard / Full / Max / Custom)
  Tier 3 — only if Custom: toggle each intel layer
  Tier 4 — optional: credentials, output formats, compliance, opt-in checks

After collection, prints the equivalent CLI command and asks for confirmation.
On confirm, builds an argparse.Namespace and runs it.
"""

from __future__ import annotations

import logging
import shlex
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

log = logging.getLogger(__name__)
console = Console()


# ── Profile presets ──────────────────────────────────────────────────────
PROFILES = {
    "1": {
        "name": "Discovery only",
        "description": "Just find hosts + open ports + banners. No CVE matching.",
        "flags": ["--aggressive"],
    },
    "2": {
        "name": "Standard scan",
        "description": "Services + CVEs + nmap. Recommended for most use.",
        "flags": ["--vuln-scan", "--deep", "--use-nmap", "--epss-kev",
                  "--aggressive"],
    },
    "3": {
        "name": "Full Coverage",
        "description": "Everything safe: all passive + analytical modules. ~2-4 min.",
        "flags": ["--full-coverage"],
    },
    "4": {
        "name": "All The Things",
        "description": ("EVERYTHING including active checks (default creds, "
                        "takeover, SMTP relay). Authorized scans only."),
        "flags": ["--all-the-things"],
    },
    "5": {
        "name": "Custom",
        "description": "Pick each layer individually.",
        "flags": [],
    },
}


SPEED_MODES = {
    "1": ("Normal", []),
    "2": ("Aggressive (workers ×8)", ["--aggressive"]),
    "3": ("Ultra (256 workers, tight timeouts)", ["--ultra"]),
    "4": ("Turbo (384 workers, reckless)", ["--turbo"]),
}


CUSTOM_LAYERS = [
    ("vuln_scan", "--vuln-scan", "Passive CVE matching from banners"),
    ("deep", "--deep", "Active version probes (HTTP GET, FTP SYST, etc.)"),
    ("use_nmap", "--use-nmap", "Nmap NSE vuln scripts"),
    ("use_searchsploit", "--use-searchsploit", "Exploit-DB references"),
    ("rich_intel", "--rich-intel", "TLS deep, HTTP deep, SMB enum"),
    ("epss_kev", "--epss-kev", "EPSS scores + CISA KEV"),
    ("unmask", "--unmask", "Protocol-specific probes for unfingerprinted ports"),
    ("udp_probe", "--udp-probe", "UDP probes (SNMP/mDNS/SSDP/NetBIOS)"),
    ("web_crawl", "--web-crawl", "HTTP crawler with JS endpoint extraction"),
    ("shodan", "--shodan", "Shodan InternetDB (public IPs only)"),
    ("ssh_enum", "--ssh-enum", "SSH algorithm enumeration"),
    ("dns_enum", "--dns-enum", "DNS records + subdomain brute"),
    ("service_intel", "--service-intel", "RDP NTLM, LDAP, Docker, k8s, ES, Mongo probes"),
    ("http_audit", "--http-audit", "HTTP methods + CORS + GraphQL + WP user enum"),
    ("osint", "--osint", "crt.sh + ASN + RDAP WHOIS"),
    ("netfabric", "--netfabric", "DHCP discovery + traceroute"),
    ("honeypot_check", "--honeypot-check", "Honeypot detection (Cowrie/Kippo/etc.)"),
    ("web_security", "--web-security", "JWT/CSP/cookie audit"),
    ("ics", "--ics", "Industrial Control Systems (Modbus/BACnet/DNP3/S7)"),
    ("prioritize", "--prioritize", "Smart vuln scoring (CVSS+EPSS+KEV+exposure)"),
    ("os_fp_db", "--os-fp-db", "Multi-signal OS fingerprinting"),
    ("verify_cves", "--verify-cves", "Top 7 verification probes (Heartbleed/MS17/etc.)"),
    ("verify_cves_v2", "--verify-cves-v2", "Extended probes (Citrix/Confluence/F5/etc.)"),
    ("check_default_creds", "--check-default-creds", "Default credential testing"),
    ("check_takeover", "--check-takeover", "Subdomain takeover detection"),
    ("smtp_audit", "--smtp-audit", "SMTP open-relay + VRFY/EXPN"),
    ("web_fuzz", "--web-fuzz", "Active web fuzzing (path/redirect/CRLF/XSS)"),
]


def _print_banner() -> None:
    console.print(Panel.fit(
        "[bold blue]🛰️  Explotica Interactive Setup[/bold blue]\n"
        "[dim]Guided scan configuration — Ctrl-C to cancel anytime[/dim]",
        border_style="blue",
    ))


def _prompt_target() -> tuple[str, list[str]]:
    """Returns (target_string, extra_flags_for_target_type)."""
    console.print("\n[bold]What do you want to scan?[/bold]")
    console.print("  [cyan]1[/cyan] Local LAN  (auto-discover all subnets)")
    console.print("  [cyan]2[/cyan] CIDR range (e.g. 192.168.1.0/24)")
    console.print("  [cyan]3[/cyan] Single host (IP or hostname)")
    console.print("  [cyan]4[/cyan] Domain name (will use --no-arp)")
    choice = Prompt.ask("[bold]Choice[/bold]", choices=["1", "2", "3", "4"],
                         default="2")
    if choice == "1":
        return ("--auto", ["--auto"])
    if choice == "2":
        target = Prompt.ask("[bold]CIDR[/bold]", default="192.168.1.0/24")
        return (target, [])
    if choice == "3":
        target = Prompt.ask("[bold]Host (IP or hostname)[/bold]")
        # If it looks like a hostname (has letters), suggest --no-arp
        if any(c.isalpha() for c in target):
            return (target, ["--no-arp"])
        return (target, [])
    # Domain
    target = Prompt.ask("[bold]Domain[/bold] (e.g. example.com)")
    return (target, ["--no-arp"])


def _prompt_ports() -> str:
    console.print("\n[bold]Port range:[/bold]")
    console.print("  [cyan]1[/cyan] Top 100 (fast — ~30s on /24)")
    console.print("  [cyan]2[/cyan] Top 1000 (recommended — ~3min on /24)")
    console.print("  [cyan]3[/cyan] All 65535 (slow — 30+ min, true full coverage)")
    console.print("  [cyan]4[/cyan] Custom (e.g. 22,80,443 or 1-1024)")
    choice = Prompt.ask("[bold]Choice[/bold]", choices=["1", "2", "3", "4"],
                         default="2")
    return {"1": "top100", "2": "top1000", "3": "all",
            "4": Prompt.ask("[bold]Custom port spec[/bold]")}[choice]


def _prompt_speed() -> list[str]:
    console.print("\n[bold]Speed mode:[/bold]")
    for k, (name, _) in SPEED_MODES.items():
        console.print(f"  [cyan]{k}[/cyan] {name}")
    choice = Prompt.ask("[bold]Choice[/bold]", choices=list(SPEED_MODES.keys()),
                         default="3")
    return SPEED_MODES[choice][1]


def _prompt_profile() -> tuple[list[str], str]:
    """Returns (flags, profile_name)."""
    console.print("\n[bold]Scan profile:[/bold]")
    for k, p in PROFILES.items():
        console.print(f"  [cyan]{k}[/cyan] [bold]{p['name']}[/bold]")
        console.print(f"     [dim]{p['description']}[/dim]")
    choice = Prompt.ask("[bold]Choice[/bold]", choices=list(PROFILES.keys()),
                         default="3")
    return (PROFILES[choice]["flags"], PROFILES[choice]["name"])


def _prompt_custom_layers() -> list[str]:
    """When 'Custom' profile chosen, ask per-layer."""
    console.print("\n[bold]Custom layer selection:[/bold] [dim](y/n per layer)[/dim]")
    flags: list[str] = []
    for attr, flag, desc in CUSTOM_LAYERS:
        # Default: yes for safe layers, no for active/heavy
        default = attr in (
            "vuln_scan", "deep", "epss_kev", "rich_intel", "ssh_enum",
            "service_intel", "http_audit", "prioritize", "os_fp_db",
            "verify_cves",
        )
        if Confirm.ask(f"  {flag:<25} [dim]{desc}[/dim]",
                       default=default, show_default=False):
            flags.append(flag)
    return flags


def _prompt_outputs() -> list[str]:
    console.print("\n[bold]Output formats:[/bold]")
    flags: list[str] = []
    if Confirm.ask("  Save JSON?", default=True):
        flags.extend(["--json", "scans/scan.json"])
    if Confirm.ask("  Save HTML report?", default=True):
        flags.extend(["--report-html", "scans/scan.html"])
    if Confirm.ask("  Launch web dashboard after scan?", default=False):
        flags.append("--dashboard")
        flags.append("scans/scan.json")
    return flags


def _prompt_creds() -> list[str]:
    console.print("\n[bold]Optional credentials[/bold] [dim](press Enter to skip)[/dim]")
    flags: list[str] = []
    ssh = Prompt.ask("  SSH user[:password] (linux hosts)", default="")
    if ssh:
        flags.extend(["--ssh-creds", ssh])
        keyfile = Prompt.ask("  SSH key file (optional)", default="")
        if keyfile:
            flags.extend(["--ssh-key", keyfile])
    winrm = Prompt.ask("  WinRM user:password (windows hosts)", default="")
    if winrm:
        flags.extend(["--winrm-creds", winrm])
    return flags


def _prompt_advanced() -> list[str]:
    console.print("\n[bold]Advanced options[/bold] [dim](press Enter to skip)[/dim]")
    flags: list[str] = []

    comp = Prompt.ask(
        "  Compliance frameworks (cis,pci,hipaa)",
        default="",
    )
    if comp:
        flags.extend(["--compliance", comp])

    cloud = Prompt.ask("  Cloud asset discovery keyword (S3/Azure/GCP)",
                        default="")
    if cloud:
        flags.extend(["--check-cloud", cloud])

    ad_domain = Prompt.ask("  AD domain to enumerate (DC discovery + Kerberos)",
                            default="")
    if ad_domain:
        flags.extend(["--ad-enum", ad_domain])
        if Confirm.ask("  AS-REP roast on that domain?", default=False):
            flags.append("--asrep-roast")

    if Confirm.ask("  Active web fuzzing? [bold red](authorized scans only)[/bold red]",
                   default=False):
        flags.append("--web-fuzz")
        if Confirm.ask("  Include time-based SQLi (adds 5s/param)?",
                       default=False):
            flags.append("--sqli-time")

    return flags


def _build_command(args: list[str], use_sudo: bool = True) -> str:
    """Build the shell command for display."""
    cmd_parts = []
    if use_sudo:
        cmd_parts.append("sudo")
    cmd_parts.extend([".venv/bin/python", "-m", "explotica"])
    cmd_parts.extend(args)
    return " ".join(shlex.quote(p) if " " in p else p for p in cmd_parts)


def run_wizard() -> Optional[list[str]]:
    """Run the wizard. Returns final argv list (excluding `python -m explotica`)
    or None if user cancels."""
    _print_banner()

    # Tier 1: target
    target, target_flags = _prompt_target()

    # Tier 1.5: port range (only if not --auto)
    extra_args: list[str] = []
    if target != "--auto":
        ports = _prompt_ports()
        extra_args = ["--ports", ports]

    # Tier 2: profile
    profile_flags, profile_name = _prompt_profile()
    if profile_name == "Custom":
        profile_flags = _prompt_custom_layers()

    # Speed
    speed_flags = _prompt_speed()

    # Outputs
    output_flags = _prompt_outputs()

    # Credentials
    cred_flags = _prompt_creds()

    # Advanced
    adv_flags = _prompt_advanced()

    # Assemble
    full_args: list[str] = []
    if target == "--auto":
        full_args.append("--auto")
    else:
        full_args.append(target)
    full_args.extend(target_flags)
    full_args.extend(extra_args)
    full_args.extend(profile_flags)
    full_args.extend(speed_flags)
    full_args.extend(output_flags)
    full_args.extend(cred_flags)
    full_args.extend(adv_flags)

    # Dedupe target_flags clash (--auto already in)
    if "--auto" in full_args:
        seen = []
        for a in full_args:
            if a not in seen or not a.startswith("--"):
                seen.append(a)
        full_args = seen

    # Show summary
    console.print()
    console.print(Panel.fit(
        f"[bold]Equivalent command:[/bold]\n[cyan]{_build_command(full_args)}[/cyan]",
        title="Review",
        border_style="green",
    ))

    if not Confirm.ask("[bold green]Confirm and run?[/bold green]", default=True):
        console.print("[dim]Cancelled.[/dim]")
        return None
    return full_args
