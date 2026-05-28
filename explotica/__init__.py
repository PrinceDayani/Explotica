"""Explotica — comprehensive network vulnerability scanner.

Package re-exports for backward compatibility. After Phase 65
reorganization, modules live in topic-based sub-packages, but the
top-level imports still resolve to the new locations.
"""

from .core.constants import SCANNER_VERSION as __version__

# Backward-compat re-exports — added by _reorg.py.
# These let existing user scripts like `from explotica.ports import
# scan_ports` keep working after the file moved to discovery/ports.py.

from .ad import ad_enum  # noqa: F401
from .discovery import aio  # noqa: F401
from .fingerprint import banners  # noqa: F401
from .safety_kit import checkpoint  # noqa: F401
from .specialized import cloud_assets  # noqa: F401
from .specialized import compliance  # noqa: F401
from .core import constants  # noqa: F401
from .active import container_scan  # noqa: F401
from .credentialed import credential_vault  # noqa: F401
from .credentialed import creds_scan  # noqa: F401
from .runtime import daemon  # noqa: F401
from .output import dashboard  # noqa: F401
from .credentialed import db_fingerprint  # noqa: F401
from .active import default_creds  # noqa: F401
from .discovery import discovery  # noqa: F401
from .enrich import dns_enum  # noqa: F401
from .discovery import enumerate  # noqa: F401
from .vulns import epss_kev  # noqa: F401
from .specialized import honeypot  # noqa: F401
from .enrich import http_audit  # noqa: F401
from .enrich import http_scan  # noqa: F401
from .specialized import ics  # noqa: F401
from .specialized import ics_extended  # noqa: F401
from .ui import interactive  # noqa: F401
from .ad import kerberoast  # noqa: F401
from .protocols import kerberos_advanced  # noqa: F401
from .safety_kit import logging_config  # noqa: F401
from .core import models  # noqa: F401
from .protocols import mssql_protocol  # noqa: F401
from .protocols import mysql_protocol  # noqa: F401
from .discovery import netfabric  # noqa: F401
from .discovery import network_spider  # noqa: F401
from .vulns import nmap_wrap  # noqa: F401
from .vulns import nvd  # noqa: F401
from .fingerprint import os_fingerprint  # noqa: F401
from .fingerprint import os_fp_db  # noqa: F401
from .enrich import osint  # noqa: F401
from .fingerprint import oui  # noqa: F401
from .enrich import playwright_crawler  # noqa: F401
from .runtime import plugins  # noqa: F401
from .core import port_classifier  # noqa: F401
from .discovery import ports  # noqa: F401
from .vulns import prioritize  # noqa: F401
from .fingerprint import protocol_probes  # noqa: F401
from .output import report  # noqa: F401
from .output import report_pdf  # noqa: F401
from .safety_kit import retry  # noqa: F401
from .safety_kit import safety  # noqa: F401
from .vulns import searchsploit_wrap  # noqa: F401
from .fingerprint import service_fp  # noqa: F401
from .fingerprint import service_fp_db  # noqa: F401
from .fingerprint import service_probes_v2  # noqa: F401
from .ui import shell  # noqa: F401
from .enrich import shodan_lite  # noqa: F401
from .safety_kit import shutdown  # noqa: F401
from .enrich import smb_scan  # noqa: F401
from .active import smtp_test  # noqa: F401
from .credentialed import snmp_inventory  # noqa: F401
from .protocols import snmp_native  # noqa: F401
from .enrich import ssh_enum  # noqa: F401
from .active import subdomain_extended  # noqa: F401
from .discovery import syn_scan  # noqa: F401
from .active import takeover  # noqa: F401
from .enrich import tls_scan  # noqa: F401
from .ui import tui  # noqa: F401
from .ui import tui_config  # noqa: F401
from .discovery import udp_probes  # noqa: F401
from .vulns import verify_probes  # noqa: F401
from .vulns import verify_probes_v2  # noqa: F401
from .vulns import vulnscan  # noqa: F401
from .active import web_appscan  # noqa: F401
from .enrich import web_crawler  # noqa: F401
from .active import web_fuzz  # noqa: F401
from .active import web_security  # noqa: F401
from .credentialed import winrm_scan  # noqa: F401
