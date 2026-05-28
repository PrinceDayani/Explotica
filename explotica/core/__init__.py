"""Core foundation — models, constants, port classification.

These modules have ZERO dependencies on other explotica sub-packages.
Everything else depends on them. If you're adding a new module,
import freely from here — there's no risk of circular dependency.
"""

from .constants import (
    SCANNER_VERSION,
    USER_AGENT,
    BROWSER_USER_AGENT,
    TIMEOUT,
    CONCURRENCY,
)
from .models import (
    CVE,
    Exploit,
    Host,
    Port,
    ScanResult,
)
from .port_classifier import (
    is_http,
    is_https,
    is_http_like,
    is_tls,
    is_smb,
    is_dns,
    is_database,
    is_remote_admin,
    is_email,
    is_open,
)

__all__ = [
    # constants
    "SCANNER_VERSION", "USER_AGENT", "BROWSER_USER_AGENT",
    "TIMEOUT", "CONCURRENCY",
    # models
    "CVE", "Exploit", "Host", "Port", "ScanResult",
    # port classifier
    "is_http", "is_https", "is_http_like", "is_tls", "is_smb",
    "is_dns", "is_database", "is_remote_admin", "is_email", "is_open",
]
