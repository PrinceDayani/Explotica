"""Platform capability detection — Phase 66.

Reports what's available on the current platform so callers can degrade
gracefully. Linux is the first-class target; Windows is best-effort.

Usage:
    from explotica.core.platform_caps import detect
    caps = detect()
    if not caps.scapy_works:
        log.warning("ARP/SYN scan unavailable — install Npcap on Windows")
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformCaps:
    """What we can actually do on this machine."""

    os_name: str               # 'linux' | 'darwin' | 'windows' | 'other'
    is_linux: bool
    is_macos: bool
    is_windows: bool

    # Python features
    has_sigterm: bool          # Windows lacks SIGTERM
    has_uvloop: bool           # Linux/macOS only

    # Network capabilities
    scapy_works: bool          # ARP / SYN scanning possible
    raw_sockets_likely: bool   # Root/admin + scapy installed
    is_root: bool              # geteuid() == 0 (Unix) / Admin token (Windows)

    # External binaries
    has_nmap: bool
    has_searchsploit: bool
    has_snmpwalk: bool
    has_trivy: bool
    has_ip_route: bool         # Linux only
    has_route_print: bool      # Windows fallback

    # Optional libs
    has_paramiko: bool         # SSH credentialed scan
    has_pywinrm: bool          # WinRM credentialed scan
    has_textual: bool          # TUI
    has_playwright: bool       # Browser crawler
    has_weasyprint: bool       # PDF reports

    def summary(self) -> str:
        """Human-readable summary suitable for --help / startup banner."""
        lines = [
            "Platform: " + self.os_name + (" (" + sys.platform + ")"),
            "Running as root/admin: " + ("yes" if self.is_root else "no"),
            "",
            "Capability matrix:",
            "  scapy ARP/SYN scan: " + _yn(self.scapy_works),
            "  raw sockets:        " + _yn(self.raw_sockets_likely),
            "  uvloop accel:       " + _yn(self.has_uvloop),
            "",
            "Optional binaries:",
            "  nmap:               " + _yn(self.has_nmap),
            "  searchsploit:       " + _yn(self.has_searchsploit),
            "  snmpwalk:           " + _yn(self.has_snmpwalk),
            "  trivy:              " + _yn(self.has_trivy),
            "",
            "Optional libraries:",
            "  paramiko (SSH):     " + _yn(self.has_paramiko),
            "  pywinrm (WinRM):    " + _yn(self.has_pywinrm),
            "  textual (TUI):      " + _yn(self.has_textual),
            "  playwright (web):   " + _yn(self.has_playwright),
            "  weasyprint (PDF):   " + _yn(self.has_weasyprint),
        ]
        return "\n".join(lines)


def _yn(b: bool) -> str:
    return "available" if b else "MISSING"


def _has_module(name: str) -> bool:
    """Check if a Python module is importable without actually importing it
    into our namespace (and triggering side effects)."""
    import importlib.util
    try:
        spec = importlib.util.find_spec(name)
        return spec is not None
    except (ImportError, ValueError):
        return False


def _is_root() -> bool:
    """True if running with elevated privileges."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0   # type: ignore[attr-defined]
    # Windows: check via ctypes
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def _scapy_works() -> bool:
    """Check if scapy can actually send packets. On Windows this requires
    Npcap; on Linux/macOS it just needs scapy installed + root."""
    if not _has_module("scapy"):
        return False
    if os.name == "nt":
        # Windows: scapy needs Npcap (or WinPcap). Cheap test: try to
        # import the Windows-specific sub-package.
        return _has_module("scapy.arch.windows")
    return True


def detect() -> PlatformCaps:
    """Detect current platform capabilities. Pure introspection — fast + safe."""
    plat = sys.platform
    is_linux = plat.startswith("linux")
    is_macos = plat == "darwin"
    is_windows = plat in ("win32", "cygwin")
    os_name = ("linux" if is_linux else
               "darwin" if is_macos else
               "windows" if is_windows else
               "other")

    return PlatformCaps(
        os_name=os_name,
        is_linux=is_linux,
        is_macos=is_macos,
        is_windows=is_windows,
        # Python signal subset
        has_sigterm=hasattr(__import__("signal"), "SIGTERM"),
        has_uvloop=_has_module("uvloop") and not is_windows,
        # Network
        scapy_works=_scapy_works(),
        raw_sockets_likely=_scapy_works() and _is_root(),
        is_root=_is_root(),
        # Binaries
        has_nmap=shutil.which("nmap") is not None,
        has_searchsploit=shutil.which("searchsploit") is not None,
        has_snmpwalk=shutil.which("snmpwalk") is not None,
        has_trivy=shutil.which("trivy") is not None,
        has_ip_route=(is_linux and shutil.which("ip") is not None),
        has_route_print=(is_windows
                          and (shutil.which("route") is not None
                                or os.path.exists(r"C:\Windows\System32\route.exe"))),
        # Optional libs
        has_paramiko=_has_module("paramiko"),
        has_pywinrm=_has_module("winrm"),
        has_textual=_has_module("textual"),
        has_playwright=_has_module("playwright"),
        has_weasyprint=_has_module("weasyprint"),
    )
