"""MAC OUI → vendor lookup.

Ships with a tiny built-in table covering the most common vendors so the tool
works offline. For full coverage, drop the IEEE OUI file at data/oui.txt and
call load_oui_file().
"""

from __future__ import annotations

from pathlib import Path

# First 3 bytes (OUI) → vendor. Lowercase, no separators.
_BUILTIN: dict[str, str] = {
    "001a11": "Google",
    "001b63": "Apple",
    "001c42": "Parallels",
    "001e8c": "ASUSTek",
    "0021cc": "Flaircomm",
    "0024d7": "Intel",
    "0050ba": "D-Link",
    "0050c2": "IEEE Registration",
    "0050f2": "Microsoft",
    "002590": "Super Micro",
    "00259c": "Cisco-Linksys",
    "00904c": "Epigram",
    "00a040": "Apple",
    "08002b": "DEC",
    "080027": "VirtualBox",
    "0a0027": "VirtualBox-host",
    "1c1b0d": "Nvidia",
    "286ab8": "Apple",
    "3c2200": "Google",
    "3c5ab4": "Google",
    "3ca067": "Liteon",
    "4ccc6a": "Espressif (ESP32)",
    "5254": "QEMU/KVM",
    "5404a6": "ASUSTek",
    "60f262": "Microsoft",
    "70b3d5": "IEEE Registration",
    "74d435": "Giga-Byte",
    "78e3b5": "TP-Link",
    "8c1645": "Apple",
    "8c8590": "Apple",
    "94c691": "ASUSTek",
    "ac220b": "ASUSTek",
    "b827eb": "Raspberry Pi",
    "b8270e": "Raspberry Pi",
    "bcd074": "Apple",
    "c40bcb": "Liteon",
    "d83bbf": "Intel",
    "dca632": "Raspberry Pi",
    "e4a471": "Intel",
    "f0d4e8": "Dell",
    "f4f5e8": "Google",
    "fcfbfb": "Cisco",
}

_loaded: dict[str, str] = dict(_BUILTIN)


def _normalize(mac: str) -> str:
    return mac.lower().replace(":", "").replace("-", "").replace(".", "")[:6]


def lookup(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = _normalize(mac)
    if prefix in _loaded:
        return _loaded[prefix]
    # Some entries use 4-char prefix (vendor block with sub-allocation)
    if prefix[:4] in _loaded:
        return _loaded[prefix[:4]]
    return None


def load_oui_file(path: str | Path) -> int:
    """Load IEEE OUI textfile. Returns number of entries loaded.

    Format expected (IEEE oui.txt):
      00-1A-11   (hex)        Google, Inc.
    """
    count = 0
    p = Path(path)
    if not p.exists():
        return 0
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "(hex)" not in line:
            continue
        try:
            prefix_part, vendor_part = line.split("(hex)", 1)
            prefix = _normalize(prefix_part.strip())
            vendor = vendor_part.strip()
            if prefix and vendor:
                _loaded[prefix] = vendor
                count += 1
        except ValueError:
            continue
    return count
