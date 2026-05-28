"""MAC OUI → vendor lookup.

Ships with a tiny built-in table covering the most common vendors so the tool
works offline. For full coverage, drop the IEEE OUI file at data/oui.txt and
call load_oui_file().
"""

from __future__ import annotations

from pathlib import Path

# First 3 bytes (OUI) → vendor. Lowercase, no separators.
# Curated table covering common consumer/SOHO/enterprise gear. For full IEEE
# coverage (~35k entries), call load_oui_file() with a downloaded oui.txt.
_BUILTIN: dict[str, str] = {
    # Apple
    "001b63": "Apple", "00a040": "Apple", "286ab8": "Apple",
    "8c1645": "Apple", "8c8590": "Apple", "bcd074": "Apple",
    "f0d1a9": "Apple", "f0dbf8": "Apple", "f0f61c": "Apple",
    "a4b197": "Apple", "a4d1d2": "Apple", "ac3c0b": "Apple",
    # ASUSTek
    "001e8c": "ASUSTek", "5404a6": "ASUSTek", "94c691": "ASUSTek",
    "ac220b": "ASUSTek", "1c872c": "ASUSTek", "2c4d54": "ASUSTek",
    "382c4a": "ASUSTek", "50465d": "ASUSTek", "704d7b": "ASUSTek",
    # Google / Nest
    "001a11": "Google", "3c2200": "Google", "3c5ab4": "Google",
    "f4f5e8": "Google", "9c5cf9": "Google (Nest)",
    # Cisco / Cisco-Linksys / Meraki
    "00259c": "Cisco-Linksys", "fcfbfb": "Cisco",
    "0017df": "Cisco", "001b54": "Cisco", "0023ab": "Cisco",
    # TP-Link  (you have these on the LAN)
    "78e3b5": "TP-Link", "bc3260": "TP-Link", "bc325f": "TP-Link",
    "240bb8": "TP-Link", "240b88": "TP-Link",
    "5c628b": "TP-Link", "9c5322": "TP-Link", "ac84c6": "TP-Link",
    "b0487a": "TP-Link", "d8470b": "TP-Link", "ec086b": "TP-Link",
    "f4f26d": "TP-Link", "f81a67": "TP-Link",
    # D-Link
    "0050ba": "D-Link", "001cf0": "D-Link", "1cbdb9": "D-Link",
    "28107b": "D-Link", "5cd998": "D-Link",
    # Netgear
    "001b2f": "Netgear", "00146c": "Netgear", "20e52a": "Netgear",
    "284977": "Netgear", "44a56e": "Netgear", "9c3dcf": "Netgear",
    # ASUS routers / Mediatek
    "002590": "Super Micro",
    "0c9d92": "ASUSTek", "30859a": "ASUSTek",
    # Synology  (your NAS at .200 is 24:5e:be)
    "245ebe": "Synology", "001132": "Synology", "0011321a": "Synology",
    "0c92": "Synology",
    # QNAP
    "00089b": "QNAP", "245ebe": "Synology",
    # Microsoft (incl. Xbox, Surface)
    "0050f2": "Microsoft", "60f262": "Microsoft",
    "001dd8": "Microsoft", "28184c": "Microsoft", "382c4a": "Microsoft",
    "7c1e52": "Microsoft", "98293f": "Microsoft", "c8348e": "Microsoft",
    # Intel  (NICs, NUCs, Wi-Fi cards)
    "0024d7": "Intel", "d83bbf": "Intel", "e4a471": "Intel",
    "0c8bfd": "Intel", "1ce62b": "Intel", "34e6d7": "Intel",
    "5c5181": "Intel", "7c7635": "Intel", "9020a6": "Intel",
    "a0a8cd": "Intel", "b88198": "Intel", "c8158d": "Intel",
    "dc97ba": "Intel", "f47b09": "Intel",
    # Dell
    "f0d4e8": "Dell", "001143": "Dell", "0015c5": "Dell",
    "001d09": "Dell", "00188b": "Dell", "1866da": "Dell",
    "5c260a": "Dell", "78ac44": "Dell", "b083fe": "Dell",
    # HP / HPE / Aruba (lots — heavy printer presence on your LAN: 40:c2:ba)
    "40c2ba": "HP (printers)", "001321": "HP", "001f29": "HP",
    "0023ae": "HP", "002522": "HP", "002655": "HP",
    "002a4b": "HP", "0030c1": "HP", "10604b": "HP",
    "2c41f4": "HP", "308d99": "HP", "3464a9": "HP",
    "3c4a92": "HP", "3cd92b": "HP", "44485d": "HP",
    "4c1885": "HP", "5c8a38": "HP", "70106f": "HP",
    "84a93e": "HP", "9457a5": "HP", "9c8e99": "HP",
    "a0d3c1": "HP", "b8af67": "HP", "d05099": "HP",
    "d8d385": "HP", "e0071b": "HP", "ec8eb5": "HP",
    "f80f41": "HP", "fc15b4": "HP",
    # Liteon  (used in many laptops, e.g. .4 with e0:2e:fe)
    "3ca067": "Liteon", "c40bcb": "Liteon",
    "e02efe": "Liteon", "00269e": "Liteon",
    # Realtek  (cheap ethernet, IoT)  — your .125 is 00:e0:4c
    "00e04c": "Realtek", "525400": "Realtek (QEMU)",
    # Foscam / Hikvision / Dahua  (IP cams)
    "b80305": "Hikvision", "001249": "Hikvision",
    "4c11bf": "Dahua", "001bf0": "Dahua",
    # Espressif (ESP8266 / ESP32)
    "4ccc6a": "Espressif", "240ac4": "Espressif",
    "c4ddc4": "Espressif", "ecfabc": "Espressif",
    # Raspberry Pi
    "b827eb": "Raspberry Pi", "b8270e": "Raspberry Pi",
    "dca632": "Raspberry Pi", "dca6": "Raspberry Pi",
    "e45f01": "Raspberry Pi", "d83add": "Raspberry Pi",
    "2cf7f1": "Raspberry Pi",
    # Xiaomi / Mi (router, IoT)
    "8cbef5": "Xiaomi", "f0b429": "Xiaomi", "788b2a": "Xiaomi",
    "640980": "Xiaomi",
    # Samsung
    "00166b": "Samsung", "0016db": "Samsung", "0018af": "Samsung",
    "0023d6": "Samsung", "5cf938": "Samsung", "8c8eb1": "Samsung",
    # OnePlus / Realme / Oppo
    "94652d": "OnePlus", "c0ee40": "OnePlus", "fc6489": "Realme",
    # Sony
    "001a80": "Sony", "002624": "Sony", "5cea1d": "Sony",
    # Amazon (Echo, Fire, Ring)
    "0017fb": "Amazon", "78e103": "Amazon", "fc65de": "Amazon",
    # Roku / Chromecast / Fire TV
    "b0a737": "Roku", "ac3a7a": "Roku", "00125a": "Roku",
    # Hypervisors / VMs  (handy for spotting your own VMs)
    "080027": "VirtualBox", "0a0027": "VirtualBox-host",
    "5254": "QEMU/KVM", "525400": "QEMU/KVM",
    "000c29": "VMware", "001c14": "VMware", "005056": "VMware",
    "001569": "VMware",
    "0003ff": "Microsoft Hyper-V",
    "00155d": "Microsoft Hyper-V",
    # Misc that turned up in your scan
    "0cef15": "Itel Mobile",  # .2 device
    "242fd0": "TP-Link",  # .3 device
    "c006c3": "ZyXEL",  # .5 device
    "a8e291": "Foxconn (likely consumer router/Pi)",  # .124
    "bcfce7": "Espressif",  # .86 IoT device
    "7c4d8f": "Cisco",  # .89 printer or PC
    "e4a8df": "Liteon",  # .28
    "a002a5": "Texas Instruments",  # .60
    "001b09": "Murata",  # .252
    # Fallback / well-known
    "70b3d5": "IEEE Registration",
    "08002b": "DEC",
    "00904c": "Epigram",
    "001c42": "Parallels",
    "1c1b0d": "Nvidia",
    "74d435": "Giga-Byte",
    "0021cc": "Flaircomm",
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
