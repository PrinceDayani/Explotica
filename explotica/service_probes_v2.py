"""High-impact service-specific probes for ports that leak rich data.

Each function probes ONE specific service and returns a dict of findings.
These are designed to be safe (no destructive operations, no credential
brute force, no exploits) but informationally aggressive.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import struct
from typing import Optional

log = logging.getLogger(__name__)


# ── RDP NTLM disclosure (port 3389) ──────────────────────────────────────
def probe_rdp_ntlm(host: str, port: int = 3389,
                   timeout: float = 4.0) -> Optional[dict]:
    """Send an X.224 CR + CredSSP TLS handshake -> server leaks NTLMSSP Type 2
    message containing: NetBIOS computer/domain, DNS computer/domain/tree.

    This is the single highest-ROI unauthenticated info disclosure on
    Windows networks.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        x224 = bytes.fromhex("030000130ee000000000000100080001000000")
        sock.sendall(x224)
        resp = sock.recv(2048)
        if not resp or len(resp) < 20:
            sock.close()
            return None
        result: dict = {"raw_response_bytes": len(resp)}
        if len(resp) > 19:
            proto = resp[19]
            result["selected_protocol"] = proto
            result["credssp"] = bool(proto & 2)
            result["tls"] = bool(proto & 1)

        try:
            ctx = ssl._create_unverified_context()
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            ntlm_neg = bytes.fromhex(
                "30370307a02430223020a103020101a21b04194e544c4d5353500001000000"
                "b7820800000000000000000000000000000000000a00614a0000000f"
            )
            tls_sock.sendall(ntlm_neg)
            tls_resp = tls_sock.recv(4096)
            tls_sock.close()
        except (ssl.SSLError, OSError) as e:
            log.debug("RDP TLS step failed for %s: %s", host, e)
            sock.close()
            return result

        if not tls_resp or b"NTLMSSP\x00" not in tls_resp:
            return result

        ntlm_offset = tls_resp.find(b"NTLMSSP\x00")
        ntlm_data = tls_resp[ntlm_offset:]
        if len(ntlm_data) < 56:
            return result

        try:
            target_name_len = struct.unpack("<H", ntlm_data[12:14])[0]
            target_name_off = struct.unpack("<I", ntlm_data[16:20])[0]
            target_info_len = struct.unpack("<H", ntlm_data[40:42])[0]
            target_info_off = struct.unpack("<I", ntlm_data[44:48])[0]
        except struct.error:
            return result

        if target_name_off + target_name_len <= len(ntlm_data):
            tn = ntlm_data[target_name_off:target_name_off + target_name_len]
            try:
                result["target_name"] = tn.decode("utf-16-le", errors="replace")
            except Exception:
                pass

        if len(ntlm_data) >= 56:
            try:
                major = ntlm_data[48]
                minor = ntlm_data[49]
                build = struct.unpack("<H", ntlm_data[50:52])[0]
                result["os_version"] = f"{major}.{minor} build {build}"
            except Exception:
                pass

        if target_info_off + target_info_len <= len(ntlm_data):
            av_data = ntlm_data[target_info_off:target_info_off + target_info_len]
            av_pairs: dict[str, str] = {}
            i = 0
            av_type_names = {
                1: "netbios_computer_name",
                2: "netbios_domain_name",
                3: "dns_computer_name",
                4: "dns_domain_name",
                5: "dns_tree_name",
            }
            while i + 4 <= len(av_data):
                av_id, av_len = struct.unpack("<HH", av_data[i:i + 4])
                i += 4
                if av_id == 0:
                    break
                value_bytes = av_data[i:i + av_len]
                i += av_len
                if av_id in av_type_names:
                    try:
                        av_pairs[av_type_names[av_id]] = value_bytes.decode(
                            "utf-16-le", errors="replace"
                        )
                    except Exception:
                        pass
            if av_pairs:
                result["ntlm_av_pairs"] = av_pairs
        return result
    except (socket.timeout, OSError, struct.error) as e:
        log.debug("RDP probe %s:%d failed: %s", host, port, e)
        return None


# ── LDAP RootDSE (ports 389, 636) ────────────────────────────────────────
def probe_ldap_rootdse(host: str, port: int = 389,
                       timeout: float = 4.0) -> Optional[dict]:
    """Anonymous LDAP bind. Extracts printable strings (naming contexts)."""
    bind_req = bytes.fromhex("300c020101600702010304008000")
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(bind_req)
        resp = sock.recv(2048)
    except (socket.timeout, OSError) as e:
        log.debug("LDAP probe %s:%d failed: %s", host, port, e)
        return None

    if not resp or len(resp) < 7:
        sock.close()
        return None

    result: dict = {"responded": True}
    if b"\x0a\x01\x00" in resp[:14]:
        result["anonymous_bind"] = "allowed"
    elif b"\x0a\x01\x32" in resp[:14] or b"\x0a\x01\x07" in resp[:14]:
        result["anonymous_bind"] = "rejected"

    sock.close()
    return result


# ── NTP version + monlist (port 123 UDP) ──────────────────────────────────
def probe_ntp(host: str, timeout: float = 3.0) -> Optional[dict]:
    """NTP client mode 3 query -> version + stratum + reference ID."""
    pkt = b"\x1b" + b"\x00" * 47
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (host, 123))
        data, _ = sock.recvfrom(2048)
    except (socket.timeout, OSError):
        sock.close()
        return None

    result: dict = {"responded": True, "response_bytes": len(data)}
    if len(data) >= 4:
        result["version"] = (data[0] >> 3) & 0x7
        result["mode"] = data[0] & 0x7
    if len(data) >= 12:
        result["stratum"] = data[1]
        ref_id = data[12:16]
        if data[1] == 1 and all(0x20 <= b < 0x7F for b in ref_id):
            result["ref_id_text"] = ref_id.decode("ascii", errors="ignore")

    monlist = b"\x17\x00\x03\x2a" + b"\x00" * 4
    try:
        sock.sendto(monlist, (host, 123))
        mon_data, _ = sock.recvfrom(8192)
        if len(mon_data) > 100:
            result["monlist_responded"] = True
            result["monlist_size_bytes"] = len(mon_data)
            result["amp_ratio"] = round(len(mon_data) / len(monlist), 1)
    except (socket.timeout, OSError):
        result["monlist_responded"] = False
    finally:
        sock.close()
    return result


# ── NFS (port 2049) ───────────────────────────────────────────────────────
def probe_nfs(host: str, port: int = 2049,
              timeout: float = 3.0) -> Optional[dict]:
    """Connect and capture banner-ish data; suggest `showmount -e` for full list."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"\x80\x00\x00\x28\x00\x00\x00\x00"
                     b"\x00\x00\x00\x00\x00\x00\x00\x02"
                     b"\x00\x01\x86\xa0\x00\x00\x00\x02"
                     b"\x00\x00\x00\x00\x00\x00\x00\x00"
                     b"\x00\x00\x00\x00\x00\x00\x00\x00"
                     b"\x00\x00\x00\x00")
        data = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data or len(data) < 4:
        return None
    return {
        "responded": True,
        "response_bytes": len(data),
        "hint": f"Use `showmount -e {host}` for full export list",
    }


# ── Docker registry (port 5000) ───────────────────────────────────────────
def probe_docker_registry(host: str, port: int = 5000,
                          timeout: float = 4.0) -> Optional[dict]:
    """GET /v2/_catalog -> all hosted images if unauthenticated."""
    paths = ["/v2/", "/v2/_catalog?n=100"]
    findings: dict = {"responded": True, "paths": {}}
    for path in paths:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            req = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: explotica\r\n\r\n"
            sock.sendall(req.encode())
            data = sock.recv(8192)
            sock.close()
        except (socket.timeout, OSError):
            continue
        if not data:
            continue
        text = data.decode("utf-8", errors="replace")
        first_line = text.split("\r\n", 1)[0] if "\r\n" in text else ""
        findings["paths"][path] = {
            "status_line": first_line[:80],
            "size": len(data),
        }
        if "200 OK" in first_line and "repositories" in text:
            m = re.search(r'"repositories"\s*:\s*\[([^\]]+)\]', text)
            if m:
                findings["repositories"] = [
                    r.strip().strip('"') for r in m.group(1).split(",")[:50]
                ]
    return findings if findings["paths"] else None


# ── Kubernetes API ────────────────────────────────────────────────────────
def probe_k8s_api(host: str, port: int, timeout: float = 4.0) -> Optional[dict]:
    """GET /version on a TLS-wrapped k8s API server."""
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl._create_unverified_context()
        sock = ctx.wrap_socket(raw, server_hostname=host)
        req = f"GET /version HTTP/1.0\r\nHost: {host}\r\nUser-Agent: explotica\r\n\r\n"
        sock.sendall(req.encode())
        data = sock.recv(4096)
        sock.close()
    except (socket.timeout, OSError, ssl.SSLError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    if "kubernetes" not in text.lower() and "gitVersion" not in text:
        return None
    result: dict = {"responded": True}
    for field in ("gitVersion", "buildDate", "platform", "goVersion"):
        m = re.search(rf'"{field}"\s*:\s*"([^"]+)"', text)
        if m:
            result[field] = m.group(1)
    return result if len(result) > 1 else None


# ── Elasticsearch indices ─────────────────────────────────────────────────
def probe_elasticsearch_indices(host: str, port: int = 9200,
                                 timeout: float = 4.0) -> Optional[dict]:
    """GET /_cat/indices?format=json -> every index if unauth."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        req = f"GET /_cat/indices?format=json HTTP/1.0\r\nHost: {host}\r\nUser-Agent: explotica\r\n\r\n"
        sock.sendall(req.encode())
        data = sock.recv(16384)
        sock.close()
    except (socket.timeout, OSError):
        return None
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    if "401" in text[:120]:
        return {"responded": True, "auth_required": True}
    if "[" not in text:
        return {"responded": True, "raw_bytes": len(data)}
    indices = re.findall(r'"index"\s*:\s*"([^"]+)"', text)
    return {
        "responded": True,
        "indices": indices[:100],
        "index_count": len(indices),
    }


# ── MongoDB listDatabases ─────────────────────────────────────────────────
def probe_mongodb_listdbs(host: str, port: int = 27017,
                          timeout: float = 4.0) -> Optional[dict]:
    """OP_QUERY {listDatabases: 1} -> all DBs if no auth."""
    try:
        bson = (
            b"\x17\x00\x00\x00"
            b"\x10listDatabases\x00"
            b"\x01\x00\x00\x00"
            b"\x00"
        )
        coll = b"admin.$cmd\x00"
        body = struct.pack("<I", 0) + coll + struct.pack("<II", 0, 1) + bson
        msg = struct.pack("<IIII", 16 + len(body), 1, 0, 2004) + body
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(msg)
        data = sock.recv(16384)
        sock.close()
    except (socket.timeout, OSError, struct.error):
        return None
    if not data:
        return None
    dbs: list[str] = []
    cur: list[int] = []
    for b in data:
        if 0x20 <= b < 0x7F and b not in (0x22, 0x5c):
            cur.append(b)
        else:
            if 3 <= len(cur) <= 64:
                s = bytes(cur).decode("ascii", errors="ignore")
                if s.isidentifier() or "_" in s or s.startswith(("admin", "config", "local")):
                    dbs.append(s)
            cur = []
    confirmed = any(d in ("admin", "config", "local") for d in dbs)
    if not confirmed:
        return None
    return {
        "responded": True,
        "databases": sorted(set(dbs))[:50],
        "auth_required": False,
    }


# ── Dispatch — port → list of (probe, default_port_kwargs) ────────────────
SERVICE_PROBES = {
    389:   probe_ldap_rootdse,
    636:   probe_ldap_rootdse,
    2049:  probe_nfs,
    3389:  probe_rdp_ntlm,
    5000:  probe_docker_registry,
    6443:  probe_k8s_api,
    9200:  probe_elasticsearch_indices,
    27017: probe_mongodb_listdbs,
}


def probe_service(host: str, port: int, timeout: float = 4.0) -> Optional[dict]:
    """Dispatch a service-specific probe by port."""
    handler = SERVICE_PROBES.get(port)
    if handler is None:
        return None
    try:
        return handler(host, port=port, timeout=timeout)
    except TypeError:
        # Some probes don't take port kwarg
        return handler(host, timeout=timeout)
    except Exception as e:
        log.debug("probe %s on %s:%d failed: %s",
                  handler.__name__, host, port, e)
        return None


def probe_udp_ntp(host: str, timeout: float = 3.0) -> Optional[dict]:
    """Convenience wrapper for the UDP probe orchestration."""
    return probe_ntp(host, timeout=timeout)
