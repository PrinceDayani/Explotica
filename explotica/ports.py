"""TCP port scanner — state-aware, full-range capable.

Phase 56 rewrite. Three core changes from the original threaded scanner:

  1. **Every probe returns a Port.** open / closed / filtered / unknown,
     never None. The caller decides what to keep.
  2. **State derived from errno**, not just `connect_ex == 0`. We can tell
     'connection refused' (= closed, host is alive) from 'timeout'
     (= filtered, firewall dropped it).
  3. **state_reason** captured for every classification so the JSON output
     explains itself: "RST received", "timeout 0.4s", "ICMP host-unreachable",
     etc. Auditable scan results.

`scan_ports()` defaults to the asyncio-backed path (5000 concurrent connects)
because at 65535 ports the thread-pool model is too slow no matter how many
workers you spawn — kernel context-switch cost dominates around 2000 threads.
The sync path is retained for environments where asyncio is unavailable
(unlikely) or for small port sets where the overhead of running a loop is
larger than the wins.

Port → IANA service name is a SEPARATE concern from open/closed/filtered.
The hardcoded `IANA_SERVICE_HINTS` dict is ONLY used as a tertiary guess
(after banner-grabbing and service fingerprinting fail). When used, the
resulting Port has `iana_guess=True` so downstream code can flag it.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from .models import Port

log = logging.getLogger(__name__)


# ── Port preset lists ─────────────────────────────────────────────────────
# The "top 100" preset stays available as an explicit fast-triage option.
# Default behavior changed in Phase 56 — `scan_ports(ports=None)` now scans
# the FULL 1-65535 range.
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 113, 135, 139, 143, 161, 199, 389,
    427, 443, 444, 445, 465, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
    990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
    1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,
    6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100,
    9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

ALL_TCP_PORTS = list(range(1, 65536))


# ── IANA hints — ONLY used as a labeled guess ─────────────────────────────
# When banner-grabbing + service fingerprinting both fail, we fall back to
# this table to give a HINT of what the port USUALLY runs. The resulting Port
# is flagged `iana_guess=True` so the JSON / TUI / dashboard never present
# this as evidence-based identification.
IANA_SERVICE_HINTS = {
    7: "echo", 9: "discard", 13: "daytime", 17: "qotd", 19: "chargen",
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    37: "time", 42: "nameserver", 43: "whois", 49: "tacacs", 53: "dns",
    67: "dhcps", 68: "dhcpc", 69: "tftp", 70: "gopher", 79: "finger",
    80: "http", 88: "kerberos", 102: "iso-tsap", 110: "pop3", 111: "sunrpc",
    113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 177: "xdmcp", 179: "bgp", 199: "smux", 201: "appletalk",
    264: "bgmp", 318: "tsp", 381: "hp-collector", 383: "hp-managed-node",
    389: "ldap", 411: "directconnect", 412: "directconnect", 443: "https",
    445: "smb", 464: "kpasswd", 465: "smtps", 497: "retrospect", 500: "isakmp",
    512: "exec", 513: "rlogin", 514: "syslog", 515: "lpd", 520: "rip",
    521: "ripng", 540: "uucp", 546: "dhcpv6c", 547: "dhcpv6s", 548: "afp",
    554: "rtsp", 563: "nntps", 587: "smtp-submission", 591: "filemaker",
    593: "ms-rpc-http", 631: "ipp", 636: "ldaps", 639: "msdp", 646: "ldp",
    691: "ms-exch-routing", 860: "iscsi", 873: "rsync", 902: "vmware",
    989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s",
    1025: "msrpc", 1026: "msrpc", 1027: "msrpc", 1028: "msrpc",
    1080: "socks", 1099: "rmi-registry", 1194: "openvpn", 1214: "kazaa",
    1241: "nessus", 1311: "rxmon", 1337: "elite", 1352: "lotusnotes",
    1433: "mssql", 1434: "mssql-monitor", 1500: "vlsi-lm", 1521: "oracle",
    1604: "icabrowser", 1701: "l2tp", 1720: "h323", 1723: "pptp",
    1755: "ms-streaming", 1812: "radius", 1813: "radius-acct",
    1883: "mqtt", 1900: "ssdp", 1985: "hsrp", 2000: "cisco-sccp",
    2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm",
    2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl", 2121: "ftp-alt",
    2181: "zookeeper", 2222: "directadmin", 2375: "docker", 2376: "docker-tls",
    2379: "etcd", 2380: "etcd-peer", 2483: "oracle", 2484: "oracle-ssl",
    2638: "sybase", 2701: "sccm", 2702: "sccm", 2745: "bagle",
    2967: "symantec-av", 3000: "ppp", 3050: "interbase", 3074: "xbox",
    3124: "http-proxy", 3127: "mydoom", 3128: "squid-http", 3222: "glbp",
    3260: "iscsi-tgt", 3268: "globalcat-ldap", 3269: "globalcat-ldaps",
    3283: "apple-remote-desktop", 3306: "mysql", 3389: "rdp", 3478: "stun",
    3493: "nut", 3527: "ms-messageserver", 3632: "distccd", 3689: "daap",
    3690: "svn", 3702: "ws-discovery", 3724: "blizzard-games",
    3784: "bfd-control", 3785: "bfd-echo", 3868: "diameter", 3998: "dnx",
    4000: "remoteanything", 4045: "lockd", 4111: "xgrid", 4444: "krb524",
    4500: "ipsec-nat-t", 4664: "google-desktop", 4672: "emule",
    4899: "radmin", 4949: "munin", 5000: "upnp", 5001: "iperf",
    5004: "rtp", 5005: "rtp", 5009: "airport-admin", 5050: "yahoo-msg",
    5051: "ita-agent", 5060: "sip", 5061: "sips", 5093: "sentinel-lm",
    5101: "yahoo-msg", 5190: "aol", 5222: "xmpp-client", 5223: "xmpp-client-ssl",
    5269: "xmpp-server", 5353: "mdns", 5355: "llmnr", 5357: "wsdapi",
    5432: "postgres", 5500: "vnc-http", 5631: "pcanywhere",
    5666: "nrpe", 5672: "amqp", 5800: "vnc-http", 5900: "vnc",
    5984: "couchdb", 6000: "x11", 6001: "x11", 6002: "x11", 6003: "x11",
    6379: "redis", 6443: "kube-apiserver", 6514: "syslog-tls",
    6660: "irc", 6661: "irc", 6662: "irc", 6663: "irc", 6664: "irc",
    6665: "irc", 6666: "irc", 6667: "irc", 6668: "irc", 6669: "irc",
    6679: "irc-ssl", 6697: "irc-ssl", 6881: "bittorrent", 6969: "tracker",
    7000: "cassandra", 7001: "weblogic", 7002: "weblogic-ssl",
    7070: "realserver", 7077: "spark", 7100: "font-service", 7474: "neo4j",
    7547: "tr-069", 7777: "cbt", 7778: "interwise", 8000: "http-alt",
    8008: "http-alt", 8009: "ajp13", 8080: "http-proxy", 8081: "http-alt",
    8083: "mqtt-ws", 8086: "influxdb", 8087: "influxdb", 8088: "radan-http",
    8089: "splunk", 8090: "atlassian-confluence", 8140: "puppet",
    8161: "activemq-ui", 8200: "vault", 8222: "vmware-ws", 8333: "bitcoin",
    8400: "cvd", 8443: "https-alt", 8500: "consul", 8530: "wsus",
    8531: "wsus-ssl", 8649: "ganglia", 8686: "jmx", 8888: "http-alt",
    8983: "solr", 9000: "cslistener", 9001: "tor", 9042: "cassandra-native",
    9090: "websm", 9091: "xmltec-xmlmail", 9092: "kafka", 9100: "jetdirect",
    9160: "cassandra-thrift", 9200: "elasticsearch", 9300: "elasticsearch",
    9389: "adws", 9418: "git", 9443: "https-alt", 9595: "pds",
    9999: "abyss", 10000: "webmin", 10050: "zabbix-agent",
    10051: "zabbix-trapper", 10250: "kubelet", 10255: "kubelet-ro",
    10443: "https-alt", 11211: "memcached", 11215: "memcached",
    11371: "openpgp", 12345: "netbus", 13720: "netbackup", 13721: "netbackup",
    15000: "hydap", 16080: "osxws", 16992: "amt", 16993: "amt-tls",
    17500: "dropbox-lan", 17988: "msrpc", 19150: "gkrellm",
    19531: "systemd-journal", 19999: "dnp", 20000: "dnp",
    22222: "easyengine", 23023: "logmein", 23424: "novar",
    25565: "minecraft", 25672: "rabbitmq", 27015: "halflife",
    27017: "mongodb", 27018: "mongodb-shard", 27019: "mongodb-config",
    28017: "mongodb-http", 31337: "elite", 32400: "plex",
    32764: "router-backdoor", 32768: "filenet-tms", 33848: "jenkins",
    37777: "dahua-dvr", 41794: "crestron-cip", 47808: "bacnet",
    49152: "msrpc-ephem", 49153: "msrpc-ephem", 49154: "msrpc-ephem",
    49155: "msrpc-ephem", 49156: "msrpc-ephem", 49157: "msrpc-ephem",
    50000: "sap", 50050: "cobalt-strike", 51820: "wireguard",
    54321: "back-orifice", 55443: "centos-php", 55553: "metasploit",
    55554: "metasploit", 60000: "shoutcast", 64738: "mumble",
}


# ── State classification from errno ───────────────────────────────────────
def _errno_to_state(err: int) -> tuple[str, str]:
    """Map socket errno (or 0 = open) to (state, human-reason) pair.

    The big practical distinction is between:
      - ECONNREFUSED → RST received → port is CLOSED (host alive, no service)
      - ETIMEDOUT / EHOSTUNREACH / ENETUNREACH → silent drop → FILTERED
      - 0 → connected → OPEN
      - Anything else (EACCES, EAFNOSUPPORT, etc.) → UNKNOWN error state

    Knowing closed-vs-filtered is the same signal nmap uses to map firewalls.
    """
    if err == 0:
        return ("open", "tcp-connect succeeded")
    if err in (errno.ECONNREFUSED,):
        return ("closed", "RST received")
    if err in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
        return ("filtered", "connect timeout")
    if err in (errno.EHOSTUNREACH,):
        return ("filtered", "ICMP host-unreachable")
    if err in (errno.ENETUNREACH,):
        return ("filtered", "ICMP net-unreachable")
    if err in (errno.EHOSTDOWN,) if hasattr(errno, "EHOSTDOWN") else ():
        return ("filtered", "host-down")
    if err in (errno.ECONNRESET,):
        return ("closed", "connection-reset")
    # Anything else — administratively prohibited, address-family-not-supported,
    # too-many-files, etc.
    return ("unknown", f"errno={err}")


# ── Synchronous probe (kept for compatibility / small port sets) ─────────
def probe_tcp(ip: str, port: int, timeout: float = 0.8) -> Port:
    """One TCP-connect probe. ALWAYS returns a Port — never None.

    The caller decides whether to keep closed/filtered entries.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    err = 0
    try:
        err = sock.connect_ex((ip, port))
    except (socket.timeout,):
        err = errno.ETIMEDOUT
    except OSError as e:
        err = e.errno or errno.EIO
    finally:
        try:
            sock.close()
        except Exception:
            pass
    state, reason = _errno_to_state(err)
    if state == "filtered" and reason == "connect timeout":
        reason = f"timeout {timeout}s"
    return Port(number=port, protocol="tcp",
                state=state, state_reason=reason)


# ── Async probe (the hot path for large port sets) ────────────────────────
async def _async_probe_one(ip: str, port: int,
                            timeout: float) -> Port:
    """One async TCP-connect probe. ALWAYS returns a Port."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        # Connected — port is open. Close politely.
        try:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.3)
            except (asyncio.TimeoutError, Exception):
                pass
        except Exception:
            pass
        return Port(number=port, protocol="tcp",
                    state="open", state_reason="tcp-connect succeeded")
    except asyncio.TimeoutError:
        return Port(number=port, protocol="tcp",
                    state="filtered", state_reason=f"timeout {timeout}s")
    except ConnectionRefusedError:
        return Port(number=port, protocol="tcp",
                    state="closed", state_reason="RST received")
    except OSError as e:
        err = e.errno or 0
        state, reason = _errno_to_state(err)
        return Port(number=port, protocol="tcp",
                    state=state, state_reason=reason)


async def _async_scan_all(ip: str, ports: list[int], *,
                           timeout: float,
                           concurrency: int,
                           progress=None) -> list[Port]:
    """Probe every port in `ports` with bounded concurrency. Returns a Port
    for every probe — open AND closed AND filtered AND unknown."""
    sem = asyncio.Semaphore(concurrency)
    done_count = [0]
    total = len(ports)

    async def probe(p: int) -> Port:
        async with sem:
            r = await _async_probe_one(ip, p, timeout)
            done_count[0] += 1
            if progress and done_count[0] % 5000 == 0:
                progress(f"scan {ip}: {done_count[0]}/{total} ports")
            return r

    results = await asyncio.gather(*(probe(p) for p in ports))
    return sorted(results, key=lambda r: r.number)


def _run_async_scan(ip: str, ports: list[int],
                     timeout: float, concurrency: int,
                     progress=None) -> list[Port]:
    """Run the async scan, creating an event loop if one isn't already running."""
    try:
        return asyncio.run(_async_scan_all(ip, ports, timeout=timeout,
                                            concurrency=concurrency,
                                            progress=progress))
    except RuntimeError:
        # Called from inside an existing event loop — create one in a thread
        import threading
        result: list[Port] = []
        exc: list[BaseException] = []

        def worker():
            try:
                result.extend(asyncio.run(_async_scan_all(
                    ip, ports, timeout=timeout,
                    concurrency=concurrency, progress=progress,
                )))
            except BaseException as e:
                exc.append(e)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join()
        if exc:
            raise exc[0]
        return result


# ── Public entry point ────────────────────────────────────────────────────
def scan_ports(ip: str, ports: Optional[list[int]] = None,
               *,
               timeout: float = 0.4,
               workers: int = 2000,
               include_closed: bool = True,
               include_filtered: bool = True,
               include_unknown: bool = False,
               progress=None) -> list[Port]:
    """Scan ports on one host.

    Defaults (Phase 56):
      - `ports=None` → ALL 65535 TCP ports.
      - `timeout=0.4` → tighter than the legacy 0.8s; works on LAN, OK on most
        Internet hosts. Bump to 1.0s for trans-continental scanning.
      - `workers=2000` → asyncio concurrency cap. 2000 is the safe default
        for most kernels (file descriptor limit). `--ultra` orchestration
        bumps this to 5000 in scanner.py.
      - `include_closed=True` and `include_filtered=True` → emit ALL three
        states. Use `--open-only` from CLI for the legacy "open ports only"
        view.

    Args:
      progress: optional callable(message:str) for periodic progress updates.
    """
    if ports is None:
        ports = ALL_TCP_PORTS
    if not ports:
        return []

    # Choose execution path:
    #  - tiny port sets (<200) → sync thread pool is fine and has less overhead
    #  - everything bigger → asyncio
    use_async = len(ports) > 200

    if use_async:
        probed = _run_async_scan(ip, ports, timeout=timeout,
                                  concurrency=workers, progress=progress)
    else:
        probed = []
        with ThreadPoolExecutor(max_workers=min(workers, 256)) as pool:
            futs = {pool.submit(probe_tcp, ip, p, timeout): p for p in ports}
            for f in as_completed(futs):
                probed.append(f.result())
        probed.sort(key=lambda r: r.number)

    # Apply state filters AFTER probing. We do the work either way — caller
    # picks what to surface in the JSON. Filtering at output time is right
    # because someone running --include-filtered later can re-extract.
    out: list[Port] = []
    for p in probed:
        if p.state == "open":
            out.append(p)
        elif p.state == "closed" and include_closed:
            out.append(p)
        elif p.state == "filtered" and include_filtered:
            out.append(p)
        elif p.state == "unknown" and include_unknown:
            out.append(p)
    return out


# ── IANA-guess tagging (called AFTER fingerprinting fails) ────────────────
def apply_iana_guess(port: Port) -> Port:
    """If a port has no service identified by banner/fingerprint, tag it with
    an IANA hint and `iana_guess=True`. Idempotent — won't overwrite an
    evidence-based service name."""
    if port.service is None and port.state == "open":
        hint = IANA_SERVICE_HINTS.get(port.number)
        if hint:
            port.service = hint
            port.iana_guess = True
    return port
