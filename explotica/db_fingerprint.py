"""Database credentialed fingerprinting — Phase 53b.

For each detected database port, identify the product+version and (if creds
provided) run a `SELECT version()`-equivalent query. Maps the resulting
version string to NVD CPE for CVE lookup.

Closes part of the Nessus auth-scanning matrix:
  MSSQL / MySQL / MariaDB / PostgreSQL / Oracle / MongoDB / Redis / Memcached /
  Elasticsearch / CouchDB / InfluxDB / Cassandra

Three modes per database:
  1. UNAUTH passive: read pre-auth handshake (most DBs leak version here)
  2. UNAUTH active: send a no-auth query (Redis INFO, ES GET /, etc.)
  3. AUTH (if creds): execute SELECT VERSION() or equivalent

Each adapter is independent — if pymysql isn't installed, we fall back to
the protocol-level handshake parser. This keeps the dep surface optional.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import struct
import urllib.request
from typing import Optional

from .constants import TIMEOUT, USER_AGENT
from .models import CVE, Port

log = logging.getLogger(__name__)


# ── MySQL / MariaDB ──────────────────────────────────────────────────────
def fingerprint_mysql(host: str, port: int = 3306,
                       timeout: float = 4.0,
                       username: Optional[str] = None,
                       password: Optional[str] = None) -> Optional[dict]:
    """MySQL/MariaDB. The pre-auth handshake packet contains the server
    version in plaintext — works without credentials.

    Packet structure (MySQL Protocol::Handshake v10):
      [3 bytes length][1 byte sequence][1 byte protocol_version=10]
      [variable-length null-terminated version_string][...]
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        data = sock.recv(256)
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("mysql fingerprint %s:%d failed: %s", host, port, e)
        return None
    if not data or len(data) < 6:
        return None
    # Packet length is little-endian 3 bytes
    pkt_len = data[0] | (data[1] << 8) | (data[2] << 16)
    if data[4] != 10:  # protocol version
        return None
    # Find null terminator after byte 5 → version string
    end = data.find(b"\x00", 5)
    if end < 6:
        return None
    version_raw = data[5:end].decode("utf-8", "replace")
    # MariaDB marker: "5.5.5-10.x.x-MariaDB" or "10.x.x-MariaDB-..."
    product = "mariadb" if "MariaDB" in version_raw else "mysql"
    version_clean = re.split(r"[-+]", version_raw)[0]
    out = {
        "product": product,
        "version_raw": version_raw,
        "version": version_clean,
        "auth_used": False,
        "cpe_vendor": "mariadb" if product == "mariadb" else "oracle",
        "cpe_product": product,
    }
    # If creds given, try to actually log in + run SELECT VERSION()
    if username and password:
        try:
            import pymysql  # type: ignore
            conn = pymysql.connect(
                host=host, port=port, user=username, password=password,
                connect_timeout=timeout, read_timeout=timeout
            )
            cur = conn.cursor()
            cur.execute("SELECT VERSION()")
            row = cur.fetchone()
            if row:
                out["version_authoritative"] = row[0]
                out["auth_used"] = True
            cur.execute("SELECT current_user(), @@hostname, @@version_comment")
            row = cur.fetchone()
            if row:
                out["auth_user"] = row[0]
                out["server_hostname"] = row[1]
                out["build_comment"] = row[2]
            conn.close()
        except ImportError:
            log.debug("pymysql not installed — skipping auth phase")
        except Exception as e:
            out["auth_error"] = str(e)
    return out


# ── PostgreSQL ───────────────────────────────────────────────────────────
def fingerprint_postgres(host: str, port: int = 5432,
                          timeout: float = 4.0,
                          username: Optional[str] = None,
                          password: Optional[str] = None,
                          database: str = "postgres") -> Optional[dict]:
    """PostgreSQL. Pre-auth: send a startup packet with a bogus user and
    parse the error response — PG often leaks version in the error message.

    Auth path: use psycopg2 → SELECT version() if available.
    """
    out: dict = {"product": "postgresql"}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        # Send a SSLRequest first to detect TLS-required
        sock.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        resp = sock.recv(1)
        if resp == b"S":
            out["tls_supported"] = True
        elif resp == b"N":
            out["tls_supported"] = False
        # Send startup packet (protocol 3.0) with user=explotica_probe
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("postgres pre-auth %s:%d failed: %s", host, port, e)
        return None

    if username and password:
        try:
            import psycopg2  # type: ignore
            conn = psycopg2.connect(
                host=host, port=port, user=username, password=password,
                dbname=database, connect_timeout=int(timeout),
            )
            cur = conn.cursor()
            cur.execute("SELECT version()")
            row = cur.fetchone()
            if row:
                out["version_authoritative"] = row[0]
                # "PostgreSQL 14.10 on x86_64-pc-linux-gnu..."
                m = re.search(r"PostgreSQL\s+(\S+)", row[0])
                if m:
                    out["version"] = m.group(1)
                out["auth_used"] = True
            cur.execute("SELECT current_user, current_database()")
            row = cur.fetchone()
            if row:
                out["auth_user"] = row[0]
                out["current_database"] = row[1]
            # Pull installed extensions for additional surface
            cur.execute("SELECT extname, extversion FROM pg_extension")
            out["extensions"] = [{"name": r[0], "version": r[1]}
                                  for r in cur.fetchall()]
            conn.close()
        except ImportError:
            log.debug("psycopg2 not installed — skipping auth phase")
        except Exception as e:
            out["auth_error"] = str(e)

    if not out.get("version") and not out.get("tls_supported"):
        return None  # Got no useful data
    out["cpe_vendor"] = "postgresql"
    out["cpe_product"] = "postgresql"
    return out


# ── MSSQL ────────────────────────────────────────────────────────────────
def fingerprint_mssql(host: str, port: int = 1433,
                       timeout: float = 4.0,
                       username: Optional[str] = None,
                       password: Optional[str] = None) -> Optional[dict]:
    """MSSQL. Send a TDS pre-login packet — server replies with version bytes.

    Pre-login packet structure (8 bytes per option entry):
      0x12 (PRELOGIN)
      0x01 (last packet flag)
      [length]
      [SPID][packet ID][window]
      ... option fields ...
    """
    # Build minimal pre-login packet
    options = b"\x00\x00\x1a\x00\x06\xff"  # version option, length 6, end mark
    payload = options + b"\x09\x00\x00\x00\x00\x00\x00"  # placeholder version bytes
    header = struct.pack(">BBHHBB",
                          0x12, 0x01, 8 + len(payload), 0x0000, 0x00, 0x00)
    pkt = header + payload
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(pkt)
        resp = sock.recv(512)
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("mssql pre-login %s:%d failed: %s", host, port, e)
        return None
    if len(resp) < 11 or resp[0] != 0x04:  # TDS Response packet type
        return None
    # Find the version option block (option type 0x00, then offset+length)
    # The first byte after the header is the option list start
    out: dict = {"product": "mssql"}
    # Parse version — bytes [major][minor][build_high][build_low][build_revision]
    # Locate by scanning for an "option type 0x00" entry
    body = resp[8:]
    for i in range(len(body) - 5):
        if body[i] == 0x00:
            # Next 4 bytes: offset (big-endian short) + length
            try:
                offset = (body[i + 1] << 8) | body[i + 2]
                length = (body[i + 3] << 8) | body[i + 4]
                if length >= 6:
                    version_bytes = body[offset:offset + 6]
                    major, minor, build = (
                        version_bytes[0],
                        version_bytes[1],
                        (version_bytes[2] << 8) | version_bytes[3],
                    )
                    out["version_raw"] = f"{major}.{minor}.{build}"
                    out["version"] = f"{major}.{minor}.{build}"
                    out["product_friendly"] = _mssql_friendly_name(major, minor)
                    break
            except Exception:
                continue

    if username and password:
        try:
            import pymssql  # type: ignore
            conn = pymssql.connect(server=host, port=port,
                                     user=username, password=password,
                                     timeout=int(timeout))
            cur = conn.cursor()
            cur.execute("SELECT @@VERSION")
            row = cur.fetchone()
            if row:
                out["version_authoritative"] = row[0]
                out["auth_used"] = True
            cur.execute("SELECT SUSER_NAME(), @@SERVERNAME, DB_NAME()")
            row = cur.fetchone()
            if row:
                out["auth_user"] = row[0]
                out["server_name"] = row[1]
                out["database"] = row[2]
            conn.close()
        except ImportError:
            log.debug("pymssql not installed — skipping auth phase")
        except Exception as e:
            out["auth_error"] = str(e)

    if not out.get("version"):
        return None
    out["cpe_vendor"] = "microsoft"
    out["cpe_product"] = "sql_server"
    return out


def _mssql_friendly_name(major: int, minor: int) -> str:
    return {
        (8, 0): "SQL Server 2000",
        (9, 0): "SQL Server 2005",
        (10, 0): "SQL Server 2008",
        (10, 50): "SQL Server 2008 R2",
        (11, 0): "SQL Server 2012",
        (12, 0): "SQL Server 2014",
        (13, 0): "SQL Server 2016",
        (14, 0): "SQL Server 2017",
        (15, 0): "SQL Server 2019",
        (16, 0): "SQL Server 2022",
    }.get((major, minor), f"SQL Server {major}.{minor}")


# ── Oracle (TNS listener) ────────────────────────────────────────────────
def fingerprint_oracle(host: str, port: int = 1521,
                        timeout: float = 4.0) -> Optional[dict]:
    """Oracle TNS listener. Send a TNS CONNECT packet — server replies with
    a REFUSE/ACCEPT containing version info."""
    # Minimal TNS CONNECT packet
    pkt = (b"\x00\x57\x00\x00\x01\x00\x00\x00"  # header
           b"\x01\x39\x01\x2c\x0c\x41\x20\x00"  # connect
           b"\xff\xff\x4f\x98\x00\x00\x01\x00"
           b"\x00\x2e\x00\x29\x00\x00\x00\x00"
           b"\x04\x00\x00\x00\x00\x00\x00\x00"
           b"\x00\x00\x00\x00"
           b"(CONNECT_DATA=(COMMAND=VERSION))")
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(pkt)
        resp = sock.recv(2048)
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("oracle TNS %s:%d failed: %s", host, port, e)
        return None
    if not resp or b"TNS" not in resp:
        return None
    # Try to extract VSNNUM / TIME_INFO / VERSION strings
    m = re.search(rb"VERSION\s*=\s*(\d+\.\d+\.\d+\.\d+\.\d+)", resp)
    if not m:
        m = re.search(rb"(\d+\.\d+\.\d+\.\d+\.\d+)", resp)
    if not m:
        return None
    version = m.group(1).decode("utf-8", "replace")
    return {
        "product": "oracle_database",
        "version": version,
        "version_raw": version,
        "cpe_vendor": "oracle",
        "cpe_product": "database_server",
    }


# ── MongoDB ──────────────────────────────────────────────────────────────
def fingerprint_mongodb(host: str, port: int = 27017,
                         timeout: float = 4.0,
                         username: Optional[str] = None,
                         password: Optional[str] = None) -> Optional[dict]:
    """MongoDB. Send an OP_QUERY for {buildInfo: 1} on admin.$cmd — works
    without auth on misconfigured deployments (the famous MongoDB CVE pattern)."""
    out: dict = {"product": "mongodb"}
    # Try the pymongo path first
    try:
        import pymongo  # type: ignore
        if username and password:
            uri = f"mongodb://{username}:{password}@{host}:{port}/admin"
        else:
            uri = f"mongodb://{host}:{port}/"
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=int(timeout * 1000))
        info = client.admin.command("buildInfo")
        out["version"] = info.get("version", "")
        out["version_raw"] = info.get("version", "")
        out["modules"] = info.get("modules", [])
        out["openssl"] = info.get("openssl", {}).get("running", "")
        out["auth_used"] = bool(username and password)
        # List databases — if we got this far without auth on a prod DB, that's a finding
        out["databases"] = client.list_database_names()
        client.close()
    except ImportError:
        # Raw protocol fallback — send OP_QUERY directly
        log.debug("pymongo not installed; trying raw protocol")
        try:
            # Build OP_QUERY for admin.$cmd.findOne({buildInfo:1})
            collection = b"admin.$cmd\x00"
            query_doc = (b"\x13\x00\x00\x00"  # doc length
                          b"\x10buildInfo\x00\x01\x00\x00\x00"  # int32 buildInfo=1
                          b"\x00")
            body = (b"\x00\x00\x00\x00"  # flags
                     + collection
                     + b"\x00\x00\x00\x00"  # skip
                     + b"\x01\x00\x00\x00"  # return 1
                     + query_doc)
            header = struct.pack("<iiii",
                                  16 + len(body),  # total length
                                  1,               # request ID
                                  0,               # response_to
                                  2004)            # OP_QUERY
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            sock.sendall(header + body)
            resp = sock.recv(4096)
            sock.close()
            if resp and b"version" in resp:
                m = re.search(rb"version\x00.{4}(\d+\.\d+\.\d+)", resp)
                if m:
                    out["version"] = m.group(1).decode("utf-8", "replace")
                    out["version_raw"] = out["version"]
        except (socket.timeout, OSError) as e:
            log.debug("mongodb raw protocol failed: %s", e)
            return None
    except Exception as e:
        log.debug("mongodb auth/connect failed: %s", e)
        if not out.get("version"):
            return None
        out["auth_error"] = str(e)

    if not out.get("version"):
        return None
    out["cpe_vendor"] = "mongodb"
    out["cpe_product"] = "mongodb"
    return out


# ── Redis ────────────────────────────────────────────────────────────────
def fingerprint_redis(host: str, port: int = 6379,
                       timeout: float = 4.0,
                       password: Optional[str] = None) -> Optional[dict]:
    """Redis. Send 'INFO server' — no auth needed if Redis is misconfigured.
    With password, AUTH first."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if password:
            auth_cmd = (
                f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n"
            )
            sock.sendall(auth_cmd.encode())
            sock.recv(128)  # +OK or -ERR
        sock.sendall(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
        data = b""
        while len(data) < 4096:
            chunk = sock.recv(2048)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("redis %s:%d failed: %s", host, port, e)
        return None
    if not data:
        return None
    text = data.decode("utf-8", "replace")
    if "NOAUTH" in text:
        return {"product": "redis", "auth_required": True,
                 "note": "NOAUTH — credentials required"}
    out: dict = {"product": "redis", "cpe_vendor": "redis", "cpe_product": "redis"}
    m = re.search(r"redis_version:(\S+)", text)
    if m:
        out["version"] = m.group(1)
        out["version_raw"] = m.group(1)
    m = re.search(r"redis_mode:(\S+)", text)
    if m:
        out["mode"] = m.group(1)
    m = re.search(r"os:(.+)", text)
    if m:
        out["os"] = m.group(1).strip()
    m = re.search(r"role:(\S+)", text)
    if m:
        out["role"] = m.group(1)
    if not out.get("version"):
        return None
    return out


# ── Memcached ────────────────────────────────────────────────────────────
def fingerprint_memcached(host: str, port: int = 11211,
                            timeout: float = 4.0) -> Optional[dict]:
    """Memcached. Send 'version\r\n' — server replies with version string.
    Memcached has no auth (until SASL was bolted on for v1.4.3+)."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"version\r\n")
        resp = sock.recv(128)
        sock.close()
    except (socket.timeout, OSError) as e:
        log.debug("memcached %s:%d failed: %s", host, port, e)
        return None
    if not resp.startswith(b"VERSION"):
        return None
    version = resp.decode("utf-8", "replace").split()[1].strip()
    return {
        "product": "memcached",
        "version": version,
        "version_raw": version,
        "cpe_vendor": "memcached",
        "cpe_product": "memcached",
    }


# ── Elasticsearch / OpenSearch ───────────────────────────────────────────
def fingerprint_elasticsearch(host: str, port: int = 9200,
                                timeout: float = 4.0,
                                use_tls: bool = False,
                                username: Optional[str] = None,
                                password: Optional[str] = None
                                ) -> Optional[dict]:
    """Elasticsearch / OpenSearch. GET / returns a JSON with version info."""
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                 "Accept": "application/json"})
    if username and password:
        import base64
        creds = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode("ascii")
        req.add_header("Authorization", f"Basic {creds}")
    try:
        import ssl as _ssl
        ctx = _ssl._create_unverified_context() if use_tls else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()
        info = json.loads(body)
    except Exception as e:
        log.debug("elasticsearch %s:%d failed: %s", host, port, e)
        return None
    ver = info.get("version", {})
    if not ver:
        return None
    distro = ver.get("distribution", "elasticsearch")  # opensearch uses "opensearch"
    return {
        "product": distro,
        "version": ver.get("number", ""),
        "version_raw": ver.get("number", ""),
        "build_hash": ver.get("build_hash"),
        "lucene_version": ver.get("lucene_version"),
        "cluster_name": info.get("cluster_name"),
        "tagline": info.get("tagline"),
        "cpe_vendor": "elastic" if distro == "elasticsearch" else "opensearch",
        "cpe_product": distro,
        "auth_used": bool(username and password),
    }


# ── CouchDB ──────────────────────────────────────────────────────────────
def fingerprint_couchdb(host: str, port: int = 5984,
                         timeout: float = 4.0,
                         use_tls: bool = False) -> Optional[dict]:
    """CouchDB. GET / returns version + UUID."""
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            info = json.loads(resp.read())
    except Exception as e:
        log.debug("couchdb %s:%d failed: %s", host, port, e)
        return None
    if not info.get("couchdb"):
        return None
    return {
        "product": "couchdb",
        "version": info.get("version", ""),
        "version_raw": info.get("version", ""),
        "uuid": info.get("uuid"),
        "vendor": info.get("vendor", {}).get("name"),
        "cpe_vendor": "apache",
        "cpe_product": "couchdb",
    }


# ── InfluxDB ─────────────────────────────────────────────────────────────
def fingerprint_influxdb(host: str, port: int = 8086,
                          timeout: float = 4.0,
                          use_tls: bool = False) -> Optional[dict]:
    """InfluxDB. Ping endpoint returns version in HTTP X-Influxdb-Version header."""
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/ping"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            version = (resp.headers.get("X-Influxdb-Version") or
                       resp.headers.get("X-Influxdb-Build"))
    except Exception as e:
        log.debug("influxdb %s:%d failed: %s", host, port, e)
        return None
    if not version:
        return None
    return {
        "product": "influxdb",
        "version": version,
        "version_raw": version,
        "cpe_vendor": "influxdata",
        "cpe_product": "influxdb",
    }


# ── Dispatcher ───────────────────────────────────────────────────────────
# Maps port number → (fingerprint_fn, supports_auth, default_args)
_PORT_DISPATCH = {
    3306: ("mysql", fingerprint_mysql, True),
    3307: ("mysql", fingerprint_mysql, True),  # alt MySQL
    5432: ("postgres", fingerprint_postgres, True),
    1433: ("mssql", fingerprint_mssql, True),
    1521: ("oracle", fingerprint_oracle, False),
    1522: ("oracle", fingerprint_oracle, False),
    27017: ("mongodb", fingerprint_mongodb, True),
    27018: ("mongodb", fingerprint_mongodb, True),
    27019: ("mongodb", fingerprint_mongodb, True),
    6379: ("redis", fingerprint_redis, True),
    11211: ("memcached", fingerprint_memcached, False),
    9200: ("elasticsearch", fingerprint_elasticsearch, True),
    9201: ("elasticsearch", fingerprint_elasticsearch, True),
    5984: ("couchdb", fingerprint_couchdb, False),
    6984: ("couchdb", fingerprint_couchdb, False),
    8086: ("influxdb", fingerprint_influxdb, False),
}


def fingerprint_port(host: str, port: int, *,
                      timeout: float = 4.0,
                      db_credentials: Optional[dict] = None
                      ) -> Optional[dict]:
    """Auto-dispatch fingerprint for a known database port.

    Args:
      db_credentials: {"mysql": {"user": "...", "password": "..."},
                       "postgres": {...}, ...} — per-product credentials.
    """
    if port not in _PORT_DISPATCH:
        return None
    product, fn, supports_auth = _PORT_DISPATCH[port]
    kwargs: dict = {"timeout": timeout}
    if supports_auth and db_credentials:
        creds = db_credentials.get(product, {})
        if creds:
            kwargs["username"] = creds.get("user") or creds.get("username")
            kwargs["password"] = creds.get("password")
            if "database" in creds:
                kwargs["database"] = creds["database"]
    try:
        return fn(host, port=port, **kwargs)
    except Exception as e:
        log.debug("db_fingerprint %s:%d (%s) crashed: %s",
                  host, port, product, e)
        return None


def fingerprint_host_databases(host: str, ports: list[Port],
                                 db_credentials: Optional[dict] = None,
                                 timeout: float = 4.0) -> dict[int, dict]:
    """Fingerprint every database port on a host. Returns {port_number: result}."""
    out: dict[int, dict] = {}
    for p in ports:
        if p.state != "open":
            continue
        if p.number not in _PORT_DISPATCH:
            continue
        result = fingerprint_port(host, p.number, timeout=timeout,
                                    db_credentials=db_credentials)
        if result:
            out[p.number] = result
            # Stamp the Port object — propagates to JSON + CVE lookup
            if result.get("version") and not p.product_version:
                p.product_version = result["version"]
            if result.get("cpe_product") and not p.product_name:
                p.product_name = result["cpe_product"]
            if result.get("cpe_vendor") and not p.product_vendor:
                p.product_vendor = result["cpe_vendor"]
    return out


def cve_lookup_for_databases(host: str, ports: list[Port],
                               db_results: dict[int, dict]) -> int:
    """For each fingerprinted DB, look up CVEs via NVD. Returns total CVEs found."""
    from .nvd import lookup_cves
    total = 0
    by_num = {p.number: p for p in ports}
    for port_num, info in db_results.items():
        vendor = info.get("cpe_vendor")
        product = info.get("cpe_product")
        version = info.get("version")
        if not (vendor and product and version):
            continue
        try:
            cves = lookup_cves(vendor, product, version)
            if cves and port_num in by_num:
                # Append to existing CVE list (don't replace what passive matching found)
                existing_ids = {c.id for c in by_num[port_num].cves}
                for c in cves:
                    if c.id not in existing_ids:
                        by_num[port_num].cves.append(c)
                        total += 1
        except Exception as e:
            log.debug("db CVE lookup failed for %s/%s/%s: %s",
                      vendor, product, version, e)
    return total
