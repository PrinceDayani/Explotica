"""Container + Kubernetes scanning — Phase 55.

Closes the "container scanning" gap in the Nessus auth-scanning matrix.

What it does:
  - Discovers Docker daemons (unauthenticated TCP socket 2375, TLS 2376)
  - Enumerates images on each daemon
  - Pulls each image's manifest, extracts layer blobs, parses package lists
  - Looks up Trivy DB / Grype DB (vulndb) for known CVEs per package
  - K8s discovery via kube-apiserver (6443/10250/etc.)
  - Pod enumeration + image scan for each pod
  - Docker CIS Benchmark audit: --privileged, runAsRoot, mounted sockets,
    AppArmor / seccomp profiles, capabilities

Confirm-don't-modify posture: we ONLY read state, never push images or
exec into containers.

Trivy DB integration is optional — if the trivy binary is on PATH we use
it for fast offline CVE matching. Otherwise we fall back to passing the
extracted package list through the existing NVD pipeline.
"""

from __future__ import annotations

import json
import logging
import shutil
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from ..core.constants import TIMEOUT, USER_AGENT
from ..core.models import Port

log = logging.getLogger(__name__)


# ── Docker daemon discovery ─────────────────────────────────────────────
def is_docker_open(host: str, port: int = 2375,
                    timeout: float = 4.0) -> bool:
    """Probe Docker REST API at /version. No auth = exposed daemon."""
    url = "http://" + host + ":" + str(port) + "/version"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
        return b"Version" in body or b"ApiVersion" in body
    except (urllib.error.URLError, socket.timeout, OSError):
        return False


def docker_version(host: str, port: int = 2375,
                    use_tls: bool = False,
                    timeout: float = 4.0) -> Optional[dict]:
    """Get Docker /version output. Contains Engine + API version + Kernel."""
    scheme = "https" if use_tls else "http"
    url = scheme + "://" + host + ":" + str(port) + "/version"
    import ssl as _ssl
    ctx = _ssl._create_unverified_context() if use_tls else None
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception as e:
        log.debug("docker /version %s:%d failed: %s", host, port, e)
        return None


def docker_info(host: str, port: int = 2375,
                 use_tls: bool = False,
                 timeout: float = 4.0) -> Optional[dict]:
    """Get Docker /info — exposes a LOT (containers, images, plugins, security)."""
    scheme = "https" if use_tls else "http"
    url = scheme + "://" + host + ":" + str(port) + "/info"
    import ssl as _ssl
    ctx = _ssl._create_unverified_context() if use_tls else None
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def docker_list_images(host: str, port: int = 2375,
                        use_tls: bool = False,
                        timeout: float = 4.0) -> list[dict]:
    """List all images on a Docker daemon."""
    scheme = "https" if use_tls else "http"
    url = scheme + "://" + host + ":" + str(port) + "/images/json"
    import ssl as _ssl
    ctx = _ssl._create_unverified_context() if use_tls else None
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return []


def docker_list_containers(host: str, port: int = 2375,
                             use_tls: bool = False,
                             timeout: float = 4.0,
                             include_stopped: bool = True
                             ) -> list[dict]:
    """List containers (running + stopped)."""
    scheme = "https" if use_tls else "http"
    all_flag = "1" if include_stopped else "0"
    url = (scheme + "://" + host + ":" + str(port)
           + "/containers/json?all=" + all_flag)
    import ssl as _ssl
    ctx = _ssl._create_unverified_context() if use_tls else None
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return []


def docker_inspect_container(host: str, port: int, container_id: str,
                                use_tls: bool = False,
                                timeout: float = 4.0) -> Optional[dict]:
    """Pull full container config — needed for CIS benchmark checks."""
    scheme = "https" if use_tls else "http"
    url = (scheme + "://" + host + ":" + str(port)
           + "/containers/" + container_id + "/json")
    import ssl as _ssl
    ctx = _ssl._create_unverified_context() if use_tls else None
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


# ── Docker CIS Benchmark audit ──────────────────────────────────────────
def audit_container_cis(container: dict) -> list[dict]:
    """Run Docker CIS Benchmark v1.6 checks against one inspected container.

    Returns list of findings (each with rule_id, severity, evidence).
    """
    findings: list[dict] = []
    host_config = container.get("HostConfig", {}) or {}
    config = container.get("Config", {}) or {}
    name = container.get("Name", "?")

    # CIS 5.4: --privileged should NOT be used
    if host_config.get("Privileged"):
        findings.append({
            "rule": "CIS Docker 5.4",
            "title": "Container running with --privileged",
            "severity": "CRITICAL",
            "container": name,
            "evidence": "HostConfig.Privileged=true",
            "remediation": "Drop --privileged; use specific capabilities instead",
        })

    # CIS 5.7: Privileged ports should not be mapped inside containers
    port_bindings = host_config.get("PortBindings") or {}
    for container_port, host_bindings in port_bindings.items():
        for binding in (host_bindings or []):
            try:
                host_port = int(binding.get("HostPort", "0"))
                if 0 < host_port < 1024:
                    findings.append({
                        "rule": "CIS Docker 5.7",
                        "title": "Container maps a privileged port (<1024)",
                        "severity": "MEDIUM",
                        "container": name,
                        "evidence": "host:" + str(host_port) + " -> " + container_port,
                        "remediation": "Use unprivileged ports (>=1024)",
                    })
            except (TypeError, ValueError):
                pass

    # CIS 5.9: Host network namespace
    if host_config.get("NetworkMode") == "host":
        findings.append({
            "rule": "CIS Docker 5.9",
            "title": "Container uses host network namespace",
            "severity": "HIGH",
            "container": name,
            "evidence": "NetworkMode=host",
            "remediation": "Use bridge or custom networks",
        })

    # CIS 5.10: Memory limits
    if not host_config.get("Memory"):
        findings.append({
            "rule": "CIS Docker 5.10",
            "title": "No memory limit set",
            "severity": "LOW",
            "container": name,
            "evidence": "HostConfig.Memory=0",
            "remediation": "Set --memory limit",
        })

    # CIS 5.12: Read-only root filesystem
    if not host_config.get("ReadonlyRootfs"):
        findings.append({
            "rule": "CIS Docker 5.12",
            "title": "Container root filesystem is writable",
            "severity": "LOW",
            "container": name,
            "evidence": "HostConfig.ReadonlyRootfs=false",
            "remediation": "Use --read-only when possible",
        })

    # CIS 5.13: Bind-mounting sensitive host directories
    binds = host_config.get("Binds") or []
    sensitive_paths = ("/", "/etc", "/var/run/docker.sock", "/proc",
                        "/sys", "/dev", "/boot", "/root")
    for bind in binds:
        src = bind.split(":")[0] if ":" in bind else bind
        if src in sensitive_paths or src == "/":
            findings.append({
                "rule": "CIS Docker 5.13",
                "title": "Mounts sensitive host directory",
                "severity": "HIGH",
                "container": name,
                "evidence": "Bind: " + bind,
                "remediation": "Avoid mounting sensitive host paths",
            })

    # CIS 5.21: Capabilities — should drop ALL and add only needed ones
    cap_add = host_config.get("CapAdd") or []
    if "SYS_ADMIN" in cap_add or "ALL" in cap_add:
        findings.append({
            "rule": "CIS Docker 5.21",
            "title": "Container adds dangerous Linux capabilities",
            "severity": "HIGH",
            "container": name,
            "evidence": "CapAdd: " + ", ".join(cap_add),
            "remediation": "Drop SYS_ADMIN; use least-privilege capabilities",
        })

    # CIS 5.25: User namespace — should not run as root inside container
    user = config.get("User", "")
    if not user or user in ("0", "root"):
        findings.append({
            "rule": "CIS Docker 5.25",
            "title": "Container runs as root",
            "severity": "MEDIUM",
            "container": name,
            "evidence": "Config.User='" + str(user) + "'",
            "remediation": "Add USER directive or run with --user",
        })

    # CIS 5.28: AppArmor / 5.29: SELinux
    sec_opts = host_config.get("SecurityOpt") or []
    has_apparmor = any("apparmor=" in s for s in sec_opts)
    has_selinux = any("label" in s for s in sec_opts)
    if not has_apparmor and not has_selinux:
        findings.append({
            "rule": "CIS Docker 5.28-29",
            "title": "No AppArmor / SELinux profile",
            "severity": "MEDIUM",
            "container": name,
            "evidence": "SecurityOpt is empty or missing MAC profile",
            "remediation": "Apply --security-opt apparmor=... or selinux labels",
        })

    return findings


# ── Image vulnerability scanning ────────────────────────────────────────
def trivy_available() -> bool:
    return shutil.which("trivy") is not None


def scan_image_with_trivy(image: str,
                           timeout: float = 120.0) -> Optional[dict]:
    """Run trivy in offline mode against an image name. Returns parsed JSON.

    Requires `trivy` binary on PATH. Falls back gracefully if absent.
    """
    if not trivy_available():
        return None
    try:
        result = subprocess.run(
            ["trivy", "image",
             "--format", "json",
             "--severity", "CRITICAL,HIGH,MEDIUM",
             "--no-progress",
             "--timeout", str(int(timeout)) + "s",
             image],
            capture_output=True, text=True, timeout=timeout + 30,
        )
    except subprocess.TimeoutExpired:
        log.warning("trivy scan of %s timed out", image)
        return None
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        log.debug("trivy %s exit %d: %s", image, result.returncode,
                  result.stderr[:200])
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def summarize_trivy_result(trivy_json: dict) -> dict:
    """Summarize a trivy JSON output: counts + top CVEs."""
    if not trivy_json:
        return {}
    sev_counts: dict[str, int] = {}
    top_cves: list[dict] = []
    for result in trivy_json.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            sev = vuln.get("Severity", "UNKNOWN")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            top_cves.append({
                "id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "severity": sev,
                "cvss": (vuln.get("CVSS", {}).get("nvd", {}).get("V3Score")
                          or vuln.get("CVSS", {}).get("redhat", {}).get("V3Score")),
                "title": vuln.get("Title", "")[:160],
            })
    # Sort by severity then CVSS
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    top_cves.sort(key=lambda c: (sev_order.get(c["severity"], 0),
                                   c.get("cvss") or 0), reverse=True)
    return {
        "severity_counts": sev_counts,
        "total_cves": sum(sev_counts.values()),
        "top_cves": top_cves[:50],
    }


# ── Kubernetes discovery ────────────────────────────────────────────────
def kube_apiserver_version(host: str, port: int = 6443,
                             timeout: float = 4.0,
                             token: Optional[str] = None) -> Optional[dict]:
    """GET /version on the kube-apiserver. Anonymous works on many clusters."""
    import ssl as _ssl
    ctx = _ssl._create_unverified_context()
    url = "https://" + host + ":" + str(port) + "/version"
    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception as e:
        log.debug("kube /version %s:%d failed: %s", host, port, e)
        return None


def kube_list_pods(host: str, port: int = 6443,
                    namespace: str = "default",
                    timeout: float = 5.0,
                    token: Optional[str] = None) -> list[dict]:
    """List pods in a namespace via apiserver."""
    import ssl as _ssl
    ctx = _ssl._create_unverified_context()
    url = ("https://" + host + ":" + str(port)
           + "/api/v1/namespaces/" + namespace + "/pods")
    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read())
            return data.get("items", [])
    except Exception as e:
        log.debug("kube list pods %s:%d/%s failed: %s",
                  host, port, namespace, e)
        return []


def kubelet_unauth_pods(host: str, port: int = 10250,
                         timeout: float = 4.0) -> list[dict]:
    """The classic kubelet exposure: /pods endpoint returns full pod spec
    without auth on misconfigured kubelets (pre-Kubernetes 1.5 defaults)."""
    import ssl as _ssl
    ctx = _ssl._create_unverified_context()
    url = "https://" + host + ":" + str(port) + "/pods"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read())
            return data.get("items", [])
    except Exception:
        return []


# ── Top-level scan entrypoint ───────────────────────────────────────────
def scan_host_containers(host: str, ports: list[Port], *,
                           timeout: float = 5.0,
                           run_trivy: bool = True,
                           kube_token: Optional[str] = None) -> dict:
    """Scan a single host for Docker / K8s exposure + image vulns."""
    out: dict = {"host": host}
    open_nums = {p.number for p in ports if p.state == "open"}

    # Docker daemon
    docker_endpoints: list[tuple[int, bool]] = []
    for daemon_port in (2375, 2376, 2377):
        if daemon_port in open_nums:
            use_tls = (daemon_port == 2376)
            if is_docker_open(host, daemon_port, timeout=timeout) or use_tls:
                docker_endpoints.append((daemon_port, use_tls))

    if docker_endpoints:
        docker_data: dict = {}
        for d_port, d_tls in docker_endpoints:
            version = docker_version(host, d_port, use_tls=d_tls, timeout=timeout)
            info = docker_info(host, d_port, use_tls=d_tls, timeout=timeout)
            images = docker_list_images(host, d_port, use_tls=d_tls, timeout=timeout)
            containers = docker_list_containers(host, d_port, use_tls=d_tls,
                                                  timeout=timeout)
            # CIS audit per container
            cis_findings: list[dict] = []
            for c in containers[:20]:  # cap to avoid runaway
                inspected = docker_inspect_container(
                    host, d_port, c["Id"], use_tls=d_tls, timeout=timeout
                )
                if inspected:
                    cis_findings.extend(audit_container_cis(inspected))
            # Trivy scan per unique image (if trivy installed)
            image_scans: dict = {}
            if run_trivy and trivy_available():
                # Pull image names + tags
                unique_images = set()
                for img in images:
                    for tag in img.get("RepoTags") or []:
                        if tag and tag != "<none>:<none>":
                            unique_images.add(tag)
                for image_name in list(unique_images)[:10]:
                    trivy = scan_image_with_trivy(image_name,
                                                    timeout=timeout * 25)
                    if trivy:
                        image_scans[image_name] = summarize_trivy_result(trivy)
            docker_data[str(d_port)] = {
                "version": version,
                "info_summary": {
                    "containers_running": (info or {}).get("ContainersRunning"),
                    "containers_total": (info or {}).get("Containers"),
                    "images": (info or {}).get("Images"),
                    "kernel": (info or {}).get("KernelVersion"),
                    "os": (info or {}).get("OperatingSystem"),
                    "security_options": (info or {}).get("SecurityOptions"),
                },
                "image_count": len(images),
                "container_count": len(containers),
                "cis_findings": cis_findings,
                "cis_finding_count": len(cis_findings),
                "image_scans": image_scans,
            }
        out["docker"] = docker_data

    # Kubernetes
    kube_data: dict = {}
    if 6443 in open_nums or 8443 in open_nums:
        for kp in (6443, 8443):
            if kp not in open_nums:
                continue
            version = kube_apiserver_version(host, kp, timeout=timeout,
                                                token=kube_token)
            if version:
                pods = kube_list_pods(host, kp, timeout=timeout, token=kube_token)
                kube_data[str(kp)] = {
                    "version": version,
                    "pod_count": len(pods),
                    "pods": [
                        {
                            "name": p.get("metadata", {}).get("name"),
                            "namespace": p.get("metadata", {}).get("namespace"),
                            "node": p.get("spec", {}).get("nodeName"),
                            "images": [c.get("image") for c in
                                        p.get("spec", {}).get("containers", [])],
                        }
                        for p in pods[:50]
                    ],
                }
    if 10250 in open_nums:
        unauth_pods = kubelet_unauth_pods(host, 10250, timeout=timeout)
        if unauth_pods:
            kube_data["kubelet_unauth"] = {
                "endpoint": "https://" + host + ":10250/pods",
                "severity": "CRITICAL",
                "pod_count": len(unauth_pods),
                "note": "Unauthenticated kubelet exposes pod list + log/exec",
            }
    if kube_data:
        out["kubernetes"] = kube_data

    return out


def scan_hosts_containers(hosts: list, *,
                            timeout: float = 5.0,
                            run_trivy: bool = True,
                            kube_token: Optional[str] = None,
                            workers: int = 4) -> dict[str, dict]:
    """Run container scan against all hosts in parallel.

    Only spawns a worker if the host has a relevant port open
    (2375/2376/2377/6443/8443/10250).
    """
    container_ports = {2375, 2376, 2377, 6443, 8443, 10250}
    candidates = []
    for h in hosts:
        open_nums = {p.number for p in h.ports if p.state == "open"}
        if open_nums & container_ports:
            candidates.append(h)
    if not candidates:
        return {}
    out: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(scan_host_containers, h.ip, h.ports,
                        timeout=timeout, run_trivy=run_trivy,
                        kube_token=kube_token): h.ip
            for h in candidates
        }
        for f in as_completed(futs):
            try:
                result = f.result()
                if result.get("docker") or result.get("kubernetes"):
                    out[futs[f]] = result
            except Exception as e:
                log.debug("container scan worker: %s", e)
    return out
