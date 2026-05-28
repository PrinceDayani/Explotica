"""Credential vault — multi-credential management with priority + rotation.

Phase 58. Replaces the flat per-service {"user", "password"} dict pattern
the codebase was using before. Reality: a real scan often has multiple
credential sets ("the local-admin cred for site A, the domain-admin cred
for site B, the service account, the rotating backup cred") and the
scanner needs to TRY each in priority order, promoting/demoting based on
success per host.

Design:
  - CredentialSet: one (user, password, key) tuple with metadata
    (label, priority, last_success_ts, success_count, fail_count)
  - CredentialVault: per-service list of CredentialSets sorted by
    effective priority. try_credentials() iterates them and records
    success/failure to update priority.
  - VaultProfile: top-level container — one vault per service category
    (ssh / winrm / smb / snmp / mysql / postgres / mssql / mongodb / ...)
  - Persistence: load_profile()/save_profile() to/from JSON (user can
    edit ~/.config/explotica/credentials.json directly).

Security notes:
  - Passwords stored plaintext on disk. This is a network-scanner CLI tool
    aimed at authorized scanning; we're not building a password manager.
    The config file is created with 0o600 permissions where possible.
  - For production scanning, point $EXPLOTICA_CRED_FILE at a tmpfs-mounted
    path so creds aren't persisted to disk.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock
from typing import Iterator, Optional

log = logging.getLogger(__name__)


# ── A single credential ─────────────────────────────────────────────────
@dataclass
class CredentialSet:
    """One (username, password, key_file) tuple with usage metadata.

    Priority is base + adjustments from success/failure history. Higher
    priority is tried first. Defaults: base=100, +5 per success, -10 per
    fail. Bounded [0, 200].
    """
    username: str
    password: str = ""
    key_filename: str = ""           # for SSH
    domain: str = ""                 # for AD / WinRM / SMB
    label: str = ""                  # human-readable note
    priority: int = 100
    last_success_ts: float = 0.0
    last_fail_ts: float = 0.0
    success_count: int = 0
    fail_count: int = 0
    # Optional extra fields for service-specific auth:
    #   community (snmp v1/v2c)
    #   v3_auth_proto, v3_auth_pass, v3_priv_proto, v3_priv_pass, v3_level (snmp v3)
    #   database (postgres / mongo default db)
    #   token (k8s bearer token)
    extra: dict = field(default_factory=dict)

    def effective_priority(self) -> int:
        """Priority adjusted by recent history."""
        p = self.priority
        if self.success_count:
            p += min(self.success_count * 5, 50)
        if self.fail_count:
            p -= min(self.fail_count * 10, 50)
        # Boost very-recent successes
        if self.last_success_ts and (time.time() - self.last_success_ts) < 300:
            p += 20
        return max(0, min(200, p))

    def record_success(self) -> None:
        self.last_success_ts = time.time()
        self.success_count += 1

    def record_failure(self) -> None:
        self.last_fail_ts = time.time()
        self.fail_count += 1

    @property
    def is_key_auth(self) -> bool:
        return bool(self.key_filename)

    def redacted(self) -> dict:
        """Dict for logging/JSON — password redacted."""
        d = asdict(self)
        if d.get("password"):
            d["password"] = "***"
        if d.get("extra", {}).get("v3_auth_pass"):
            d["extra"] = dict(d["extra"])
            d["extra"]["v3_auth_pass"] = "***"
        if d.get("extra", {}).get("v3_priv_pass"):
            d["extra"] = dict(d["extra"])
            d["extra"]["v3_priv_pass"] = "***"
        return d


# ── Per-service vault ───────────────────────────────────────────────────
class CredentialVault:
    """Ordered list of CredentialSets for one service category."""

    def __init__(self, service: str,
                  credentials: Optional[list[CredentialSet]] = None):
        self.service = service
        self.credentials: list[CredentialSet] = credentials or []
        self._lock = Lock()

    def add(self, cred: CredentialSet) -> None:
        with self._lock:
            self.credentials.append(cred)

    def __len__(self) -> int:
        return len(self.credentials)

    def __iter__(self) -> Iterator[CredentialSet]:
        """Iterate in current effective-priority order (highest first)."""
        with self._lock:
            ordered = sorted(self.credentials,
                              key=lambda c: -c.effective_priority())
        return iter(ordered)

    def best(self) -> Optional[CredentialSet]:
        """Return the highest-priority cred, or None if empty."""
        with self._lock:
            if not self.credentials:
                return None
            return max(self.credentials,
                       key=lambda c: c.effective_priority())

    def try_in_order(self, attempt_fn) -> Optional[tuple[CredentialSet, dict]]:
        """Try each cred in priority order via attempt_fn(cred).

        attempt_fn should return:
          - A truthy result dict on success (cred.record_success() is called)
          - None / falsy on failure (cred.record_failure() is called)

        Returns (winning_cred, result_dict) or None if all failed.
        """
        for cred in iter(self):
            try:
                result = attempt_fn(cred)
            except Exception as e:
                log.debug("cred attempt crashed for %s %s: %s",
                          self.service, cred.username, e)
                cred.record_failure()
                continue
            if result:
                cred.record_success()
                return (cred, result)
            cred.record_failure()
        return None


# ── Top-level profile (all services) ────────────────────────────────────
class VaultProfile:
    """Top-level vault holding per-service CredentialVaults."""

    def __init__(self):
        self.vaults: dict[str, CredentialVault] = {}
        self._lock = Lock()

    def vault(self, service: str) -> CredentialVault:
        """Get or create the vault for a service."""
        with self._lock:
            v = self.vaults.get(service)
            if v is None:
                v = CredentialVault(service)
                self.vaults[service] = v
            return v

    def add(self, service: str, cred: CredentialSet) -> None:
        self.vault(service).add(cred)

    def services(self) -> list[str]:
        with self._lock:
            return list(self.vaults.keys())

    def __len__(self) -> int:
        return sum(len(v) for v in self.vaults.values())


# ── Persistence ─────────────────────────────────────────────────────────
def _config_path() -> Path:
    env = os.environ.get("EXPLOTICA_CRED_FILE")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "explotica" / "credentials.json"
    return Path.home() / ".config" / "explotica" / "credentials.json"


def load_profile(path: Optional[Path] = None) -> VaultProfile:
    """Load credentials from JSON config. Returns empty profile if missing."""
    profile = VaultProfile()
    p = path or _config_path()
    if not p.exists():
        return profile
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.warning("credential file %s invalid: %s", p, e)
        return profile
    for service, cred_list in (data.get("vaults") or {}).items():
        if not isinstance(cred_list, list):
            continue
        for cred_dict in cred_list:
            try:
                cs = CredentialSet(
                    username=cred_dict.get("username", ""),
                    password=cred_dict.get("password", ""),
                    key_filename=cred_dict.get("key_filename", ""),
                    domain=cred_dict.get("domain", ""),
                    label=cred_dict.get("label", ""),
                    priority=int(cred_dict.get("priority", 100)),
                    last_success_ts=float(cred_dict.get("last_success_ts", 0.0)),
                    last_fail_ts=float(cred_dict.get("last_fail_ts", 0.0)),
                    success_count=int(cred_dict.get("success_count", 0)),
                    fail_count=int(cred_dict.get("fail_count", 0)),
                    extra=cred_dict.get("extra", {}),
                )
                profile.add(service, cs)
            except (KeyError, TypeError, ValueError) as e:
                log.warning("skipping malformed credential in %s: %s", p, e)
    return profile


def save_profile(profile: VaultProfile, path: Optional[Path] = None) -> Path:
    """Save profile to JSON. Creates parent dir, sets 0o600 perms where possible."""
    p = path or _config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "vaults": {
            service: [asdict(c) for c in vault.credentials]
            for service, vault in profile.vaults.items()
        },
    }
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # Best-effort lock-down — works on POSIX; silently does nothing on Windows
    try:
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return p


# ── Compat helpers — accept legacy {"user":..,"password":..} dict ──────
def cred_set_from_legacy(d: dict) -> CredentialSet:
    """Build a CredentialSet from the old flat-dict form some modules use."""
    return CredentialSet(
        username=d.get("username") or d.get("user") or "",
        password=d.get("password", ""),
        key_filename=d.get("key_filename", ""),
        domain=d.get("domain", ""),
        label=d.get("label", "legacy-import"),
        extra={k: v for k, v in d.items() if k not in (
            "username", "user", "password", "key_filename", "domain", "label"
        )},
    )


def vault_with_legacy(service: str, legacy: dict) -> CredentialVault:
    """One-shot: build a single-cred vault from a legacy dict."""
    v = CredentialVault(service)
    if legacy:
        v.add(cred_set_from_legacy(legacy))
    return v


# ── Module-level convenience ────────────────────────────────────────────
_PROFILE_CACHE: Optional[VaultProfile] = None
_PROFILE_LOCK = Lock()


def get_profile() -> VaultProfile:
    """Return the current process's loaded VaultProfile (lazy)."""
    global _PROFILE_CACHE
    with _PROFILE_LOCK:
        if _PROFILE_CACHE is None:
            _PROFILE_CACHE = load_profile()
        return _PROFILE_CACHE


def reset_profile() -> None:
    """Force reload from disk on next get_profile() call."""
    global _PROFILE_CACHE
    with _PROFILE_LOCK:
        _PROFILE_CACHE = None
