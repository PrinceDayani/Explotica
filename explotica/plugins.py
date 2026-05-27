"""Plugin/extension system — entry-point based external probe loading.

How third parties add probes:

  # In their package's pyproject.toml:
  [project.entry-points."explotica.probes"]
  myprobe = "my_package.my_module:MyProbe"

  # MyProbe class implements:
  class MyProbe:
      name = "my-probe"
      ports = (8888,)          # ports this probe applies to
      def probe(self, host, port, timeout=3.0) -> dict | None: ...

This module discovers + loads them at scan start. Built-in probes can
also be registered via register_probe() for internal extension.
"""

from __future__ import annotations

import importlib.metadata
import logging
from typing import Optional, Callable, Protocol

log = logging.getLogger(__name__)


class ProbePlugin(Protocol):
    """Duck-typed interface for probe plugins."""
    name: str
    ports: tuple[int, ...]
    def probe(self, host: str, port: int, timeout: float = 3.0) -> Optional[dict]: ...


class ReportPlugin(Protocol):
    """Duck-typed interface for report-writer plugins."""
    name: str
    def write(self, scan_result, output_path: str) -> str: ...


# Registry
_probe_plugins: dict[str, ProbePlugin] = {}
_report_plugins: dict[str, ReportPlugin] = {}
_probe_port_index: dict[int, list[ProbePlugin]] = {}


def register_probe(plugin: ProbePlugin) -> None:
    """Register a probe plugin (for built-ins or programmatic use)."""
    _probe_plugins[plugin.name] = plugin
    for port in plugin.ports:
        _probe_port_index.setdefault(port, []).append(plugin)
    log.info("registered probe plugin: %s (ports: %s)",
             plugin.name, plugin.ports)


def register_report(plugin: ReportPlugin) -> None:
    _report_plugins[plugin.name] = plugin
    log.info("registered report plugin: %s", plugin.name)


def discover_plugins() -> dict[str, list[str]]:
    """Find + load all plugins from `explotica.probes` and `explotica.reports`
    entry points. Returns dict of {group: [loaded plugin names]}.
    """
    loaded = {"probes": [], "reports": []}

    # Probe plugins
    try:
        eps = importlib.metadata.entry_points(group="explotica.probes")
    except TypeError:
        # Python < 3.10
        eps = importlib.metadata.entry_points().get("explotica.probes", [])
    for ep in eps:
        try:
            cls = ep.load()
            instance = cls() if callable(cls) else cls
            register_probe(instance)
            loaded["probes"].append(ep.name)
        except Exception as e:
            log.warning("failed to load probe plugin %s: %s", ep.name, e)

    # Report plugins
    try:
        eps = importlib.metadata.entry_points(group="explotica.reports")
    except TypeError:
        eps = importlib.metadata.entry_points().get("explotica.reports", [])
    for ep in eps:
        try:
            cls = ep.load()
            instance = cls() if callable(cls) else cls
            register_report(instance)
            loaded["reports"].append(ep.name)
        except Exception as e:
            log.warning("failed to load report plugin %s: %s", ep.name, e)

    if loaded["probes"] or loaded["reports"]:
        log.info("plugin discovery: %d probe(s), %d report(s)",
                 len(loaded["probes"]), len(loaded["reports"]))
    return loaded


def probes_for_port(port: int) -> list[ProbePlugin]:
    """Return all probe plugins applicable to a given port."""
    return _probe_port_index.get(port, [])


def all_probes() -> list[ProbePlugin]:
    return list(_probe_plugins.values())


def get_report(name: str) -> Optional[ReportPlugin]:
    return _report_plugins.get(name)


def all_reports() -> list[ReportPlugin]:
    return list(_report_plugins.values())


def run_probe_plugins(host: str, port: int, timeout: float = 3.0) -> dict:
    """Run all probes registered for this port; collect results by plugin name."""
    out: dict = {}
    for plugin in probes_for_port(port):
        try:
            r = plugin.probe(host, port, timeout=timeout)
            if r:
                out[plugin.name] = r
        except Exception as e:
            log.debug("probe plugin %s failed: %s", plugin.name, e)
    return out


# Example skeleton plugin (used as a template)
class ExampleProbe:
    """Template you can copy to write your own probe plugin."""
    name = "example"
    ports = (12345,)

    def probe(self, host: str, port: int,
              timeout: float = 3.0) -> Optional[dict]:
        # Replace with real probe logic.
        import socket
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return {"detected": True, "note": "example probe placeholder"}
        except OSError:
            return None
