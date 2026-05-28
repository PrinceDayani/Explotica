"""Module dependency graph generator — Phase 65.

Walks the explotica package and produces:
  1. A coupling report: each module → list of imports, sorted by fan-in/fan-out
  2. A DOT-format graph for graphviz rendering
  3. Highlights "god modules" (high fan-out) and "bottlenecks" (high fan-in)

Run from repo root:
  python tools/dep_graph.py                  # text report only
  python tools/dep_graph.py --dot graph.dot  # also emit DOT file
  python tools/dep_graph.py --threshold 20   # flag modules with 20+ imports

Convert to image:
  dot -Tsvg graph.dot -o graph.svg
  dot -Tpng graph.dot -o graph.png
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections import defaultdict
from pathlib import Path


def find_explotica_package() -> Path:
    here = Path(__file__).resolve()
    for parent in [here.parent.parent] + list(here.parents):
        pkg = parent / "explotica"
        if pkg.is_dir() and (pkg / "__init__.py").exists():
            return pkg
    raise SystemExit("explotica/ package not found")


def module_name(path: Path, root: Path) -> str:
    """Convert .../explotica/discovery/aio.py → explotica.discovery.aio"""
    rel = path.relative_to(root.parent)
    parts = list(rel.with_suffix("").parts)
    return ".".join(parts)


def extract_imports(path: Path) -> set[str]:
    """Return the set of relative-or-absolute imports inside `path`."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set()
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level > 0:
                # Relative import — synthesize the absolute path
                # node.module may be None for `from . import X`
                imports.add((".." * (node.level - 1)
                              + (node.module or "")))
            elif node.module and node.module.startswith("explotica"):
                imports.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("explotica"):
                    imports.add(alias.name)
    return imports


def build_graph(pkg: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Returns (fan_out, fan_in) maps. Both keyed by module name."""
    fan_out: dict[str, set[str]] = {}
    all_modules: set[str] = set()

    for path in pkg.rglob("*.py"):
        if path.name == "__init__.py":
            continue
        mod = module_name(path, pkg)
        all_modules.add(mod)
        imports = extract_imports(path)
        fan_out[mod] = imports

    # Build fan-in (reverse graph)
    fan_in: dict[str, set[str]] = defaultdict(set)
    for src, deps in fan_out.items():
        for dep in deps:
            fan_in[dep].add(src)

    return fan_out, dict(fan_in)


def print_report(fan_out: dict[str, set[str]],
                  fan_in: dict[str, set[str]],
                  threshold: int) -> None:
    print("=" * 72)
    print("EXPLOTICA MODULE DEPENDENCY REPORT")
    print("=" * 72)
    print()

    # High fan-out (god modules — depend on many things)
    print("─── HIGH FAN-OUT (modules that pull in many dependencies) ───")
    print("    (these are good refactor targets — splitting them helps)")
    god_modules = sorted(fan_out.items(),
                          key=lambda kv: len(kv[1]), reverse=True)[:15]
    for mod, deps in god_modules:
        marker = "  !! " if len(deps) >= threshold else "     "
        print(marker + str(len(deps)).rjust(3) + "  " + mod)
    print()

    # High fan-in (bottlenecks — many things depend on these)
    print("─── HIGH FAN-IN (modules that many others depend on) ───")
    print("    (these are foundation modules — changes here ripple widely)")
    bottlenecks = sorted(fan_in.items(),
                          key=lambda kv: len(kv[1]), reverse=True)[:15]
    for mod, depends_on_me in bottlenecks:
        print("     " + str(len(depends_on_me)).rjust(3) + "  " + mod)
    print()

    # Module counts per sub-package
    print("─── MODULES PER SUB-PACKAGE ───")
    by_pkg: dict[str, int] = defaultdict(int)
    for mod in fan_out:
        parts = mod.split(".")
        if len(parts) >= 3:  # explotica.PKG.module
            by_pkg[parts[1]] += 1
        else:
            by_pkg["(top-level)"] += 1
    for pkg in sorted(by_pkg, key=lambda k: by_pkg[k], reverse=True):
        print("     " + str(by_pkg[pkg]).rjust(3) + "  " + pkg)
    print()

    # Total stats
    total_deps = sum(len(d) for d in fan_out.values())
    print("─── SUMMARY ───")
    print("     " + str(len(fan_out)) + " modules")
    print("     " + str(total_deps) + " total import edges")
    avg = total_deps / max(1, len(fan_out))
    print("     " + str(round(avg, 1)) + " avg imports per module")
    print()


def emit_dot(fan_out: dict[str, set[str]], output: Path) -> None:
    """Generate Graphviz DOT graph. Color nodes by sub-package."""
    colors = {
        "core": "#1f77b4", "safety_kit": "#ff7f0e", "discovery": "#2ca02c",
        "fingerprint": "#d62728", "vulns": "#9467bd", "protocols": "#8c564b",
        "credentialed": "#e377c2", "enrich": "#7f7f7f", "active": "#bcbd22",
        "ad": "#17becf", "specialized": "#aec7e8", "output": "#ffbb78",
        "ui": "#98df8a", "runtime": "#ff9896",
    }
    lines = ["digraph explotica {", "  rankdir=LR;",
             "  node [shape=box, style=filled];"]
    for mod, deps in fan_out.items():
        parts = mod.split(".")
        pkg = parts[1] if len(parts) >= 3 else "top-level"
        color = colors.get(pkg, "#cccccc")
        label = ".".join(parts[1:]) if len(parts) >= 3 else parts[-1]
        lines.append('  "' + mod + '" [fillcolor="' + color
                      + '", label="' + label + '"];')
    for src, deps in fan_out.items():
        for dep in deps:
            if dep in fan_out:
                lines.append('  "' + src + '" -> "' + dep + '";')
    lines.append("}")
    output.write_text("\n".join(lines), encoding="utf-8")
    print("DOT graph written to:", output)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--threshold", type=int, default=15,
                    help="Flag modules with this many imports (default: 15)")
    p.add_argument("--dot", type=Path, default=None,
                    help="Emit Graphviz DOT to this path")
    args = p.parse_args()

    pkg = find_explotica_package()
    fan_out, fan_in = build_graph(pkg)
    print_report(fan_out, fan_in, args.threshold)
    if args.dot:
        emit_dot(fan_out, args.dot)
    return 0


if __name__ == "__main__":
    sys.exit(main())
