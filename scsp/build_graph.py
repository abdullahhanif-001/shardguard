"""Build graph: package.json lifecycle + module import graph."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set


LIFECYCLE_SCRIPTS = frozenset(
    {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"}
)

IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[\w*{}\s,]+\s+from\s+)?|require\s*\(\s*)['"]([^'"]+)['"]""",
    re.MULTILINE,
)


@dataclass
class BuildGraph:
    root: Path
    nodes: Set[str] = field(default_factory=set)
    edges: List[tuple[str, str, str]] = field(default_factory=list)  # src, dst, kind
    lifecycle_entries: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "nodes": sorted(self.nodes),
            "edges": [{"from": a, "to": b, "kind": k} for a, b, k in self.edges],
            "lifecycle_entries": self.lifecycle_entries,
        }


def resolve_import(base_file: Path, spec: str, root: Path) -> Path | None:
    if spec.startswith("."):
        base = (base_file.parent / spec).resolve()
        candidates = [
            base,
            base.with_suffix(".js"),
            base.with_suffix(".mjs"),
            base.with_suffix(".cjs"),
            base / "index.js",
            base / "index.mjs",
        ]
        for c in candidates:
            if c.is_file():
                return c
    return None


def build_graph(target: Path) -> BuildGraph:
    target = target.resolve()
    graph = BuildGraph(root=target)

    pkg_json = target / "package.json"
    if pkg_json.is_file():
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
            scripts = pkg.get("scripts") or {}
            main = pkg.get("main", "index.js")
            for name, cmd in scripts.items():
                if name in LIFECYCLE_SCRIPTS:
                    entry = str((target / main).resolve()) if (target / main).is_file() else str(pkg_json)
                    graph.lifecycle_entries.append(entry)
                    graph.nodes.add(entry)
                    graph.edges.append((str(pkg_json), entry, f"lifecycle:{name}"))
        except (json.JSONDecodeError, OSError):
            pass

    js_files = list(target.rglob("*.js")) + list(target.rglob("*.mjs")) + list(target.rglob("*.cjs"))
    if target.is_file() and target.suffix in {".js", ".mjs", ".cjs"}:
        js_files = [target]

    for jf in js_files:
        if "node_modules" in jf.parts:
            continue
        rel = str(jf.resolve())
        graph.nodes.add(rel)
        try:
            text = jf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for spec in IMPORT_RE.findall(text):
            resolved = resolve_import(jf, spec, target)
            if resolved:
                dst = str(resolved.resolve())
                graph.nodes.add(dst)
                graph.edges.append((rel, dst, "import"))

    return graph
