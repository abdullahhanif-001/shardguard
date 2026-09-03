"""Transitive dependency graph from package.json without npm install."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set


RISKY_PACKAGES = {
    "flatmap-stream",
    "event-stream",
    "ua-parser-js",
    "coa",
    "rc",
    "colors",
    "faker",
    "node-ipc",
}


@dataclass
class DepEdge:
    from_pkg: str
    to_pkg: str
    version: str
    depth: int


@dataclass
class TransitiveGraph:
    root: str
    edges: List[DepEdge] = field(default_factory=list)
    risky_paths: List[List[str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "edges": [{"from": e.from_pkg, "to": e.to_pkg, "version": e.version, "depth": e.depth} for e in self.edges],
            "risky_paths": self.risky_paths,
        }


def _read_pkg_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _local_node_modules(pkg_dir: Path, name: str) -> Path | None:
    nm = pkg_dir / "node_modules" / name / "package.json"
    if nm.is_file():
        return nm.parent
    return None


def build_transitive_graph(root: Path, max_depth: int = 3) -> TransitiveGraph:
    root = root.resolve()
    pkg_json = root / "package.json"
    data = _read_pkg_json(pkg_json)
    root_name = data.get("name", root.name)
    graph = TransitiveGraph(root=root_name)

    def walk(pkg_dir: Path, depth: int, chain: List[str]) -> None:
        if depth > max_depth:
            return
        pdata = _read_pkg_json(pkg_dir / "package.json")
        deps = {**pdata.get("dependencies", {}), **pdata.get("devDependencies", {})}
        for dep_name, version in deps.items():
            graph.edges.append(
                DepEdge(from_pkg=pdata.get("name", pkg_dir.name), to_pkg=dep_name, version=str(version), depth=depth)
            )
            new_chain = chain + [dep_name]
            if dep_name in RISKY_PACKAGES:
                graph.risky_paths.append(new_chain)
            local = _local_node_modules(pkg_dir, dep_name)
            if local:
                walk(local, depth + 1, new_chain)

    walk(root, 1, [root_name])
    return graph


def scan_transitive_risk(root: Path) -> List[dict]:
    """Return SUSPICIOUS findings for risky transitive paths."""
    graph = build_transitive_graph(root)
    findings: List[dict] = []
    for path in graph.risky_paths:
        findings.append(
            {
                "rule_id": "scsp/transitive-risk",
                "severity": "HIGH",
                "message": f"Risky transitive dependency path: {' -> '.join(path)}",
                "status": "SUSPICIOUS",
                "evidence_path": [str(root / "package.json")],
            }
        )
    return findings
