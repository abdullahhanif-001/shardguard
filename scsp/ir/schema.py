"""Universal IR schema (CPG-compatible nodes)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeKind(str, Enum):
    FILE = "FILE"
    METHOD = "METHOD"
    CALL = "CALL"
    IMPORT = "IMPORT"
    LITERAL = "LITERAL"
    IDENTIFIER = "IDENTIFIER"
    SOURCE = "SOURCE"
    SINK = "SINK"


@dataclass
class IRNode:
    id: str
    kind: NodeKind
    file: str
    line: int = 1
    label: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class IREdge:
    src: str
    dst: str
    kind: str  # CFG, PDG, CALL, IMPORT


@dataclass
class IRGraph:
    language: str
    nodes: list[IRNode] = field(default_factory=list)
    edges: list[IREdge] = field(default_factory=list)

    def add_node(self, node: IRNode) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: IREdge) -> None:
        self.edges.append(edge)

    def semantic_lift_ok(self) -> bool:
        """G17: must have calls/imports/sources/sinks, not parse-only."""
        kinds = {n.kind for n in self.nodes}
        return bool(kinds & {NodeKind.CALL, NodeKind.IMPORT, NodeKind.SOURCE, NodeKind.SINK})

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "nodes": [
                {"id": n.id, "kind": n.kind.value, "file": n.file, "line": n.line, "label": n.label}
                for n in self.nodes
            ],
            "edges": [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in self.edges],
        }
