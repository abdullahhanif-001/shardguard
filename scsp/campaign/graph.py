"""Campaign intelligence graph."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CampaignNode:
    id: str
    kind: str  # package, maintainer, domain, hash
    attrs: dict = field(default_factory=dict)


@dataclass
class CampaignGraph:
    nodes: list[CampaignNode] = field(default_factory=list)
    edges: list[tuple[str, str, str]] = field(default_factory=list)

    def add(self, node: CampaignNode) -> None:
        self.nodes.append(node)

    def link(self, src: str, dst: str, kind: str) -> None:
        self.edges.append((src, dst, kind))

    def to_dict(self) -> dict:
        return {
            "nodes": [{"id": n.id, "kind": n.kind, **n.attrs} for n in self.nodes],
            "edges": [{"src": s, "dst": d, "kind": k} for s, d, k in self.edges],
        }
