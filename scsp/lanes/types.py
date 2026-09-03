"""Unified finding with URNS tier."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LaneFinding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int = 1
    lane: str = "static"
    tier: str = "P1"  # P0, P1, P2, P3, OUT_OF_SCOPE
    cross_file: bool = False
    evidence_path: list[str] = field(default_factory=list)
    witness_constraints: dict[str, Any] = field(default_factory=dict)
    status: str = "DETECT"
    asvs_chapter: str = ""
    mitre: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "lane": self.lane,
            "tier": self.tier,
            "cross_file": self.cross_file,
            "evidence_path": self.evidence_path,
            "witness_constraints": self.witness_constraints,
            "status": self.status,
            "asvs_chapter": self.asvs_chapter,
            "mitre": self.mitre,
        }
