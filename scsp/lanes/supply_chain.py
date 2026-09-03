"""Lane 2 — supply chain (wraps existing SCSP modules)."""

from __future__ import annotations

from pathlib import Path

from scsp.cross_file_taint import Finding, scan_directory
from scsp.lanes.types import LaneFinding


def _to_lane(f: Finding, tier: str = "P1") -> LaneFinding:
    witness = {}
    if f.evidence_path:
        witness["evidence_path"] = f.evidence_path
    if f.cross_file:
        tier = "P0" if f.severity == "CRITICAL" and f.cross_file else tier
    return LaneFinding(
        rule_id=f.rule_id,
        severity=f.severity,
        message=f.message,
        file=f.file,
        line=f.line,
        lane="supply_chain",
        tier=tier,
        cross_file=f.cross_file,
        evidence_path=f.evidence_path,
        witness_constraints=witness,
        status=f.status,
        mitre="T1195.002",
    )


def scan_supply_chain(target: Path) -> list[LaneFinding]:
    findings, _ = scan_directory(target)
    out: list[LaneFinding] = []
    for f in findings:
        tier = "P0" if f.status == "DETECT" and f.cross_file and f.severity == "CRITICAL" else "P1"
        if f.status == "UNKNOWN_RISK":
            tier = "OUT_OF_SCOPE"
        elif f.status == "SUSPICIOUS":
            tier = "P2"
        out.append(_to_lane(f, tier=tier))
    return out
