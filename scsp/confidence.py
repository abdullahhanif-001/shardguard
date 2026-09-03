"""Deterministic confidence ladder (Anthropic-style, fully offline)."""

from __future__ import annotations

from typing import List

from scsp.cross_file_taint import Finding

SINK_SEVERITY = {"eval", "Function", "command.exec", "vm.exec", "constructor.eval"}


def score_finding(f: Finding, unicode_adjacent: bool = False, lifecycle_entry: bool = False) -> int:
    score = 35  # base for any emitted finding
    if f.cross_file and len(f.evidence_path) >= 2:
        score += 40
    sink = f.rule_id.replace("scsp/taint-", "").replace("scsp/", "")
    if sink in SINK_SEVERITY or f.severity == "CRITICAL":
        score += 25
    if unicode_adjacent or f.rule_id.startswith("scsp/unicode"):
        score += 20
    if lifecycle_entry or "lifecycle" in f.message.lower() or "postinstall" in f.message.lower():
        score += 15
    if not f.cross_file and len(f.evidence_path) <= 1:
        score -= 15
    if not f.evidence_path:
        score -= 10
    return max(0, min(100, score))


def apply_confidence_ladder(findings: List[Finding], lifecycle_entry: bool = False) -> List[Finding]:
    """Filter and relabel findings by confidence score."""
    out: List[Finding] = []
    for f in findings:
        unicode_adj = f.rule_id.startswith("scsp/unicode")
        s = score_finding(f, unicode_adjacent=unicode_adj, lifecycle_entry=lifecycle_entry)
        if s < 50:
            continue  # suppress from alert queue
        nf = Finding(
            rule_id=f.rule_id,
            severity="CRITICAL" if s >= 80 else f.severity,
            message=f.message + f" [confidence={s}]",
            file=f.file,
            line=f.line,
            cross_file=f.cross_file,
            evidence_path=f.evidence_path,
            fragmentation_pattern=f.fragmentation_pattern,
            status="DETECT" if s >= 80 else ("SUSPICIOUS" if s >= 50 else f.status),
        )
        out.append(nf)
    return out


def f3_score(precision: float, recall: float, beta: float = 3.0) -> float:
    if precision + recall == 0:
        return 0.0
    b2 = beta * beta
    return (1 + b2) * precision * recall / (b2 * precision + recall)


def precision_at_k(findings_per_case: List[bool], k: int = 20) -> float:
    top = findings_per_case[:k]
    if not top:
        return 1.0
    return sum(1 for x in top if x) / len(top)
