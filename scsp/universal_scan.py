"""Universal scan orchestrator."""

from __future__ import annotations

import os
from pathlib import Path

from scsp.fusion.datalog_taint import TaintFact, upgrade_findings_with_fusion
from scsp.fusion.z3_paths import scan_env_gates
from scsp.ir.lifter import lift_directory
from scsp.lanes.orchestrator import run_all_lanes
from scsp.report.generator import generate_report
from scsp.scan_limits import ScanLimits
from scsp.sandbox import safe_read_text


def scan_universal(
    target: Path,
    limits: ScanLimits | None = None,
    report_dir: Path | None = None,
    llm_slices: bool = False,
) -> tuple[list, dict, dict | None]:
    """Full URNS scan — all lanes + fusion + optional report."""
    limits = limits or ScanLimits()
    target = target.resolve()

    findings, meta = run_all_lanes(target, limits)

    # Fusion: env gates from JS files
    facts: list[TaintFact] = []
    for fp in target.rglob("*.js") if target.is_dir() else [target]:
        if not fp.is_file():
            continue
        text = safe_read_text(fp) or ""
        fs = str(fp.resolve())
        findings.extend(scan_env_gates(text, fs))
        if "process.env" in text and re.search(r"eval|exec", text):
            facts.append(TaintFact(source="process.env", sink="eval", file=fs, line=1))

    findings = upgrade_findings_with_fusion(findings, facts)

    if llm_slices and os.environ.get("SCSP_LLM_SLICES") == "1":
        from scsp.fusion.llm_slice import classify_slice
        from scsp.fusion.cpg_slicer import extract_cpg_slice

        slice_text = extract_cpg_slice([f.file for f in findings[:5]])
        findings.extend(classify_slice(slice_text, enabled=True))

    # IR lift meta
    graphs = lift_directory(target, max_files=min(100, limits.max_files))
    meta["ir_graphs"] = len(graphs)
    meta["ir_semantic_ok"] = sum(1 for g in graphs if g.semantic_lift_ok())

    report = None
    if report_dir:
        report = generate_report(target, findings, meta, report_dir)

    return findings, meta, report


import re  # noqa: E402
