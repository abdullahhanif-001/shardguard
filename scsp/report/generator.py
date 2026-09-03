"""Universal SecurityReport generator."""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scsp.lanes.git_forensics import maintainer_risk
from scsp.lanes.types import LaneFinding
from scsp.report.asvs import ASVS_CHAPTERS, LANE_TO_CHAPTERS
from scsp.report.html_triage import render_triage_html


def build_coverage_matrix(findings: list[LaneFinding], meta: dict) -> dict[str, Any]:
    covered: set[str] = set()
    for f in findings:
        if f.asvs_chapter:
            covered.add(f.asvs_chapter)
    for lane in meta.get("lanes", {}):
        for ch in LANE_TO_CHAPTERS.get(lane, []):
            if isinstance(meta["lanes"].get(lane), int) and meta["lanes"][lane] > 0:
                covered.add(ch)
    chapters = []
    testable = [c for c in ASVS_CHAPTERS if c["testable"]]
    for ch in ASVS_CHAPTERS:
        ch_findings = [f for f in findings if f.asvs_chapter == ch["id"]]
        p0 = sum(1 for f in ch_findings if f.tier == "P0")
        status = "PASS"
        if ch_findings:
            status = "FINDINGS"
        elif not ch["testable"]:
            status = "OUT_OF_SCOPE"
        elif ch["id"] not in covered:
            status = "NOT_APPLICABLE"
        chapters.append(
            {
                "chapter": ch["id"],
                "title": ch["title"],
                "status": status,
                "findings_count": len(ch_findings),
                "p0_count": p0,
                "coverage_pct": 1.0 if ch["id"] in covered else 0.0,
            }
        )
    overall = len([c for c in testable if any(x["chapter"] == c["id"] and x["coverage_pct"] > 0 for x in chapters)])
    return {
        "chapters": chapters,
        "overall_coverage_pct": round(overall / max(len(testable), 1), 4),
        "testable_chapters": len(testable),
        "covered_testable": overall,
    }


def build_attack_surface(findings: list[LaneFinding], target: Path) -> dict[str, Any]:
    entry_points = []
    for f in findings:
        if f.lane in ("supply_chain", "behavioral", "hidden") and "lifecycle" in f.message.lower():
            entry_points.append({"file": f.file, "type": "install_hook"})
        if "http" in f.rule_id or "fetch" in f.rule_id:
            entry_points.append({"file": f.file, "type": "network"})
    return {
        "target": str(target.resolve()),
        "entry_points": entry_points[:50],
        "trust_boundaries": ["npm_registry", "process_env", "filesystem"],
        "data_flows": len([f for f in findings if f.cross_file]),
    }


def build_honest_gaps(findings: list[LaneFinding]) -> str:
    lines = [
        "# Honest Gaps (Rice's Theorem Bounds)",
        "",
        "See docs/RICE_BOUNDS.md for mathematical limits of static analysis.",
        "",
    ]
    oos = [f for f in findings if f.tier == "OUT_OF_SCOPE"]
    if oos:
        lines.append("## OUT_OF_SCOPE findings")
        for f in oos[:20]:
            lines.append(f"- {f.rule_id}: {f.message}")
    lines.extend(
        [
            "",
            "## Known undecidable or out-of-scope cases",
            "- Dynamic `import(expr)` — static resolution is undecidable in the general case",
            "- Business logic / authorization flaws (e.g. IDOR) — require application semantics",
            "- Race conditions / TOCTOU — typically need dynamic analysis",
            "- Guaranteeing detection of all zero-days — impossible",
            "- VM-based JavaScript obfuscators without dynamic execution — OUT_OF_SCOPE",
        ]
    )
    return "\n".join(lines) + "\n"


def generate_report(
    target: Path,
    findings: list[LaneFinding],
    meta: dict,
    out_dir: Path,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage = build_coverage_matrix(findings, meta)
    attack = build_attack_surface(findings, target)
    mr = meta.get("maintainer_risk") or maintainer_risk(target)

    report = {
        "schema": "shardguard-security-report-v1",
        "product": "ShardGuard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": str(target.resolve()),
        "findings_count": len(findings),
        "tier_counts": meta.get("tier_counts", {}),
        "findings": [f.to_dict() for f in findings],
        "coverage_matrix": coverage,
        "attack_surface": attack,
        "maintainer_risk": mr,
        "lanes": meta.get("lanes", {}),
    }

    json_path = out_dir / "SECURITY_REPORT.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out_dir / "coverage_matrix.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
    (out_dir / "attack_surface.json").write_text(json.dumps(attack, indent=2), encoding="utf-8")
    (out_dir / "maintainer_risk.json").write_text(json.dumps(mr, indent=2), encoding="utf-8")
    (out_dir / "HONEST_GAPS.md").write_text(build_honest_gaps(findings), encoding="utf-8")

    html_path = out_dir / "SECURITY_REPORT.html"
    html_path.write_text(render_triage_html(report), encoding="utf-8")

    from scsp.cross_file_taint import Finding
    from scsp.sarif import findings_to_sarif

    sarif_findings = [
        Finding(
            rule_id=f.rule_id,
            severity=f.severity,
            message=f.message,
            file=f.file,
            line=f.line,
            cross_file=f.cross_file,
            evidence_path=f.evidence_path,
            status=f.status,
        )
        for f in findings
    ]
    sarif_path = out_dir / "findings.sarif"
    sarif_path.write_text(json.dumps(findings_to_sarif(sarif_findings, target), indent=2), encoding="utf-8")

    zip_path = out_dir / "shardguard-report.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(html_path, arcname="SECURITY_REPORT.html")
        zf.write(json_path, arcname="SECURITY_REPORT.json")
        zf.write(sarif_path, arcname="findings.sarif")
        zf.write(out_dir / "HONEST_GAPS.md", arcname="HONEST_GAPS.md")

    return report
