"""SARIF output enrichment for scsp-custom fragmentation tags."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List

from scsp.cross_file_taint import Finding


def findings_to_sarif(findings: List[Finding], target: Path) -> dict:
    rules = {}
    results = []
    for f in findings:
        rid = f.rule_id.replace("/", ".")
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.message},
            }
        results.append(
            {
                "ruleId": rid,
                "level": "error" if f.severity in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
                "properties": {
                    "cross_file": f.cross_file,
                    "evidence_path": f.evidence_path,
                    "fragmentation_pattern": f.fragmentation_pattern,
                    "status": f.status,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "scsp", "rules": list(rules.values())}},
                "results": results,
                "originalUriBaseIds": {"ROOT": {"uri": str(target.resolve())}},
            }
        ],
    }


def write_sarif(findings: List[Finding], target: Path, out: Path) -> None:
    out.write_text(json.dumps(findings_to_sarif(findings, target), indent=2), encoding="utf-8")
