"""Lightweight symbolic env-branch detection for dormant sleepers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from scsp.cross_file_taint import Finding

ENV_GATE_RE = re.compile(
    r"if\s*\(\s*process\.env\.(\w+)|process\.env\.npm_package_name|process\.env\.npm_package_description"
)
SINK_AFTER_GATE = re.compile(r"createDecipher|eval\s*\(|child_process|exec\s*\(")


def scan_symbolic_env(target: Path, file_texts: Dict[str, str]) -> List[Finding]:
    findings: List[Finding] = []
    for fs, text in file_texts.items():
        if not ENV_GATE_RE.search(text):
            continue
        if SINK_AFTER_GATE.search(text):
            findings.append(
                Finding(
                    rule_id="scsp/env-gated-sleeper",
                    severity="HIGH",
                    message="Environment-gated branch with crypto/exec sink (dormant sleeper pattern)",
                    file=fs,
                    line=1,
                    cross_file=False,
                    evidence_path=[fs],
                    status="SUSPICIOUS",
                )
            )
    return findings
