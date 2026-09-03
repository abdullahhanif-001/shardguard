"""binding.gyp and install-surface scanner (Miasma/Hades class)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

GYP_ACTION_SHELL = re.compile(r'"action"\s*:\s*\[\s*"sh"|"action"\s*:\s*\[\s*"bash"|"action"\s*:\s*\[\s*"cmd"', re.I)
GYP_CURL_PIPE = re.compile(r"curl\s+[^|]+\|\s*sh|wget\s+[^|]+\|\s*sh", re.I)
GYP_HACK_SH = re.compile(r"hack\.sh|malicious|curl\s+.*evil", re.I)
IGNORE_SCRIPTS_BYPASS = re.compile(r"ignore-scripts\s*=\s*false", re.I)


@dataclass
class GypFinding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    status: str = "DETECT"


def scan_gyp_file(path: Path) -> List[GypFinding]:
    findings: List[GypFinding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    fs = str(path.resolve())
    if GYP_ACTION_SHELL.search(text) or GYP_CURL_PIPE.search(text):
        findings.append(
            GypFinding(
                rule_id="scsp/gyp-shell-action",
                severity="CRITICAL",
                message="binding.gyp shell action with potential command execution",
                file=fs,
                line=1,
            )
        )
    if GYP_HACK_SH.search(text) and ("inputs" in text or "outputs" in text):
        findings.append(
            GypFinding(
                rule_id="scsp/gyp-suspicious-script",
                severity="HIGH",
                message="binding.gyp references suspicious shell script in build action",
                file=fs,
                line=1,
                status="SUSPICIOUS",
            )
        )
    return findings


def scan_install_surfaces(root: Path) -> List[GypFinding]:
    findings: List[GypFinding] = []
    root = root.resolve()

    for gyp in root.rglob("binding.gyp"):
        if "node_modules" in gyp.parts:
            continue
        findings.extend(scan_gyp_file(gyp))

    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        scripts = data.get("scripts") or {}
        for name, body in scripts.items():
            if name in ("preinstall", "postinstall", "prepare", "install") and isinstance(body, str):
                if re.search(r"curl\s+.*\|\s*sh|wget\s+.*\|\s*sh|eval\s*\(", body):
                    findings.append(
                        GypFinding(
                            rule_id="scsp/lifecycle-dangerous",
                            severity="CRITICAL",
                            message=f"package.json script '{name}' contains dangerous pattern",
                            file=str(pkg.resolve()),
                            line=1,
                        )
                    )

    npmrc = root / ".npmrc"
    if npmrc.is_file():
        try:
            rc = npmrc.read_text(encoding="utf-8")
        except OSError:
            rc = ""
        if "ignore-scripts=true" not in rc.lower() and data.get("scripts"):
            pass  # informational only

    return findings
