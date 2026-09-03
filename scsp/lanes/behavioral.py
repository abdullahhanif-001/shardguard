"""Lane 5 — behavioral / install-time sandbox (gVisor optional, L17)."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

INSTALL_PATTERNS = [
    (re.compile(r"postinstall|preinstall|prepare"), "lifecycle-hook", "HIGH"),
    (re.compile(r"curl\s+.*\|\s*node"), "curl-pipe-node", "CRITICAL"),
    (re.compile(r"wget\s+.*\|\s*sh"), "wget-pipe-shell", "CRITICAL"),
]


def scan_install_behavior(target: Path) -> list[LaneFinding]:
    """Static install-surface behavioral signals."""
    findings: list[LaneFinding] = []
    pkg = target / "package.json"
    if pkg.is_file():
        text = safe_read_text(pkg) or ""
        data = {}
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            pass
        scripts = data.get("scripts") or {}
        for name, cmd in scripts.items():
            if name in ("postinstall", "preinstall", "prepare", "install"):
                for pat, rule, sev in INSTALL_PATTERNS:
                    if pat.search(cmd) or pat.search(name):
                        findings.append(
                            LaneFinding(
                                rule_id=f"urns/behavioral-{rule}",
                                severity=sev,
                                message=f"Risky install script: {name}",
                                file=str(pkg.resolve()),
                                lane="behavioral",
                                tier="P1",
                                status="DETECT",
                                mitre="T1195.002",
                            )
                        )
                if re.search(r"curl|wget|eval|exec", cmd, re.I):
                    findings.append(
                        LaneFinding(
                            rule_id="urns/behavioral-install-exec",
                            severity="CRITICAL",
                            message=f"Install script executes remote/shell: {name}",
                            file=str(pkg.resolve()),
                            lane="behavioral",
                            tier="P1",
                            status="DETECT",
                        )
                    )
    return findings


def run_gvisor_sandbox(target: Path, timeout: int = 30) -> list[LaneFinding]:
    """Run npm install in gVisor if available (VPS only)."""
    findings: list[LaneFinding] = []
    if not (target / "package.json").is_file():
        return findings
    try:
        which = subprocess.run(["which", "runsc"], capture_output=True, text=True, check=False)
        if which.returncode != 0:
            return findings
        result = subprocess.run(
            ["runsc", "do", "npm", "install", "--ignore-scripts"],
            cwd=str(target),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        combined = (result.stdout or "") + (result.stderr or "")
        if re.search(r"ETIMEDOUT|ECONNREFUSED|malicious|exfil", combined, re.I):
            findings.append(
                LaneFinding(
                    rule_id="urns/behavioral-sandbox-signal",
                    severity="HIGH",
                    message="Sandbox install produced suspicious network activity",
                    file=str(target / "package.json"),
                    lane="behavioral",
                    tier="P2",
                    status="SUSPICIOUS",
                )
            )
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return findings
