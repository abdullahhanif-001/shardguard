"""Lane 4 — IaC / CI workflow scanning."""

from __future__ import annotations

import re
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

IAC_PATTERNS = [
    (re.compile(r'action\s*=\s*["\'][^"\']*@[^"\']*["\']'), "unpinned-github-action", "HIGH"),
    (re.compile(r"curl\s+.*\|\s*(ba)?sh"), "curl-pipe-shell", "CRITICAL"),
    (re.compile(r"privileged\s*:\s*true"), "k8s-privileged", "CRITICAL"),
    (re.compile(r"hostNetwork\s*:\s*true"), "k8s-host-network", "HIGH"),
    (re.compile(r"0\.0\.0\.0/0"), "open-cidr", "HIGH"),
    (re.compile(r"password\s*=\s*['\"][^'\"]+['\"]"), "tf-hardcoded-password", "CRITICAL"),
    (re.compile(r"FROM\s+\w+\s*$", re.MULTILINE), "docker-unpinned-base", "MEDIUM"),
]

IAC_GLOBS = ["**/*.tf", "**/*.yaml", "**/*.yml", "**/Dockerfile*", "**/.github/workflows/*"]


def scan_iac(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    files: list[Path] = []
    if target.is_file():
        files = [target]
    else:
        for pattern in IAC_GLOBS:
            files.extend(p for p in target.glob(pattern) if p.is_file())
    for fp in files[:500]:
        text = safe_read_text(fp)
        if not text:
            continue
        fs = str(fp.resolve())
        for i, line in enumerate(text.splitlines(), 1):
            for pat, name, sev in IAC_PATTERNS:
                if pat.search(line):
                    findings.append(
                        LaneFinding(
                            rule_id=f"urns/iac-{name}",
                            severity=sev,
                            message=f"IaC misconfiguration: {name}",
                            file=fs,
                            line=i,
                            lane="iac",
                            tier="P1",
                            asvs_chapter="V13",
                        )
                    )
    return findings
