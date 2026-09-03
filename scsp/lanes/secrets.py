"""Lane 3 — secrets scanning (entropy + patterns + git history)."""

from __future__ import annotations

import math
import re
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws-access-key", "CRITICAL"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github-token", "CRITICAL"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "openai-key", "CRITICAL"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "private-key", "CRITICAL"),
    (re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*['\"][^'\"]{8,}"), "generic-secret", "HIGH"),
]

SCAN_EXTENSIONS = {
    ".js", ".py", ".go", ".rs", ".java", ".c", ".cpp", ".env", ".yaml", ".yml", ".json", ".tf",
    ".php", ".rb", ".cs", ".kt", ".kts", ".swift", ".sh", ".bash",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def scan_secrets(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    files = [target] if target.is_file() else [
        p for p in target.rglob("*") if p.is_file() and p.suffix.lower() in SCAN_EXTENSIONS
        and "node_modules" not in p.parts
    ]
    for fp in files[:5000]:
        text = safe_read_text(fp)
        if not text:
            continue
        fs = str(fp.resolve())
        for i, line in enumerate(text.splitlines(), 1):
            for pat, name, sev in SECRET_PATTERNS:
                if pat.search(line):
                    findings.append(
                        LaneFinding(
                            rule_id=f"urns/secret-{name}",
                            severity=sev,
                            message=f"Potential secret: {name}",
                            file=fs,
                            line=i,
                            lane="secrets",
                            tier="P1",
                            asvs_chapter="V6",
                        )
                    )
            # High-entropy quoted strings (mock trufflehog)
            for m in re.finditer(r"['\"]([A-Za-z0-9+/=]{32,})['\"]", line):
                blob = m.group(1)
                if _shannon_entropy(blob) > 4.5 and not blob.startswith("MOCK_"):
                    findings.append(
                        LaneFinding(
                            rule_id="urns/secret-high-entropy",
                            severity="MEDIUM",
                            message="High-entropy string may be secret",
                            file=fs,
                            line=i,
                            lane="secrets",
                            tier="P2",
                            asvs_chapter="V6",
                        )
                    )
    return findings


def scan_git_secrets(target: Path) -> list[LaneFinding]:
    """Scan git log for leaked secrets (L03)."""
    import subprocess

    findings: list[LaneFinding] = []
    if not (target / ".git").is_dir():
        return findings
    try:
        out = subprocess.run(
            ["git", "-C", str(target), "log", "-p", "--all", "-S", "AKIA", "--max-count=5"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if "AKIA" in out.stdout:
            findings.append(
                LaneFinding(
                    rule_id="urns/git-secret-history",
                    severity="CRITICAL",
                    message="AWS key pattern found in git history",
                    file=str(target),
                    lane="secrets",
                    tier="P0",
                    witness_constraints={"git": "log -S AKIA"},
                    asvs_chapter="V6",
                )
            )
    except (OSError, subprocess.TimeoutExpired):
        pass
    return findings
