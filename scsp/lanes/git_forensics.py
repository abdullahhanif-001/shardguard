"""Lane 7 — git forensics (backdoor commits, author anomalies)."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

from scsp.lanes.types import LaneFinding


def scan_git_forensics(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    git_dir = target / ".git"
    if not git_dir.is_dir():
        return findings
    try:
        log = subprocess.run(
            ["git", "-C", str(target), "log", "--oneline", "-20", "--format=%H|%an|%ae|%s"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        authors: set[str] = set()
        for line in log.stdout.strip().splitlines():
            parts = line.split("|", 3)
            if len(parts) < 4:
                continue
            _h, author, email, subject = parts
            authors.add(author)
            if any(k in subject.lower() for k in ("backdoor", "payload", "exfil", "MOCK_BACKDOOR")):
                findings.append(
                    LaneFinding(
                        rule_id="urns/git-suspicious-commit",
                        severity="HIGH",
                        message=f"Suspicious commit message: {subject[:80]}",
                        file=str(target),
                        lane="git_forensics",
                        tier="P3",
                        mitre="T1195.002",
                        asvs_chapter="V15",
                    )
                )
        if len(authors) == 1:
            findings.append(
                LaneFinding(
                    rule_id="urns/git-single-author",
                    severity="LOW",
                    message="Single author — low bus factor (maintainer risk)",
                    file=str(target),
                    lane="git_forensics",
                    tier="P3",
                    asvs_chapter="V15",
                )
            )
        # Large binary in recent commits
        diff_stat = subprocess.run(
            ["git", "-C", str(target), "log", "--diff-filter=A", "--name-only", "-5", "--", "*.exe", "*.dll", "*.so"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        for bn in diff_stat.stdout.strip().splitlines():
            if bn.strip():
                findings.append(
                    LaneFinding(
                        rule_id="urns/git-binary-added",
                        severity="MEDIUM",
                        message=f"Binary added in history: {bn}",
                        file=str(target / bn) if (target / bn).exists() else str(target),
                        lane="git_forensics",
                        tier="P3",
                        asvs_chapter="V15",
                    )
                )
    except (OSError, subprocess.TimeoutExpired):
        pass
    return findings


def maintainer_risk(target: Path) -> dict:
    """L15 — maintainer reliability score."""
    risk = {"bus_factor": 1, "last_commit_days": None, "typosquat_score": 0.0}
    if not (target / ".git").is_dir():
        return risk
    try:
        out = subprocess.run(
            ["git", "-C", str(target), "log", "-1", "--format=%ct"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if out.stdout.strip().isdigit():
            ts = int(out.stdout.strip())
            days = (datetime.now(timezone.utc).timestamp() - ts) / 86400
            risk["last_commit_days"] = round(days, 1)
        authors = subprocess.run(
            ["git", "-C", str(target), "shortlog", "-sn", "--all"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        risk["bus_factor"] = len([l for l in authors.stdout.splitlines() if l.strip()])
    except OSError:
        pass
    return risk
