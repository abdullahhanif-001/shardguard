"""Lane 8 — fast pattern scan (OpenGrep/Semgrep-style rules)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

FAST_RULES = [
    (re.compile(r"eval\s*\("), "eval", "CRITICAL"),
    (re.compile(r"innerHTML\s*="), "xss-innerHTML", "HIGH"),
    (re.compile(r"pickle\.loads"), "pickle-deser", "CRITICAL"),
    (re.compile(r"yaml\.load\s*\([^)]*\)(?!.*Loader)"), "yaml-unsafe-load", "HIGH"),
    (re.compile(r"sql\.Query.*\+"), "sql-concat", "HIGH"),
    (re.compile(r"subprocess\.(run|Popen|call)"), "subprocess", "CRITICAL"),
    (re.compile(r"os\.system\s*\("), "os-system", "CRITICAL"),
    (re.compile(r"system\s*\("), "system-call", "CRITICAL"),
    (re.compile(r"Process\.Start\s*\("), "process-start", "CRITICAL"),
    (re.compile(r"Runtime\.getRuntime\(\)\.exec"), "runtime-exec", "CRITICAL"),
    (re.compile(r"exec\.Command\s*\("), "go-exec", "CRITICAL"),
    (re.compile(r"evaluateJavaScript"), "webview-js", "HIGH"),
    (re.compile(r"curl\s+[^|]*\|\s*(ba)?sh"), "curl-pipe-sh", "CRITICAL"),
    (re.compile(r"ObjectInputStream"), "java-deser", "CRITICAL"),
    (re.compile(r"Command::new\s*\("), "rust-command", "CRITICAL"),
    (re.compile(r"\.spawn\s*\("), "rust-spawn", "HIGH"),
    (re.compile(r"Process\s*\(\s*\)"), "swift-process", "HIGH"),
]

EXT = {
    ".js", ".py", ".go", ".rs", ".java", ".c", ".cpp", ".ts", ".yaml", ".yml",
    ".php", ".rb", ".cs", ".kt", ".kts", ".swift", ".sh", ".bash",
}


def scan_fast_patterns(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    files = [target] if target.is_file() else [
        p for p in target.rglob("*") if p.suffix.lower() in EXT and "node_modules" not in p.parts
    ]
    for fp in files[:5000]:
        text = safe_read_text(fp)
        if not text:
            continue
        fs = str(fp.resolve())
        for i, line in enumerate(text.splitlines(), 1):
            for pat, name, sev in FAST_RULES:
                if pat.search(line):
                    findings.append(
                        LaneFinding(
                            rule_id=f"urns/fast-{name}",
                            severity=sev,
                            message=f"Fast pattern: {name}",
                            file=fs,
                            line=i,
                            lane="fast",
                            tier="P1",
                            status="DETECT",
                        )
                    )
    return findings


def scan_semgrep_optional(target: Path) -> list[LaneFinding]:
    """Integrate semgrep if on PATH."""
    findings: list[LaneFinding] = []
    semgrep = shutil.which("semgrep")
    if not semgrep:
        return findings
    try:
        r = subprocess.run(
            [semgrep, "--config", "p/javascript", "--json", "-q", str(target)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if r.stdout:
            import json
            data = json.loads(r.stdout)
            for res in data.get("results", [])[:50]:
                findings.append(
                    LaneFinding(
                        rule_id=f"urns/semgrep-{res.get('check_id', 'rule')}",
                        severity="MEDIUM",
                        message=res.get("extra", {}).get("message", "semgrep hit"),
                        file=res.get("path", str(target)),
                        line=res.get("start", {}).get("line", 1),
                        lane="fast",
                        tier="P1",
                    )
                )
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return findings
