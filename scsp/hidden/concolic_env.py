"""Hidden logic: concolic env, entropy, IDE hooks, attestation."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

FUTURE_DOOR_PATTERNS = [
    (re.compile(r"setTimeout\s*\([^,]+,\s*\d{5,}"), "time-bomb-setTimeout"),
    (re.compile(r"Date\.now\s*\(\s*\)"), "time-trigger"),
    (re.compile(r"cron|node-cron|schedule\."), "cron-schedule"),
    (re.compile(r"fetch\s*\(\s*['\"]https?://"), "remote-config-fetch"),
]

IDE_PATHS = [
    ".claude/settings.json",
    ".vscode/tasks.json",
    ".vscode/launch.json",
    ".husky/pre-commit",
    ".pre-commit-config.yaml",
    ".github/workflows",
]


def scan_concolic_env(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    from scsp.symbolic_env import scan_symbolic_env

    file_texts: dict[str, str] = {}
    for fp in target.rglob("*.js") if target.is_dir() else [target]:
        if fp.is_file():
            t = safe_read_text(fp)
            if t:
                file_texts[str(fp.resolve())] = t
    for sf in scan_symbolic_env(target, file_texts):
        findings.append(
            LaneFinding(
                rule_id=sf.rule_id,
                severity=sf.severity,
                message=sf.message,
                file=sf.file,
                line=sf.line,
                lane="hidden",
                tier="P2",
                status=sf.status,
            )
        )
    for fs, text in file_texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            for pat, name in FUTURE_DOOR_PATTERNS:
                if pat.search(line) and re.search(r"eval|exec|child_process", text):
                    findings.append(
                        LaneFinding(
                            rule_id=f"urns/future-door-{name}",
                            severity="MEDIUM",
                            message=f"Future door pattern: {name}",
                            file=fs,
                            line=i,
                            lane="hidden",
                            tier="P2",
                            status="SUSPICIOUS",
                            mitre="T1480",
                        )
                    )
    return findings


_SOURCE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".kt", ".kts",
    ".c", ".cpp", ".h", ".php", ".rb", ".cs", ".swift", ".sh", ".bash",
}


def _source_extensions() -> set[str]:
    return set(_SOURCE_EXTENSIONS)


def scan_entropy(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    exts = _source_extensions()
    if target.is_dir():
        files = [p for p in target.rglob("*") if p.is_file() and p.suffix.lower() in exts]
    else:
        files = [target]
    for fp in files:
        if not fp.is_file():
            continue
        text = safe_read_text(fp)
        if not text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for m in re.finditer(r"['\"]([^'\"]{64,})['\"]", line):
                blob = m.group(1)
                freq: dict[str, int] = {}
                for c in blob:
                    freq[c] = freq.get(c, 0) + 1
                n = len(blob)
                ent = -sum((c / n) * math.log2(c / n) for c in freq.values()) if n else 0
                if ent > 5.5:
                    findings.append(
                        LaneFinding(
                            rule_id="urns/entropy-blob",
                            severity="MEDIUM",
                            message=f"High Shannon entropy blob ({ent:.2f})",
                            file=str(fp.resolve()),
                            line=i,
                            lane="hidden",
                            tier="P2",
                            mitre="T1027",
                        )
                    )
    return findings


def scan_ide_hooks(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    for rel in IDE_PATHS:
        p = target / rel
        if p.is_file():
            text = safe_read_text(p) or ""
            if re.search(r"SessionStart|folderOpen|postinstall|curl|eval|exec", text, re.I):
                findings.append(
                    LaneFinding(
                        rule_id="urns/ide-persistence",
                        severity="HIGH",
                        message=f"IDE/CI persistence hook: {rel}",
                        file=str(p.resolve()),
                        lane="hidden",
                        tier="P1",
                        status="DETECT",
                        mitre="T1547",
                        asvs_chapter="V13",
                    )
                )
        elif p.is_dir():
            for wf in p.glob("*.yml"):
                text = safe_read_text(wf) or ""
                if re.search(r"curl.*\|.*bash|secrets\.|GITHUB_TOKEN", text, re.I):
                    findings.append(
                        LaneFinding(
                            rule_id="urns/ci-workflow-risk",
                            severity="HIGH",
                            message=f"Risky CI workflow: {wf.name}",
                            file=str(wf.resolve()),
                            lane="hidden",
                            tier="P1",
                            status="DETECT",
                        )
                    )
    return findings


def scan_attestation(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    prov = target / ".github" / "workflows" / "provenance.yml"
    pkg = target / "package.json"
    if pkg.is_file() and not prov.is_file():
        text = safe_read_text(pkg) or ""
        if "postinstall" in text:
            findings.append(
                LaneFinding(
                    rule_id="urns/attestation-mismatch",
                    severity="MEDIUM",
                    message="Install scripts without SLSA provenance workflow",
                    file=str(pkg.resolve()),
                    lane="hidden",
                    tier="P3",
                    status="SUSPICIOUS",
                )
            )
    return findings


def deobfuscate_and_rescan(target: Path) -> list[LaneFinding]:
    """B14 fix — normalize minified JS then re-scan (L06)."""
    from scsp.deobfuscate import detect_obfuscation_patterns, normalize_minified

    findings: list[LaneFinding] = []
    for fp in target.rglob("*.js") if target.is_dir() else [target]:
        if not fp.is_file() or "node_modules" in fp.parts:
            continue
        text = safe_read_text(fp) or ""
        if len(text) < 500:
            continue
        is_minified = len(text.splitlines()) < 5 and len(text) > 200
        if not is_minified and not detect_obfuscation_patterns(text):
            continue
        norm = normalize_minified(text)
        if re.search(r"eval\s*\(|child_process|Function\s*\(", norm):
            findings.append(
                LaneFinding(
                    rule_id="urns/deobf-relift-exec",
                    severity="CRITICAL",
                    message="Execution sink after deobfuscation re-lift (B14)",
                    file=str(fp.resolve()),
                    line=1,
                    lane="hidden",
                    tier="P0",
                    status="DETECT",
                    witness_constraints={"deobf": True},
                )
            )
    return findings
