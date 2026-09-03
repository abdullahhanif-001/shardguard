"""Deterministic readability anomaly detection (military hidden signals)."""

from __future__ import annotations

import math
import re
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

IDENT_RE = re.compile(r"\b[a-zA-Z_\u0400-\u04ff][\w\u0400-\u04ff]*")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


ALL_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".kt", ".kts",
    ".c", ".cpp", ".h", ".php", ".rb", ".cs", ".swift", ".sh", ".bash",
}


def _scanable_extensions() -> set[str]:
    return set(ALL_EXTENSIONS)


def scan_readability(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    exts = _scanable_extensions()
    files = [target] if target.is_file() else [
        p for p in target.rglob("*") if p.is_file() and p.suffix.lower() in exts and "node_modules" not in p.parts
    ]
    for fp in files[:2000]:
        text = safe_read_text(fp)
        if not text:
            continue
        lines = text.splitlines()
        fs = str(fp.resolve())
        loc = len(lines)
        if loc == 0:
            continue
        avg_len = sum(len(ln) for ln in lines) / loc
        if avg_len > 200:
            findings.append(
                LaneFinding(
                    rule_id="urns/hidden-long-line-density",
                    severity="MEDIUM",
                    message=f"Average line length {avg_len:.0f} chars (human-unreadable density)",
                    file=fs,
                    line=1,
                    lane="hidden",
                    tier="P2",
                    status="SUSPICIOUS",
                    mitre="T1027",
                )
            )
        ids = IDENT_RE.findall(text)
        if ids:
            ent = sum(_shannon(i) for i in ids) / len(ids)
            if ent > 4.5:
                findings.append(
                    LaneFinding(
                        rule_id="urns/hidden-id-entropy",
                        severity="MEDIUM",
                        message=f"High identifier entropy ({ent:.2f})",
                        file=fs,
                        line=1,
                        lane="hidden",
                        tier="P2",
                        status="SUSPICIOUS",
                    )
                )
        if loc > 500:
            comments = sum(1 for ln in lines if ln.strip().startswith(("#", "//", "/*", "*")))
            if comments / loc < 0.01:
                findings.append(
                    LaneFinding(
                        rule_id="urns/hidden-no-comment-blob",
                        severity="LOW",
                        message="Large file with almost no comments",
                        file=fs,
                        line=1,
                        lane="hidden",
                        tier="P3",
                        status="SUSPICIOUS",
                    )
                )
        non_ascii = sum(1 for c in text if ord(c) > 127)
        if len(text) > 100 and non_ascii / len(text) > 0.30:
            if not re.search(r"[\u4e00-\u9fff]", text):
                findings.append(
                    LaneFinding(
                        rule_id="urns/hidden-nonascii-code",
                        severity="MEDIUM",
                        message=f"High non-ASCII ratio ({100*non_ascii/len(text):.0f}%)",
                        file=fs,
                        line=1,
                        lane="hidden",
                        tier="P2",
                        status="SUSPICIOUS",
                    )
                )
    return findings
