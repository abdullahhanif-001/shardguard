"""Non-unicode steganography: whitespace, comment padding, polyglot."""

from __future__ import annotations

import re
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text


def scan_stego(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    files = [target] if target.is_file() else [
        p for p in target.rglob("*") if p.is_file() and "node_modules" not in p.parts
    ]
    for fp in files[:2000]:
        text = safe_read_text(fp)
        if not text:
            continue
        fs = str(fp.resolve())
        lines = text.splitlines()
        trailing_ws = sum(1 for ln in lines if ln != ln.rstrip() and ln.rstrip())
        if trailing_ws >= 2:
            findings.append(
                LaneFinding(
                    rule_id="urns/stego-whitespace",
                    severity="HIGH",
                    message=f"Trailing whitespace steganography ({trailing_ws} lines)",
                    file=fs,
                    line=1,
                    lane="hidden",
                    tier="P1",
                    status="DETECT",
                    mitre="T1027",
                )
            )
        for i, ln in enumerate(lines, 1):
            if re.match(r"^\s*//+\s*$", ln) and i < len(lines) and re.search(r"eval|exec|system", lines[i - 1] if i > 0 else ""):
                continue
            if len(ln) > 200 and re.match(r"^\s*(//|#)", ln):
                tail = ln.lstrip("/#").strip()
                if len(tail) > 100 and not tail.isalnum():
                    findings.append(
                        LaneFinding(
                            rule_id="urns/stego-comment-padding",
                            severity="MEDIUM",
                            message="Suspicious comment padding",
                            file=fs,
                            line=i,
                            lane="hidden",
                            tier="P2",
                            status="SUSPICIOUS",
                        )
                    )
                    break
        ext = fp.suffix.lower()
        if ext in (".js", ".mjs", ".ts") and "<?php" in text:
            findings.append(
                LaneFinding(
                    rule_id="urns/stego-polyglot",
                    severity="HIGH",
                    message="PHP polyglot header inside JS file",
                    file=fs,
                    line=1,
                    lane="hidden",
                    tier="P1",
                    status="DETECT",
                )
            )
        if text.startswith("#!") and ext in (".js", ".py") and re.search(r"/bin/(ba)?sh", text[:80]):
            findings.append(
                LaneFinding(
                    rule_id="urns/stego-shebang-abuse",
                    severity="MEDIUM",
                    message="Shell shebang in non-shell source",
                    file=fs,
                    line=1,
                    lane="hidden",
                    tier="P2",
                    status="SUSPICIOUS",
                )
            )
    return findings
