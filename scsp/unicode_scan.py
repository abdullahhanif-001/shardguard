"""Unicode / steganography threat detection — all 12 plugin languages."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List

BIDI_CHARS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}
ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
VARIATION_SELECTORS = {chr(c) for c in range(0xFE00, 0xFE10)}
TAG_CHARS = {chr(c) for c in range(0xE0000, 0xE0080)}

# Universal execution sinks across 12 langs
EXEC_NEAR = re.compile(
    r"(eval|exec|Function|child_process|system|shell_exec|subprocess|os\.system|"
    r"Process\.Start|Runtime|pickle\.loads|ObjectInputStream|passthru|popen|"
    r"Runtime\.getRuntime|exec\.Command|Command::new|ProcessBuilder|"
    r"Process\s*\(|\.spawn\s*\(|openssl_decrypt)",
    re.I,
)

HOMOGLYPH_CYRILLIC = re.compile(r"[\u0400-\u04ff]")
HOMOGLYPH_REQUIRE = re.compile(r"[\u0430-\u044f\uff41-\uff5a]{2,}|[\u0400-\u04ff].*require|require.*[\u0400-\u04ff]")
PHP_CYRILLIC_VAR = re.compile(r"\$[\u0430-\u044f\u0400-\u04ff]")
SHELL_HOMOGLYPH = re.compile(r"[\u0430-\u044f\u0400-\u04ff].*(?:curl|wget|bash|sh\s)")

# Cyrillic → Latin for sink normalization (explicit codepoints)
_HOMO_MAP = {
    0x0430: 0x0061, 0x0431: 0x0062, 0x0435: 0x0065, 0x043E: 0x006F, 0x0440: 0x0070,
    0x0441: 0x0063, 0x0445: 0x0078, 0x0443: 0x0079, 0x0410: 0x0041, 0x0412: 0x0042,
    0x0421: 0x0043, 0x0415: 0x0045, 0x041E: 0x004F, 0x0420: 0x0050, 0x0422: 0x0054,
    0x0423: 0x0055,
}


@dataclass
class UnicodeFinding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    char_code: str
    status: str = "DETECT"

    def to_finding_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "unicode_char": self.char_code,
            "status": self.status,
        }


# All 12 plugin language extensions (hardcoded — avoids registry circular import)
ALL_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".kt", ".kts",
    ".c", ".cpp", ".h", ".php", ".rb", ".cs", ".swift", ".sh", ".bash",
}


def _all_extensions() -> set[str]:
    return set(ALL_EXTENSIONS)


def _normalize_for_sink(text: str) -> str:
    """Strip invisible chars + map Cyrillic homoglyphs for sink matching."""
    t = text
    for ch in ZERO_WIDTH | BIDI_CHARS | TAG_CHARS | VARIATION_SELECTORS:
        t = t.replace(ch, "")
    return t.translate(_HOMO_MAP)


def _has_invisible(text: str) -> bool:
    return any(c in text for c in BIDI_CHARS | ZERO_WIDTH | TAG_CHARS | VARIATION_SELECTORS) or bool(
        HOMOGLYPH_CYRILLIC.search(text)
    )


def _line_of(text: str, pos: int) -> int:
    return text[:pos].count("\n") + 1


def _is_benign_unicode_only(text: str) -> bool:
    if text.startswith("\ufeff") and not EXEC_NEAR.search(text):
        return True
    lines = text.splitlines()
    non_comment = [
        ln for ln in lines
        if ln.strip() and not ln.strip().startswith(("#", "//", "*", "/*"))
    ]
    body = "\n".join(non_comment)
    if "😀" in text and not EXEC_NEAR.search(body):
        return True
    return False


def _homoglyph_checks(text: str, file_path: str, ext: str) -> List[UnicodeFinding]:
    findings: List[UnicodeFinding] = []
    norm = _normalize_for_sink(text)
    if HOMOGLYPH_REQUIRE.search(text) and EXEC_NEAR.search(norm):
        findings.append(
            UnicodeFinding(
                rule_id="scsp/unicode-homoglyph",
                severity="CRITICAL",
                message="Homoglyph identifier near execution sink",
                file=file_path,
                line=1,
                char_code="homoglyph",
            )
        )
    if HOMOGLYPH_CYRILLIC.search(text) and EXEC_NEAR.search(norm):
        findings.append(
            UnicodeFinding(
                rule_id="scsp/unicode-homoglyph-cyrillic",
                severity="CRITICAL",
                message="Cyrillic homoglyph near dangerous sink",
                file=file_path,
                line=1,
                char_code="cyrillic",
            )
        )
    if ext == ".php" and PHP_CYRILLIC_VAR.search(text):
        findings.append(
            UnicodeFinding(
                rule_id="scsp/unicode-php-var-spoof",
                severity="HIGH",
                message="Cyrillic variable name spoofing in PHP",
                file=file_path,
                line=1,
                char_code="php-var",
                status="SUSPICIOUS",
            )
        )
    if ext in (".sh", ".bash") and SHELL_HOMOGLYPH.search(text):
        findings.append(
            UnicodeFinding(
                rule_id="scsp/unicode-shell-homoglyph",
                severity="CRITICAL",
                message="Homoglyph in shell command token",
                file=file_path,
                line=1,
                char_code="shell",
            )
        )
    if re.search(r"[\uff52\uff45\uff51\uff55\uff49\uff52\uff45]", text):
        findings.append(
            UnicodeFinding(
                rule_id="scsp/unicode-fullwidth",
                severity="CRITICAL",
                message="Fullwidth homoglyph execution pattern",
                file=file_path,
                line=1,
                char_code="fullwidth",
            )
        )
    return findings


def scan_unicode_in_text(file_path: str, text: str, ext: str = "") -> List[UnicodeFinding]:
    findings: List[UnicodeFinding] = []
    norm = _normalize_for_sink(text)
    if _is_benign_unicode_only(text) and not _has_invisible(text):
        return findings

    # Invisible char + sink after normalization (catches split-token tricks)
    if _has_invisible(text) and EXEC_NEAR.search(norm):
        findings.append(
            UnicodeFinding(
                rule_id="scsp/unicode-invisible-sink",
                severity="CRITICAL",
                message="Invisible/homoglyph obfuscation hiding execution sink",
                file=file_path,
                line=1,
                char_code="normalized",
            )
        )

    for i, ch in enumerate(text):
        line = _line_of(text, i)
        ctx_start = max(0, i - 40)
        ctx_end = min(len(text), i + 40)
        ctx = text[ctx_start:ctx_end]
        ctx_norm = _normalize_for_sink(ctx)

        if ch in BIDI_CHARS and EXEC_NEAR.search(ctx_norm):
            findings.append(
                UnicodeFinding(
                    rule_id="scsp/unicode-bidi",
                    severity="CRITICAL",
                    message=f"Bidirectional override near dangerous sink (U+{ord(ch):04X})",
                    file=file_path,
                    line=line,
                    char_code=f"U+{ord(ch):04X}",
                )
            )
        elif ch in ZERO_WIDTH and ch != "\ufeff" and EXEC_NEAR.search(ctx_norm):
            findings.append(
                UnicodeFinding(
                    rule_id="scsp/unicode-zero-width",
                    severity="CRITICAL",
                    message=f"Zero-width character in executable context (U+{ord(ch):04X})",
                    file=file_path,
                    line=line,
                    char_code=f"U+{ord(ch):04X}",
                )
            )
        elif ch in VARIATION_SELECTORS and EXEC_NEAR.search(ctx_norm):
            findings.append(
                UnicodeFinding(
                    rule_id="scsp/unicode-variation-selector",
                    severity="HIGH",
                    message="Variation selector adjacent to execution primitive",
                    file=file_path,
                    line=line,
                    char_code=f"U+{ord(ch):04X}",
                    status="SUSPICIOUS",
                )
            )
        elif ch in TAG_CHARS:
            findings.append(
                UnicodeFinding(
                    rule_id="scsp/unicode-tag-char",
                    severity="HIGH",
                    message="Unicode tag character in source",
                    file=file_path,
                    line=line,
                    char_code=f"U+{ord(ch):04X}",
                    status="SUSPICIOUS",
                )
            )

    findings.extend(_homoglyph_checks(text, file_path, ext))
    return findings


def scan_unicode_directory(target: Path) -> List[UnicodeFinding]:
    findings: List[UnicodeFinding] = []
    target = target.resolve()
    exts = _all_extensions()
    files: List[Path] = []
    if target.is_file():
        files = [target]
    else:
        files = [
            p for p in target.rglob("*")
            if p.is_file() and p.suffix.lower() in exts and "node_modules" not in p.parts
        ]

    for jf in files:
        try:
            text = jf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_unicode_in_text(str(jf.resolve()), text, jf.suffix.lower()))

    return findings
