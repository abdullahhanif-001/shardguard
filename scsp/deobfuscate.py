"""Deobfuscation helpers: base91-like, hex shards, entropy flags."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

BASE91_CHARS = re.compile(r"['\"][A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_{|}~-]{20,}['\"]")
HEX_BLOB = re.compile(r"['\"]([0-9a-fA-F]{32,})['\"]")
BUFFER_FROM_HEX = re.compile(r"Buffer\.from\s*\(\s*['\"][0-9a-fA-F]+['\"]\s*,\s*['\"]hex['\"]\s*\)")


def detect_obfuscation_patterns(text: str) -> List[Tuple[str, str]]:
    """Return list of (rule_id, message) for obfuscation signals."""
    hits: List[Tuple[str, str]] = []
    if BUFFER_FROM_HEX.search(text):
        hits.append(("scsp/deobf-hex-buffer", "Hex buffer decode pattern"))
    if len(text) > 500_000 and re.search(r"eval|Function|child_process", text):
        hits.append(("scsp/deobf-large-entry", "Oversized entry with execution primitives"))
    if BASE91_CHARS.search(text) and re.search(r"decode|charCodeAt|fromCharCode", text):
        hits.append(("scsp/deobf-encoded-string", "Encoded string with decode chain"))
    # High entropy line density
    lines = [ln for ln in text.splitlines() if len(ln) > 200]
    if len(lines) > 5:
        hits.append(("scsp/deobf-high-entropy", "Multiple long obfuscated lines"))
    return hits


def normalize_minified(text: str) -> str:
    """Insert newlines after semicolons for minified single-file (B14 re-lift)."""
    if "\n" in text and text.count("\n") > 3:
        return text
    # Break on common tokens
    out = re.sub(r";(?=\S)", ";\n", text)
    out = re.sub(r"\{(?=\S)", "{\n", out)
    out = re.sub(r"\}(?=\S)", "}\n", out)
    return out


def normalize_for_extension(text: str, ext: str) -> str:
    """Dispatch per-language normalizer."""
    from scsp.hidden.deobfuscate_lang import normalize_for_lang

    return normalize_for_lang(text, ext)


def preprocess_file(path: Path) -> str:
    """Return normalized text for scanning (decode obvious hex literals in comments only)."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
