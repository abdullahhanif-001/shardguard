"""Per-language encoding chain unfold (base64/hex/zlib, max depth 3)."""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

MAX_DEPTH = 3
MAX_EXPAND = 65536

SINK_RE = re.compile(
    r"\b(eval|exec|system|shell_exec|Process\.Start|Runtime\.getRuntime|subprocess|os\.system|"
    r"child_process|Function|exec\.Command|pickle\.loads|ObjectInputStream|include\s*\()\b",
    re.I,
)

LANG_PATTERNS: dict[str, list[tuple[re.Pattern, str]]] = {
    "javascript": [
        (re.compile(r"Buffer\.from\s*\(\s*['\"]([0-9a-fA-F]+)['\"]\s*,\s*['\"]hex['\"]\s*\)"), "hex"),
        (re.compile(r"atob\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64"),
    ],
    "python": [
        (re.compile(r"base64\.b64decode\s*\(\s*b?['\"]([A-Za-z0-9+/=]{8,})['\"]"), "b64"),
        (re.compile(r"bytes\.fromhex\s*\(\s*['\"]([0-9a-fA-F]{16,})['\"]\s*\)"), "hex"),
    ],
    "php": [
        (re.compile(r"base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64"),
        (re.compile(r"gzinflate\s*\(\s*base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64zlib"),
    ],
    "ruby": [
        (re.compile(r"Base64\.decode64\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64"),
    ],
    "java": [
        (re.compile(r"Base64\.getDecoder\(\)\.decode\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64"),
    ],
    "kotlin": [
        (re.compile(r"Base64\.getDecoder\(\)\.decode\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64"),
    ],
    "go": [
        (re.compile(r"encoding/base64.*DecodeString\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64"),
    ],
    "csharp": [
        (re.compile(r"Convert\.FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64"),
    ],
    "rust": [
        (re.compile(r"base64::decode\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64"),
    ],
    "c": [
        (re.compile(r"\\x([0-9a-fA-F]{2})"), "hex_esc"),
    ],
    "shell": [
        (re.compile(r"\$'([^']{4,})'"), "shell_hex"),
        (re.compile(r"base64\s+-d\s*\|\s*(ba)?sh"), "shell_b64_pipe"),
        (re.compile(r"echo\s+['\"][A-Za-z0-9+/=]{8,}['\"]\s*\|\s*base64"), "shell_b64_echo"),
    ],
    "swift": [
        (re.compile(r"Data\(base64Encoded:\s*['\"]([A-Za-z0-9+/=]{8,})['\"]\s*\)"), "b64"),
    ],
}


def _decode_blob(kind: str, blob: str) -> str:
    try:
        if kind == "b64":
            return base64.b64decode(blob + "==").decode("utf-8", errors="replace")[:MAX_EXPAND]
        if kind == "hex":
            return bytes.fromhex(blob).decode("utf-8", errors="replace")[:MAX_EXPAND]
        if kind == "b64zlib":
            raw = base64.b64decode(blob + "==")
            return zlib.decompress(raw).decode("utf-8", errors="replace")[:MAX_EXPAND]
        if kind == "hex_esc":
            return blob  # handled separately
    except Exception:
        return ""
    return ""


def _lang_for_ext(ext: str) -> str:
    m = {
        ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "javascript",
        ".py": "python", ".php": "php", ".rb": "ruby", ".java": "java", ".kt": "kotlin",
        ".kts": "kotlin", ".go": "go", ".rs": "rust", ".cs": "csharp", ".swift": "swift",
        ".sh": "shell", ".bash": "shell", ".c": "c", ".cpp": "c", ".h": "c",
    }
    return m.get(ext.lower(), "javascript")


def scan_encoding_chains(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    files = [target] if target.is_file() else [
        p for p in target.rglob("*") if p.is_file() and "node_modules" not in p.parts
    ]
    for fp in files[:2000]:
        text = safe_read_text(fp)
        if not text:
            continue
        lang = _lang_for_ext(fp.suffix)
        patterns = LANG_PATTERNS.get(lang, LANG_PATTERNS["javascript"])
        fs = str(fp.resolve())
        for pat, kind in patterns:
            for m in pat.finditer(text):
                blob = m.group(1) if m.lastindex else m.group(0)
                if kind in ("shell_b64_pipe", "shell_b64_echo"):
                    findings.append(
                        LaneFinding(
                            rule_id="urns/encoding-chain-unfold",
                            severity="CRITICAL",
                            message=f"Shell base64 decode pipe to shell ({kind})",
                            file=fs,
                            line=text[: m.start()].count("\n") + 1,
                            lane="hidden",
                            tier="P0",
                            status="DETECT",
                            evidence_path=[fs, f"unfold:{kind}"],
                            mitre="T1027",
                        )
                    )
                    continue
                expanded = _decode_blob(kind, blob)
                depth = 1
                while depth < MAX_DEPTH and expanded:
                    if SINK_RE.search(expanded):
                        findings.append(
                            LaneFinding(
                                rule_id="urns/encoding-chain-unfold",
                                severity="CRITICAL",
                                message=f"Sink found after {kind} unfold (depth {depth})",
                                file=fs,
                                line=text[: m.start()].count("\n") + 1,
                                lane="hidden",
                                tier="P0",
                                status="DETECT",
                                evidence_path=[fs, f"unfold:{kind}:depth{depth}"],
                                mitre="T1027",
                            )
                        )
                        break
                    inner = ""
                    for p2, k2 in patterns:
                        m2 = p2.search(expanded)
                        if m2:
                            inner = _decode_blob(k2, m2.group(1) if m2.lastindex else m2.group(0))
                            break
                    if not inner:
                        break
                    expanded = inner
                    depth += 1
                if kind == "hex_esc" and SINK_RE.search(text):
                    findings.append(
                        LaneFinding(
                            rule_id="urns/encoding-hex-escape",
                            severity="HIGH",
                            message="Hex escape sequence near execution sink",
                            file=fs,
                            line=1,
                            lane="hidden",
                            tier="P1",
                            status="DETECT",
                        )
                    )
    return findings
