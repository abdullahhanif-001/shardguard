"""Per-language deobfuscation normalizers (12 langs)."""

from __future__ import annotations

import re
from pathlib import Path

from scsp.deobfuscate import detect_obfuscation_patterns, normalize_minified as normalize_js
from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

SINK_RE = re.compile(
    r"(eval|exec|system|shell_exec|Process\.Start|Runtime\.getRuntime|subprocess|os\.system|"
    r"child_process|Function|exec\.Command|pickle\.loads|ObjectInputStream|"
    r"Command::new|\.spawn\s*\(|Process\s*\()",
    re.I,
)


ALL_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".kt", ".kts",
    ".c", ".cpp", ".h", ".php", ".rb", ".cs", ".swift", ".sh", ".bash",
}


def _extensions() -> set[str]:
    return set(ALL_EXTENSIONS)


def normalize_for_lang(text: str, ext: str) -> str:
    ext = ext.lower()
    if ext in (".js", ".mjs", ".cjs", ".ts", ".tsx"):
        return normalize_js(text)
    if ext == ".py":
        if text.count("\n") > 3:
            return text
        out = re.sub(r";(?=\S)", ";\n", text)
        return re.sub(r"(?<=[):])(?=\S)", "\n", out)
    if ext == ".php":
        if text.count("\n") > 3:
            return text
        return re.sub(r";(?=\S)", ";\n", text)
    if ext in (".sh", ".bash"):
        return text
    if ext in (".java", ".kt", ".kts", ".cs", ".go", ".rs", ".rb", ".swift", ".c", ".cpp"):
        if text.count("\n") > 3:
            return text
        return re.sub(r";(?=\S)", ";\n", text)
    return text


def deobfuscate_all_langs(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    exts = _extensions()
    files = [target] if target.is_file() else [
        p for p in target.rglob("*") if p.is_file() and p.suffix.lower() in exts and "node_modules" not in p.parts
    ]
    for fp in files[:1500]:
        text = safe_read_text(fp) or ""
        if len(text) < 80:
            continue
        is_min = len(text.splitlines()) < 5 and len(text) > 120
        if not is_min and not detect_obfuscation_patterns(text):
            continue
        norm = normalize_for_lang(text, fp.suffix)
        if SINK_RE.search(norm):
            from scsp.plugins.registry import get_plugin_for_file

            lang = get_plugin_for_file(fp)
            findings.append(
                LaneFinding(
                    rule_id="urns/deobf-relift-exec",
                    severity="CRITICAL",
                    message=f"Execution sink after deobfuscation re-lift ({lang.name if lang else 'unknown'})",
                    file=str(fp.resolve()),
                    line=1,
                    lane="hidden",
                    tier="P0",
                    status="DETECT",
                    witness_constraints={"deobf": True, "lang": lang.name if lang else ""},
                    evidence_path=[str(fp.resolve()), "deobf:relift"],
                )
            )
    return findings
