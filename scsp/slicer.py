"""Taint-based minimal security slice export."""

from __future__ import annotations

from pathlib import Path
from typing import List

from scsp.cross_file_taint import Finding


def export_minimal_slice(findings: List[Finding], root: Path) -> str:
    """Build minimal JS slice from evidence paths in findings."""
    paths: List[str] = []
    for f in findings:
        for p in f.evidence_path:
            if p not in paths:
                paths.append(p)
    if not paths:
        return "// no slice\n"

    parts: List[str] = ["// SCSP minimal security slice", ""]
    for p in paths[:8]:
        fp = Path(p)
        if not fp.is_file():
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        # Keep lines with sink/source keywords
        kept = [
            ln
            for ln in lines
            if any(
                k in ln
                for k in (
                    "eval",
                    "exec",
                    "child_process",
                    "require",
                    "process.env",
                    "createDecipher",
                    "Function",
                    "vm.",
                )
            )
        ]
        snippet = "\n".join(kept[:40]) if kept else "\n".join(lines[:15])
        parts.append(f"// --- {fp.name} ---")
        parts.append(snippet)
        parts.append("")
    return "\n".join(parts)


def write_slice_artifacts(case_dir: Path, findings: List[Finding]) -> Path:
    out = case_dir / "minimal_slice.js"
    out.write_text(export_minimal_slice(findings, case_dir), encoding="utf-8")
    return out
