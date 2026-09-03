"""CPG-aware minimal slice export."""

from __future__ import annotations

from pathlib import Path

from scsp.sandbox import safe_read_text

SLICE_KEYWORDS = (
    "eval", "exec", "child_process", "process.env", "Function(", "require(",
    "import(", "WebAssembly", "fetch(", "http.", "subprocess", "os.system",
)


def extract_cpg_slice(paths: list[str], out_path: Path | None = None) -> str:
    lines_out: list[str] = []
    for p in paths:
        fp = Path(p)
        text = safe_read_text(fp)
        if not text:
            continue
        lines_out.append(f"// --- {fp.name} ---")
        for i, line in enumerate(text.splitlines(), 1):
            if any(k in line for k in SLICE_KEYWORDS):
                lines_out.append(f"// L{i}: {line[:200]}")
    blob = "\n".join(lines_out)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(blob, encoding="utf-8")
    return blob
