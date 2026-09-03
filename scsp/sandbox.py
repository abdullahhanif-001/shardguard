"""Safe file read limits (L30 — scanner self-protection)."""

from __future__ import annotations

from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB per file
MAX_FILES_DEFAULT = 50_000
MAX_LOC_DEFAULT = 500_000


def safe_read_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str | None:
    """Read text with size cap; returns None if too large or unreadable."""
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def iter_safe_files(
    root: Path,
    extensions: set[str],
    max_files: int = MAX_FILES_DEFAULT,
) -> list[Path]:
    """Collect files skipping node_modules and oversize paths."""
    out: list[Path] = []
    if root.is_file():
        if root.suffix.lower() in extensions:
            return [root]
        return []
    for p in root.rglob("*"):
        if len(out) >= max_files:
            break
        if not p.is_file():
            continue
        if "node_modules" in p.parts or ".git" in p.parts:
            continue
        if p.suffix.lower() in extensions:
            out.append(p)
    return out
