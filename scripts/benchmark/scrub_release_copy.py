#!/usr/bin/env python3
"""Scrub private hosts and marketing fluff from release tree."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IP = "YOUR_HOST"
EXTS = {".md", ".py", ".sh", ".json", ".yml", ".yaml", ".txt", ".html", ".toml"}
SKIP_PARTS = {".venv", "node_modules", ".git", "__pycache__", "benchmarks/stress"}


def main() -> None:
    changed: list[str] = []
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        if any(s in p.parts for s in (".venv", "node_modules", ".git", "__pycache__")):
            continue
        if "stress" in p.parts and "benchmarks" in p.parts:
            continue
        if p.suffix.lower() not in EXTS:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        orig = text
        if IP in text:
            text = text.replace(IP, "YOUR_HOST")
        # Public marketing surfaces only
        rel = p.relative_to(ROOT)
        top = rel.parts[0] if rel.parts else ""
        if top in ("docs", "site") or p.name in (
            "README.md",
            "DESIGN.md",
            "CONTRIBUTING.md",
            "SECURITY.md",
            "pyproject.toml",
        ):
            text = re.sub(r"(?i)\bmilitary-grade\b", "gate-attested", text)
            text = re.sub(r"(?i)\bworld-first\b", "differentiated", text)
            text = re.sub(r"(?i)\bunbreakable\b", "bounded", text)
        if text != orig:
            p.write_text(text, encoding="utf-8")
            changed.append(str(rel))
    print(f"changed {len(changed)}")
    for c in changed:
        print(c)


if __name__ == "__main__":
    main()
