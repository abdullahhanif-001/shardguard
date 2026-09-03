#!/usr/bin/env python3
"""Generate 100K LOC stress corpus for G30 (2000 files x ~50 LOC)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "benchmarks" / "stress" / "100k-loc"
FILES = 2000
LINES_PER_FILE = 50


def main() -> None:
    if DEST.is_dir():
        import shutil
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True, exist_ok=True)
    total_loc = 0
    for i in range(FILES):
        sub = DEST / f"pkg_{i // 100}"
        sub.mkdir(parents=True, exist_ok=True)
        lines = [
            f"// stress module {i}",
            f"const id = {i};",
            "function helper(x) { return x + 1; }",
        ]
        for j in range(LINES_PER_FILE - 3):
            lines.append(f"module.exports['k{i}_{j}'] = helper({j});")
        content = "\n".join(lines) + "\n"
        (sub / f"m{i}.js").write_text(content, encoding="utf-8")
        total_loc += len(lines)
    manifest = {
        "files": FILES,
        "approx_loc": total_loc,
        "path": str(DEST),
    }
    (DEST / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
