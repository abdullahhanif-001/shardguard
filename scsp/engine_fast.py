"""Fast path bridge — uses Rust engine when built, else Python."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUST_BIN = ROOT / "crates" / "scsp-engine" / "target" / "release" / "scsp-engine.exe"
RUST_BIN_UNIX = ROOT / "crates" / "scsp-engine" / "target" / "release" / "scsp-engine"


def count_js_files_fast(target: Path) -> int:
    """Count JS files via Rust binary if available."""
    for bin_path in (RUST_BIN, RUST_BIN_UNIX):
        if bin_path.is_file():
            try:
                r = subprocess.run(
                    [str(bin_path), str(target)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if r.returncode == 0 and r.stdout.strip().isdigit():
                    return int(r.stdout.strip())
            except (OSError, subprocess.TimeoutExpired):
                pass
    # Python fallback
    if target.is_file():
        return 1
    return len(
        [
            p
            for p in list(target.rglob("*.js")) + list(target.rglob("*.mjs"))
            if "node_modules" not in p.parts
        ]
    )
