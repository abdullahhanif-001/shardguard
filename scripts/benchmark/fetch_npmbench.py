#!/usr/bin/env python3
"""NPMBench-style corpus fetcher — stratified Tier I (offline synthesis from MOCK_)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    script = ROOT / "scripts" / "benchmark" / "generate_world_beat_fixtures.py"
    r = subprocess.run([sys.executable, str(script)], cwd=str(ROOT))
    print('{"note": "Tier I synthesized from MOCK stratified sample; full NPMBench download optional"}')
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
