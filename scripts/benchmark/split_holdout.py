#!/usr/bin/env python3
"""Assign 80/20 calibration/holdout split to manifest cases (seed=42)."""

from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "benchmarks" / "incidents" / "manifest.json"


def main() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    detect_cases = [c for c in data["cases"] if c.get("tier") in ("A", "H") and c.get("verdict", "DETECT") == "DETECT"]
    random.seed(42)
    random.shuffle(detect_cases)
    holdout_ids = {c["id"] for c in detect_cases[: max(1, len(detect_cases) // 5)]}

    for case in data["cases"]:
        if case["id"] in holdout_ids:
            case["split"] = "holdout"
        else:
            case["split"] = "calibration"

    MANIFEST.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(json.dumps({"holdout": len(holdout_ids), "total": len(data["cases"])}))


if __name__ == "__main__":
    main()
