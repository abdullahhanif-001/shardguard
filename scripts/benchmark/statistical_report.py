#!/usr/bin/env python3
"""Generate STATISTICAL_REPORT.json for world_beat proof."""

from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def mcnemar(b: int, c: int) -> float:
    if b + c == 0:
        return 1.0
    stat = (abs(b - c) - 1) ** 2 / (b + c)
    return math.exp(-stat / 2)


def main() -> None:
    lb_path = ROOT / "benchmarks" / "BENCHMARK_LEADERBOARD.json"
    lb = json.loads(lb_path.read_text(encoding="utf-8")) if lb_path.is_file() else {}
    m = lb.get("mcnemar_vs_semgrep", {})

    report = {
        "wilson_ci": "see attestations/G5_REALWORLD.json",
        "mcnemar_vs_semgrep": {
            "scsp_only_wins": m.get("scsp_only_wins", 0),
            "semgrep_only_wins": m.get("semgrep_only_wins", 0),
            "p_value": m.get("p_value", 1.0),
            "significant_at_0_05": m.get("p_value", 1.0) < 0.05,
        },
        "scsp_recall": lb.get("scsp_recall", 0),
        "corpus_sha256": lb.get("corpus_sha256", ""),
        "bootstrap_note": "Run with N=10000 for production; scaffold uses gate metrics",
    }

    wb = ROOT / "proof" / "world_beat"
    wb.mkdir(parents=True, exist_ok=True)
    (wb / "STATISTICAL_REPORT.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"written": str(wb / "STATISTICAL_REPORT.json")}))


if __name__ == "__main__":
    main()
