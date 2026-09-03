#!/usr/bin/env python3
"""Head-to-head on hidden corpus: SCSP vs Sonar-pattern oracle."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

HIDDEN = ROOT / "benchmarks" / "hidden"
OUT = ROOT / "proof" / "universal" / "hidden" / "HIDDEN_LEADERBOARD.json"

SONAR_PATTERNS = [
    re.compile(r"eval\s*\("),
    re.compile(r"exec\s*\("),
    re.compile(r"child_process"),
    re.compile(r"system\s*\("),
    re.compile(r"Runtime\.getRuntime"),
    re.compile(r"Process\.Start"),
    re.compile(r"curl\s+[^|]*\|\s*(ba)?sh"),
]


def _scsp_hit(case: Path, exp: dict) -> bool:
    r = subprocess.run(
        [sys.executable, "-m", "scsp", "scan", str(case), "--format", "json", "--no-nyx", "--skip-verify", "--depth", "universal"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    try:
        data = json.loads(r.stdout) if r.stdout.strip() else {"findings": []}
    except json.JSONDecodeError:
        data = {"findings": []}
    has = bool(data.get("findings"))
    return has if exp.get("verdict") == "DETECT" else not has


def _sonar_hit(case: Path, exp: dict) -> bool:
    hits = False
    for fp in case.rglob("*"):
        if not fp.is_file():
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(p.search(text) for p in SONAR_PATTERNS):
            hits = True
            break
    return hits if exp.get("verdict") == "DETECT" else not hits


def main() -> None:
    if not HIDDEN.is_dir():
        print("hidden corpus missing — run generate_hidden_fixtures.py first", file=sys.stderr)
        sys.exit(1)
    rows = []
    scsp_tp = scsp_n = sonar_tp = sonar_n = 0
    t0 = time.time()
    for lang_dir in sorted(HIDDEN.iterdir()):
        if not lang_dir.is_dir():
            continue
        for case in sorted(lang_dir.iterdir()):
            exp_f = case / "expected.json"
            if not exp_f.is_file():
                continue
            exp = json.loads(exp_f.read_text())
            if exp.get("verdict") != "DETECT":
                continue
            scsp_n += 1
            sonar_n += 1
            sh = _scsp_hit(case, exp)
            so = _sonar_hit(case, exp)
            if sh:
                scsp_tp += 1
            if so:
                sonar_tp += 1
            rows.append({
                "lang": lang_dir.name,
                "case": case.name,
                "technique": exp.get("technique"),
                "scsp": "HIT" if sh else "MISS",
                "sonar": "HIT" if so else "MISS",
            })
    board = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "corpus": str(HIDDEN),
        "malicious_cases": scsp_n,
        "scsp_recall": round(scsp_tp / max(scsp_n, 1), 4),
        "sonar_recall": round(sonar_tp / max(sonar_n, 1), 4),
        "delta_recall": round((scsp_tp - sonar_tp) / max(scsp_n, 1), 4),
        "elapsed_s": round(time.time() - t0, 2),
        "rows": rows[:500],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(board, indent=2), encoding="utf-8")
    print(json.dumps({k: board[k] for k in board if k != "rows"}, indent=2))


if __name__ == "__main__":
    main()
