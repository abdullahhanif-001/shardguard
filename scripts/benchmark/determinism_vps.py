#!/usr/bin/env python3
"""Cross-host determinism: hash findings on frozen corpus (3-run strict)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROOF = ROOT / "proof" / "universal"
CORPUS = ROOT / "benchmarks" / "universal" / "head-to-head"
CASE_LIMIT = 50


def findings_hash() -> str:
    from scsp.determinism_hash import findings_hash_normalized
    from scsp.universal_scan import scan_universal

    cases = sorted(CORPUS.iterdir())[:CASE_LIMIT] if CORPUS.is_dir() else []
    return findings_hash_normalized([c for c in cases if c.is_dir()], scan_universal)


def run_n_hashes(runs: int) -> list[str]:
    hashes: list[str] = []
    for _ in range(runs):
        hashes.append(findings_hash())
    return hashes


def main() -> None:
    parser = argparse.ArgumentParser(description="VPS cross-host determinism attestation")
    parser.add_argument("--runs", type=int, default=3, help="Number of consecutive hash runs")
    parser.add_argument("--write-vps-hash", action="store_true", help="Record vps_hash when SCSP_ON_VPS=1")
    args = parser.parse_args()

    PROOF.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    det_path = PROOF / "DETERMINISM_VPS.json"
    if det_path.is_file():
        existing = json.loads(det_path.read_text(encoding="utf-8"))

    run_hashes = run_n_hashes(args.runs)
    stable = len(set(run_hashes)) == 1
    current_hash = run_hashes[0] if stable else ""

    on_vps = os.environ.get("SCSP_ON_VPS") == "1"
    att: dict = {
        "local_hash": existing.get("local_hash", ""),
        "vps_hash": existing.get("vps_hash", ""),
        "corpus": f"benchmarks/universal/head-to-head ({CASE_LIMIT} cases)",
        "vps_host": "YOUR_HOST",
        "runs": args.runs,
        "run_hashes": run_hashes,
        "stable_across_runs": stable,
        "match": False,
    }

    if on_vps and args.write_vps_hash and stable:
        att["vps_hash"] = current_hash
    elif not on_vps and stable:
        att["local_hash"] = current_hash

    if att.get("local_hash") and att.get("vps_hash"):
        att["match"] = att["local_hash"] == att["vps_hash"]

    det_path.write_text(json.dumps(att, indent=2), encoding="utf-8")
    print(json.dumps(att, indent=2))

    if os.environ.get("SCSP_STRICT") == "1" and not stable:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
