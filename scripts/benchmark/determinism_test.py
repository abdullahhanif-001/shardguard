#!/usr/bin/env python3
"""Determinism test: 3 runs must produce identical findings hash."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INCIDENTS = ROOT / "benchmarks" / "incidents"


def findings_hash() -> str:
    manifest = json.loads((INCIDENTS / "manifest.json").read_text(encoding="utf-8"))
    all_findings: list = []
    for case in manifest["cases"][:30]:
        path = ROOT / case["path"]
        r = subprocess.run(
            [sys.executable, "-m", "scsp", "scan", str(path), "--format", "json", "--no-nyx"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        try:
            data = json.loads(r.stdout)
            all_findings.append(sorted(data.get("findings", []), key=lambda x: (x.get("rule_id"), x.get("file"))))
        except json.JSONDecodeError:
            all_findings.append([])
    blob = json.dumps(all_findings, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def main() -> None:
    hashes = [findings_hash() for _ in range(3)]
    identical = len(set(hashes)) == 1
    out = {
        "runs": 3,
        "findings_hash_identical": identical,
        "hashes": hashes,
    }
    wb = ROOT / "proof" / "world_beat"
    wb.mkdir(parents=True, exist_ok=True)
    (wb / "DETERMINISM_ATTESTATION.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out))
    sys.exit(0 if identical else 1)


if __name__ == "__main__":
    main()
