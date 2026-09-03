#!/usr/bin/env python3
"""Build complete proof/world_beat package."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WB = ROOT / "proof" / "world_beat"


def main() -> None:
    WB.mkdir(parents=True, exist_ok=True)
    att_src = ROOT / "attestations"
    att_dst = WB / "attestations"
    att_dst.mkdir(exist_ok=True)
    for p in sorted(att_src.glob("G*.json")):
        shutil.copy2(p, att_dst / p.name)

    for name in [
        "BENCHMARK_LEADERBOARD.json",
        "STATISTICAL_REPORT.json",
        "DETERMINISM_ATTESTATION.json",
        "FP_REGISTRY.json",
        "PERF_PROFILE.json",
    ]:
        src = WB / name
        if not src.is_file() and (ROOT / "benchmarks" / name).is_file():
            shutil.copy2(ROOT / "benchmarks" / name, src)

    # Evidence bundle manifest
    files: list[str] = []
    for p in sorted(WB.rglob("*")):
        if p.is_file():
            rel = p.relative_to(WB).as_posix()
            files.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}")
    (WB / "EVIDENCE_BUNDLE.sha256").write_text("\n".join(files) + "\n", encoding="utf-8")

    meta = {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "file_count": len(files),
    }
    (WB / "EVIDENCE_BUNDLE.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
