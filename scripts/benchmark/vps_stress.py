#!/usr/bin/env python3
"""VPS stress tests: parallel scan, memory peak, incremental cache."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROOF = ROOT / "proof" / "universal" / "vps"
STRESS = ROOT / "benchmarks" / "stress" / "100k-loc"
MOCK = ROOT / "fixtures" / "MOCK_"


def _rss_mb() -> float:
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except ImportError:
        try:
            with open("/proc/self/status", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) / 1024
        except OSError:
            pass
    return 0.0


def _scan_one(target: Path) -> dict:
    t0 = time.perf_counter()
    r = subprocess.run(
        [sys.executable, "-m", "scsp", "scan", str(target), "--depth", "universal", "--skip-verify", "--format", "json"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    elapsed = time.perf_counter() - t0
    findings = 0
    try:
        findings = len(json.loads(r.stdout or "{}").get("findings", []))
    except json.JSONDecodeError:
        pass
    return {"target": str(target), "elapsed_s": round(elapsed, 2), "findings": findings, "ok": r.returncode == 0}


def main() -> int:
    PROOF.mkdir(parents=True, exist_ok=True)
    report: dict = {"tests": {}, "rss_peak_mb": 0.0, "status": "PASS"}
    peak = _rss_mb()

    # Parallel load (3 MOCK packages)
    samples = sorted(MOCK.iterdir())[:3] if MOCK.is_dir() else []
    parallel_results = []
    if samples:
        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = [ex.submit(_scan_one, p) for p in samples if p.is_dir()]
            for fut in as_completed(futs):
                parallel_results.append(fut.result())
                peak = max(peak, _rss_mb())
        report["tests"]["parallel_3x"] = {
            "results": parallel_results,
            "all_ok": all(r["ok"] for r in parallel_results),
        }
        if not all(r["ok"] for r in parallel_results):
            report["status"] = "FAIL"

    # G30 stress corpus timing
    if STRESS.is_dir():
        t0 = time.perf_counter()
        r = subprocess.run(
            [sys.executable, "-m", "scsp", "scan", str(STRESS), "--depth", "universal", "--skip-verify"],
            capture_output=True,
            cwd=str(ROOT),
        )
        elapsed = time.perf_counter() - t0
        peak = max(peak, _rss_mb())
        report["tests"]["scale_100k_loc"] = {
            "elapsed_s": round(elapsed, 2),
            "pass": elapsed < 120 and r.returncode == 0,
        }
        if elapsed >= 120 or r.returncode != 0:
            report["status"] = "FAIL"
    else:
        report["tests"]["scale_100k_loc"] = {"error": "stress corpus missing", "pass": False}
        report["status"] = "FAIL"

    # Incremental: second scan should be faster (cache warm)
    if samples:
        first = _scan_one(samples[0])
        second = _scan_one(samples[0])
        peak = max(peak, _rss_mb())
        faster = second["elapsed_s"] <= first["elapsed_s"] * 1.1  # allow 10% jitter
        report["tests"]["incremental"] = {
            "first_s": first["elapsed_s"],
            "second_s": second["elapsed_s"],
            "pass": faster,
        }

    report["rss_peak_mb"] = round(peak, 1)
    if peak > 7168:  # 7 GB
        report["status"] = "FAIL"
        report["oom_risk"] = True

    out = PROOF / "STRESS_REPORT.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
