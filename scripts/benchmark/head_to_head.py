#!/usr/bin/env python3
"""Head-to-head v2: SCSP vs Semgrep/npm-audit/Trivy on frozen corpus. Outputs BENCHMARK_LEADERBOARD.json."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scsp.incidents import case_path, classify_scan, load_case_expected, load_manifest


def _corpus_sha256() -> str:
    m = ROOT / "benchmarks" / "incidents" / "manifest.json"
    if m.is_file():
        return hashlib.sha256(m.read_bytes()).hexdigest()
    return ""


def _run_scsp(path: Path) -> dict:
    t0 = time.time()
    r = subprocess.run(
        [sys.executable, "-m", "scsp", "scan", str(path), "--format", "json", "--no-nyx"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    ms = int((time.time() - t0) * 1000)
    try:
        data = json.loads(r.stdout) if r.stdout.strip() else {"findings": []}
    except json.JSONDecodeError:
        data = {"findings": []}
    return {
        "verdict": "HIT" if data.get("findings") else "MISS",
        "findings": len(data.get("findings", [])),
        "latency_ms": ms,
        "cross_file": any(f.get("cross_file") for f in data.get("findings", [])),
    }


def _run_semgrep(path: Path) -> dict:
    if not shutil.which("semgrep"):
        return {"verdict": "SKIP", "note": "semgrep not installed"}
    t0 = time.time()
    r = subprocess.run(
        ["semgrep", "--config", "auto", "--json", str(path)],
        capture_output=True,
        text=True,
    )
    ms = int((time.time() - t0) * 1000)
    try:
        hits = len(json.loads(r.stdout or "{}").get("results", []))
    except json.JSONDecodeError:
        hits = 0
    return {"verdict": "HIT" if hits else "MISS", "findings": hits, "latency_ms": ms}


def _run_npm_audit(path: Path) -> dict:
    pkg = path / "package.json"
    if not pkg.is_file():
        return {"verdict": "SKIP", "note": "no package.json"}
    if not shutil.which("npm"):
        return {"verdict": "SKIP", "note": "npm not installed"}
    t0 = time.time()
    try:
        r = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            text=True,
            cwd=str(path),
        )
    except OSError:
        return {"verdict": "SKIP", "note": "npm failed"}
    ms = int((time.time() - t0) * 1000)
    try:
        data = json.loads(r.stdout or "{}")
        vulns = data.get("metadata", {}).get("vulnerabilities", {})
        total = sum(vulns.values()) if isinstance(vulns, dict) else 0
    except (json.JSONDecodeError, TypeError):
        total = 0
    return {"verdict": "HIT" if total else "MISS", "findings": total, "latency_ms": ms}


def _run_trivy(path: Path) -> dict:
    if not shutil.which("trivy"):
        return {"verdict": "SKIP", "note": "trivy not installed"}
    t0 = time.time()
    r = subprocess.run(
        ["trivy", "fs", "--scanners", "vuln", "--format", "json", str(path)],
        capture_output=True,
        text=True,
    )
    ms = int((time.time() - t0) * 1000)
    try:
        data = json.loads(r.stdout or "{}")
        hits = sum(len(r.get("Vulnerabilities") or []) for r in data.get("Results", []))
    except (json.JSONDecodeError, TypeError):
        hits = 0
    return {"verdict": "HIT" if hits else "MISS", "findings": hits, "latency_ms": ms}


def _run_muaddib(path: Path) -> dict:
    cmd = shutil.which("muaddib") or shutil.which("muaddib-scanner")
    if not cmd:
        return {"verdict": "SKIP", "note": "muaddib not installed"}
    t0 = time.time()
    r = subprocess.run([cmd, "scan", str(path)], capture_output=True, text=True)
    ms = int((time.time() - t0) * 1000)
    hit = r.returncode != 0 or "CRITICAL" in (r.stdout + r.stderr) or "HIGH" in (r.stdout + r.stderr)
    return {"verdict": "HIT" if hit else "MISS", "latency_ms": ms}


def _score_row(case: dict, tools: dict) -> dict:
    expected = load_case_expected(case_path(case))
    exp = expected.get("verdict", "DETECT")
    scsp_hit = tools.get("scsp", {}).get("verdict") == "HIT"
    return {
        "id": case["id"],
        "tier": case["tier"],
        "expected": exp,
        "tools": tools,
        "scsp_correct": scsp_hit if exp == "DETECT" else (not scsp_hit if exp == "CLEAN" else True),
    }


def mcnemar_p(scsp_wins: int, other_wins: int) -> float:
    b, c = other_wins, scsp_wins
    if b + c == 0:
        return 1.0
    import math

    stat = (abs(b - c) - 1) ** 2 / (b + c)
    return math.exp(-stat / 2)


def main() -> None:
    manifest = load_manifest()
    tiers = sys.argv[1:] if len(sys.argv) > 1 else ["A", "H"]
    cases = [c for c in manifest["cases"] if c["tier"] in tiers]

    rows = []
    scsp_vs_semgrep_b = scsp_vs_semgrep_c = 0

    for case in cases:
        path = case_path(case)
        if not path.is_dir():
            continue
        tools = {
            "scsp": _run_scsp(path),
            "semgrep": _run_semgrep(path),
            "npm_audit": _run_npm_audit(path),
            "trivy": _run_trivy(path),
            "muaddib": _run_muaddib(path),
        }
        row = _score_row(case, tools)
        rows.append(row)

        if case["tier"] in ("A", "H") and load_case_expected(path).get("verdict") == "DETECT":
            s_hit = tools["scsp"]["verdict"] == "HIT"
            g_hit = tools["semgrep"].get("verdict") == "HIT"
            if s_hit and not g_hit:
                scsp_vs_semgrep_c += 1
            elif g_hit and not s_hit:
                scsp_vs_semgrep_b += 1

    scsp_tp = sum(1 for r in rows if r["expected"] == "DETECT" and r["tools"]["scsp"]["verdict"] == "HIT")
    scsp_fn = sum(1 for r in rows if r["expected"] == "DETECT" and r["tools"]["scsp"]["verdict"] != "HIT")
    recall = scsp_tp / (scsp_tp + scsp_fn) if (scsp_tp + scsp_fn) else 1.0

    leaderboard = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus_sha256": _corpus_sha256(),
        "tiers": list(tiers),
        "cases_total": len(rows),
        "scsp_recall": round(recall, 4),
        "mcnemar_vs_semgrep": {
            "scsp_only_wins": scsp_vs_semgrep_c,
            "semgrep_only_wins": scsp_vs_semgrep_b,
            "p_value": round(mcnemar_p(scsp_vs_semgrep_c, scsp_vs_semgrep_b), 6),
        },
        "cases": rows,
    }

    out = ROOT / "benchmarks" / "BENCHMARK_LEADERBOARD.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(leaderboard, indent=2), encoding="utf-8")

    wb = ROOT / "proof" / "world_beat"
    wb.mkdir(parents=True, exist_ok=True)
    (wb / "BENCHMARK_LEADERBOARD.json").write_text(json.dumps(leaderboard, indent=2), encoding="utf-8")
    raw = wb / "raw"
    raw.mkdir(exist_ok=True)
    (raw / "head_to_head_latest.json").write_text(json.dumps(leaderboard, indent=2), encoding="utf-8")

    print(json.dumps({"written": str(out), "cases": len(rows), "recall": recall}))


if __name__ == "__main__":
    main()
