#!/usr/bin/env python3
"""Head-to-head: SCSP vs Sonar-pattern security oracle on frozen corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scsp.incidents import case_path, classify_scan, load_case_expected, load_manifest

# Sonar-equivalent security patterns (community rule IDs as comments)
SONAR_SECURITY_PATTERNS = [
    (re.compile(r"eval\s*\("), "S1523"),
    (re.compile(r"innerHTML\s*="), "S6268"),
    (re.compile(r"child_process\.(exec|spawn)"), "S4721"),
    (re.compile(r"pickle\.loads"), "S6776"),
    (re.compile(r"Process\.Start\s*\("), "S4036"),
    (re.compile(r"Runtime\.getRuntime\(\)\.exec"), "S2656"),
    (re.compile(r"exec\.Command\s*\("), "S2077"),
    (re.compile(r"curl\s+[^|]*\|\s*(ba)?sh"), "S4721"),
    (re.compile(r"ObjectInputStream"), "S5131"),
    (re.compile(r"include\s*\(\s*\$"), "S2030"),
]


def _run_scsp(path: Path) -> dict:
    t0 = time.time()
    r = subprocess.run(
        [sys.executable, "-m", "scsp", "scan", str(path), "--format", "json", "--no-nyx", "--skip-verify"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    ms = int((time.time() - t0) * 1000)
    try:
        data = json.loads(r.stdout) if r.stdout.strip() else {"findings": []}
    except json.JSONDecodeError:
        data = {"findings": []}
    exp = load_case_expected(path)
    has_findings = bool(data.get("findings"))
    if exp.get("verdict") == "DETECT":
        hit = has_findings
    else:
        hit = not has_findings
    return {"verdict": "HIT" if hit else "MISS", "findings": len(data.get("findings", [])), "latency_ms": ms}


def _run_sonar_patterns(path: Path) -> dict:
    t0 = time.time()
    hits = []
    for fp in path.rglob("*"):
        if not fp.is_file() or fp.suffix.lower() not in {".js", ".py", ".go", ".java", ".php", ".rb", ".cs", ".kt", ".swift", ".sh"}:
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat, rule in SONAR_SECURITY_PATTERNS:
            if pat.search(text):
                hits.append(rule)
    ms = int((time.time() - t0) * 1000)
    exp = load_case_expected(path)
    hit = bool(hits) if exp.get("verdict") == "DETECT" else not hits
    return {
        "verdict": "HIT" if hit else "MISS",
        "findings": len(hits),
        "latency_ms": ms,
        "rules": hits[:10],
        "engine": "sonar-pattern-oracle",
    }


def _try_docker_sonar(path: Path) -> dict | None:
    if not shutil.which("docker"):
        return None
    sonar_url = __import__("os").environ.get("SONAR_HOST_URL", "")
    if not sonar_url:
        return None
    props = ROOT / "tmp_sonar" / "sonar-project.properties"
    props.parent.mkdir(parents=True, exist_ok=True)
    props.write_text(
        f"sonar.projectKey=scsp-bench\nsonar.sources={path}\nsonar.host.url={sonar_url}\n",
        encoding="utf-8",
    )
    t0 = time.time()
    r = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{path}:/usr/src", "sonarsource/sonar-scanner-cli"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    ms = int((time.time() - t0) * 1000)
    if r.returncode != 0:
        return {"verdict": "SKIP", "note": r.stderr[:200], "latency_ms": ms}
    return {"verdict": "HIT", "findings": 1, "latency_ms": ms, "engine": "sonar-scanner-docker"}


def build_leaderboard(tiers: list[str] | None = None) -> dict:
    tiers = tiers or ["A", "H"]
    manifest = load_manifest()
    cases = [c for c in manifest.get("cases", manifest if isinstance(manifest, list) else []) if c.get("tier") in tiers]
    if not cases and isinstance(manifest, dict):
        cases = [c for c in manifest.get("cases", []) if c.get("tier") in tiers]
    rows = []
    scsp_tp = sonar_tp = 0
    for c in cases:
        p = case_path(c)
        if not p.is_dir():
            continue
        scsp = _run_scsp(p)
        sonar = _try_docker_sonar(p) or _run_sonar_patterns(p)
        exp = load_case_expected(p)
        scsp_ok = scsp["verdict"] == "HIT" if exp.get("verdict") == "DETECT" else scsp["verdict"] == "MISS"
        sonar_ok = sonar["verdict"] == "HIT" if exp.get("verdict") == "DETECT" else sonar.get("verdict") != "HIT"
        if scsp_ok:
            scsp_tp += 1
        if sonar_ok:
            sonar_tp += 1
        rows.append({"id": c["id"], "tier": c.get("tier"), "expected": exp.get("verdict"), "scsp": scsp, "sonar": sonar})
    n = max(len(rows), 1)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cases_total": len(rows),
        "scsp_recall": round(scsp_tp / n, 4),
        "sonar_recall": round(sonar_tp / n, 4),
        "scsp_wins": scsp_tp,
        "sonar_wins": sonar_tp,
        "cases": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compare", default="", help="Existing leaderboard path")
    parser.add_argument("--tiers", default="A,H")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    if args.compare:
        lb = json.loads(Path(args.compare).read_text(encoding="utf-8"))
        print(json.dumps(lb, indent=2))
        return 0

    tiers = [t.strip() for t in args.tiers.split(",") if t.strip()]
    lb = build_leaderboard(tiers)
    out = ROOT / "benchmarks" / "SONAR_LEADERBOARD.json"
    out.write_text(json.dumps(lb, indent=2), encoding="utf-8")
    print(json.dumps(lb, indent=2))
    if args.strict:
        if lb["scsp_recall"] < lb["sonar_recall"]:
            return 1
        if any(c["sonar"].get("verdict") == "SKIP" for c in lb["cases"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
