#!/usr/bin/env python3
"""Validate URNS scan report directories (fail-closed schema checks)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_REPORT_KEYS = {"schema", "timestamp", "target", "findings", "tier_counts", "lanes", "findings_count"}
SCAN_DIR_MARKERS = ("SECURITY_REPORT.json", "findings.sarif")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_security_report(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return [f"SECURITY_REPORT.json unreadable: {e}"]
    missing = REQUIRED_REPORT_KEYS - set(data.keys())
    if missing:
        errors.append(f"SECURITY_REPORT.json missing keys: {sorted(missing)}")
    if data.get("schema") != "urns-security-report-v1":
        errors.append(f"unexpected schema: {data.get('schema')}")
    for f in data.get("findings", []):
        if f.get("tier") == "P0":
            if not f.get("witness_constraints") and not f.get("evidence_path"):
                errors.append(f"P0 finding missing witness/evidence: {f.get('rule_id')}")
    return errors


def validate_sarif(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return [f"findings.sarif unreadable: {e}"]
    if data.get("version") != "2.1.0":
        errors.append(f"SARIF version must be 2.1.0, got {data.get('version')}")
    for run in data.get("runs", []):
        for res in run.get("results", []):
            if not res.get("ruleId"):
                errors.append("SARIF result missing ruleId")
            if "level" not in res:
                errors.append("SARIF result missing level")
            locs = res.get("locations", [])
            if not locs:
                errors.append(f"SARIF result {res.get('ruleId')} missing locations")
    return errors


def validate_coverage_matrix(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return [f"coverage_matrix.json unreadable: {e}"]
    if "chapters" not in data:
        errors.append("coverage_matrix missing chapters")
    if "overall_coverage_pct" not in data:
        errors.append("coverage_matrix missing overall_coverage_pct")
    return errors


def validate_attack_surface(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return [f"attack_surface.json unreadable: {e}"]
    for key in ("entry_points", "trust_boundaries"):
        if key not in data:
            errors.append(f"attack_surface missing {key}")
    return errors


def validate_maintainer_risk(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return [f"maintainer_risk.json unreadable: {e}"]
    for key in ("bus_factor", "last_commit_days", "typosquat_score"):
        if key not in data:
            errors.append(f"maintainer_risk missing {key}")
        elif key != "bus_factor" and isinstance(data.get(key), (int, float)):
            if data[key] < 0:
                errors.append(f"maintainer_risk.{key} negative")
    return errors


def validate_scan_dir(scan_dir: Path, require_honest_gaps: bool = False) -> dict:
    result = {"path": str(scan_dir), "status": "PASS", "files": {}, "errors": []}
    if not scan_dir.is_dir():
        result["status"] = "FAIL"
        result["errors"].append("not a directory")
        return result

    checks = [
        ("SECURITY_REPORT.json", validate_security_report),
        ("findings.sarif", validate_sarif),
        ("coverage_matrix.json", validate_coverage_matrix),
        ("attack_surface.json", validate_attack_surface),
        ("maintainer_risk.json", validate_maintainer_risk),
    ]
    for fname, fn in checks:
        fp = scan_dir / fname
        if not fp.is_file():
            result["status"] = "FAIL"
            result["errors"].append(f"missing {fname}")
            continue
        errs = fn(fp)
        result["files"][fname] = {"sha256": _sha256(fp), "status": "PASS" if not errs else "FAIL", "errors": errs}
        if errs:
            result["status"] = "FAIL"
            result["errors"].extend(errs)

    gaps = scan_dir / "HONEST_GAPS.md"
    if require_honest_gaps and not gaps.is_file():
        result["status"] = "FAIL"
        result["errors"].append("missing HONEST_GAPS.md")
    elif gaps.is_file():
        result["files"]["HONEST_GAPS.md"] = {"sha256": _sha256(gaps), "status": "PASS", "errors": []}

    html = scan_dir / "SECURITY_REPORT.html"
    if html.is_file():
        result["files"]["SECURITY_REPORT.html"] = {"sha256": _sha256(html), "status": "PASS", "errors": []}

    return result


def discover_scan_dirs(proof_root: Path) -> list[Path]:
    dirs: list[Path] = []
    for p in proof_root.rglob("*"):
        if p.is_dir() and (p / "SECURITY_REPORT.json").is_file():
            dirs.append(p)
    return sorted(set(dirs))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate URNS report directories")
    parser.add_argument("proof_root", nargs="?", default=str(ROOT / "proof" / "universal"))
    parser.add_argument("--strict", action="store_true", help="Exit 1 on any failure")
    parser.add_argument("--require-honest-gaps", action="store_true")
    parser.add_argument("--output", default=str(ROOT / "proof" / "universal" / "REPORT_VALIDATION.json"))
    args = parser.parse_args()

    proof_root = Path(args.proof_root)
    scan_dirs = discover_scan_dirs(proof_root)
    results = [validate_scan_dir(d, require_honest_gaps=args.require_honest_gaps) for d in scan_dirs]
    summary = {
        "proof_root": str(proof_root),
        "scan_dirs": len(scan_dirs),
        "pass": sum(1 for r in results if r["status"] == "PASS"),
        "fail": sum(1 for r in results if r["status"] == "FAIL"),
        "status": "PASS" if all(r["status"] == "PASS" for r in results) else "FAIL",
        "results": results,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if args.strict and summary["status"] != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
