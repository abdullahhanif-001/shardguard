"""Load incident manifest and evaluate case results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scsp.integrity import ROOT

MANIFEST_YAML = ROOT / "benchmarks" / "incidents" / "manifest.yaml"
MANIFEST_JSON = ROOT / "benchmarks" / "incidents" / "manifest.json"


def load_manifest() -> dict:
    if MANIFEST_JSON.is_file():
        return json.loads(MANIFEST_JSON.read_text(encoding="utf-8"))
    if MANIFEST_YAML.is_file():
        text = MANIFEST_YAML.read_text(encoding="utf-8")
        try:
            import yaml

            return yaml.safe_load(text)
        except ImportError:
            pass
        # minimal YAML list parser fallback
        if text.strip().startswith("{"):
            return json.loads(text)
    raise FileNotFoundError("benchmarks/incidents/manifest.yaml not found — run generate_incident_fixtures.py")


def cases_by_tier(manifest: Optional[dict] = None) -> Dict[str, List[dict]]:
    m = manifest or load_manifest()
    out: Dict[str, List[dict]] = {t: [] for t in "ABCDEFG"}
    for case in m.get("cases", []):
        tier = case.get("tier", "?")
        out.setdefault(tier, []).append(case)
    return out


def case_path(case: dict) -> Path:
    rel = case.get("path", "")
    return (ROOT / rel).resolve()


def load_case_expected(case_dir: Path) -> dict:
    exp = case_dir / "expected.json"
    if exp.is_file():
        return json.loads(exp.read_text(encoding="utf-8"))
    return {}


def _fget(f: Any, key: str, default: Any = None) -> Any:
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def classify_scan(
    findings: list,
    expected: dict,
) -> dict:
    """Classify scan result against ground truth."""
    statuses = {_fget(f, "status", "DETECT") for f in findings}
    severities = {_fget(f, "severity", "LOW") for f in findings}
    has_detect = any(s in ("DETECT", "UNKNOWN_RISK", "SUSPICIOUS") for s in statuses)
    has_critical = any(s in ("CRITICAL", "HIGH") for s in severities)
    cross_file = any(_fget(f, "cross_file", False) for f in findings)

    verdict = expected.get("verdict", "DETECT")
    allowed = expected.get("allowed_statuses", ["DETECT"])

    if verdict == "CLEAN":
        passed = not has_detect and not has_critical
        actual = "CLEAN" if passed else "FALSE_POSITIVE"
    elif verdict == "DOCUMENTED_SKIP":
        passed = True
        actual = "DOCUMENTED_SKIP"
    elif verdict == "DOCUMENTED_MISS":
        if not findings:
            actual = "DOCUMENTED_MISS"
            passed = True
        else:
            actual = "BONUS_DETECT" if has_detect else "DOCUMENTED_MISS"
            passed = True
    else:
        passed = has_detect or any(s in allowed for s in statuses)
        actual = "DETECT" if passed else "MISS"

    if expected.get("require_cross_file") and passed and verdict == "DETECT":
        if not cross_file:
            passed = False
            actual = "MISS_NO_CROSS_FILE"

    return {
        "passed": passed,
        "actual": actual,
        "has_detect": has_detect,
        "cross_file": cross_file,
        "statuses": list(statuses),
        "findings_count": len(findings),
    }
