#!/usr/bin/env python3
"""Generate HTML dashboard for gates, languages, Sonar compare, report validation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_json(path: Path) -> dict:
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def build_dashboard(proof_root: Path) -> str:
    attestations = ROOT / "attestations"
    gates: dict[str, str] = {}
    for p in sorted(attestations.glob("G*.json")):
        try:
            gates[p.stem] = json.loads(p.read_text()).get("status", "?")
        except json.JSONDecodeError:
            gates[p.stem] = "ERR"

    lang_matrix = _load_json(ROOT / "benchmarks" / "LANGUAGE_MATRIX.json")
    import re

    reg = (ROOT / "scsp" / "plugins" / "registry.py").read_text(encoding="utf-8")
    registered = len(re.findall(r"Plugin\(\)", reg))
    sonar_lb = _load_json(ROOT / "benchmarks" / "SONAR_LEADERBOARD.json")
    report_val = _load_json(proof_root / "REPORT_VALIDATION.json")
    det = _load_json(proof_root / "DETERMINISM_VPS.json")
    strict_summary = _load_json(proof_root / "vps" / "SONAR_PARITY_SUMMARY.json")
    if not strict_summary:
        strict_summary = _load_json(proof_root / "vps" / "HEAVY_STRICT_SUMMARY.json")

    pass_n = sum(1 for v in gates.values() if v == "PASS")
    fail_n = sum(1 for v in gates.values() if v not in ("PASS", "SKIP"))
    skip_n = sum(1 for v in gates.values() if v == "SKIP")

    gate_rows = "".join(
        f"<tr><td>{k}</td><td class='{v.lower()}'>{v}</td></tr>" for k, v in sorted(gates.items())
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SCSP Report Dashboard</title>
<style>
body{{font-family:system-ui;margin:2rem;background:#0f172a;color:#e2e8f0}}
.card{{background:#1e293b;border-radius:8px;padding:1rem;margin:1rem 0}}
.pass{{color:#4ade80}}.fail{{color:#f87171}}.skip{{color:#fbbf24}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #334155;padding:8px}}
.bar{{height:24px;background:#334155;border-radius:4px;overflow:hidden}}
.bar>div{{height:100%;background:#3b82f6}}
</style></head><body>
<h1>SCSP Sonar Parity Dashboard</h1>
<div class="card">
<h2>Gate Summary</h2>
<p>PASS: {pass_n} | FAIL: {fail_n} | SKIP: {skip_n} | Strict: {strict_summary.get('status', 'N/A')}</p>
</div>
<div class="card">
<h2>Language Coverage</h2>
<p>Registered: {registered} / {lang_matrix.get('sonar_target_count', 40)} Sonar target</p>
<div class="bar"><div style="width:{min(100, registered * 100 // max(lang_matrix.get('sonar_target_count', 40), 1))}%"></div></div>
</div>
<div class="card">
<h2>Sonar Head-to-Head</h2>
<p>SCSP recall: {sonar_lb.get('scsp_recall', 'N/A')} | Sonar oracle: {sonar_lb.get('sonar_recall', 'N/A')}</p>
</div>
<div class="card">
<h2>Report Validation</h2>
<p>Status: {report_val.get('status', 'not run')} | Dirs: {report_val.get('scan_dirs', 0)}</p>
</div>
<div class="card">
<h2>Determinism</h2>
<p>Stable: {det.get('stable_across_runs', 'N/A')} | Cross-host match: {det.get('match', 'N/A')}</p>
</div>
<div class="card">
<h2>All Gates</h2>
<table><tr><th>Gate</th><th>Status</th></tr>{gate_rows}</table>
</div>
<p><small>Generated from proof at {proof_root}</small></p>
</body></html>"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", default=str(ROOT / "proof" / "universal"))
    args = parser.parse_args()
    proof_root = Path(args.proof)
    html = build_dashboard(proof_root)
    out = proof_root / "REPORT_DASHBOARD.html"
    out.write_text(html, encoding="utf-8")
    summary = {
        "dashboard": str(out),
        "proof_root": str(proof_root),
    }
    (proof_root / "REPORT_DASHBOARD.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
