#!/usr/bin/env python3
"""HTML dashboard for hidden military gates G41–G48."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROOF = ROOT / "proof" / "universal" / "hidden"
ATTESTATIONS = ROOT / "attestations"
HIDDEN = ROOT / "benchmarks" / "hidden"
LEADERBOARD = PROOF / "HIDDEN_LEADERBOARD.json"


def _gate_rows() -> str:
    rows = []
    for g in range(41, 49):
        p = ATTESTATIONS / f"G{g}_*.json"
        files = list(ATTESTATIONS.glob(f"G{g}_*.json"))
        if not files:
            rows.append(f"<tr><td>G{g}</td><td class='fail'>MISSING</td><td>—</td></tr>")
            continue
        d = json.loads(files[0].read_text())
        st = d.get("status", "FAIL")
        cls = "pass" if st == "PASS" else "fail"
        detail = ", ".join(f"{k}={v}" for k, v in d.items() if k in ("recall", "fpr", "langs_pass", "silent_miss", "failures"))
        rows.append(f"<tr><td>{d.get('gate', f'G{g}')}</td><td class='{cls}'>{st}</td><td>{detail}</td></tr>")
    return "\n".join(rows)


def _heatmap() -> str:
    if not HIDDEN.is_dir():
        return "<p>Corpus not generated.</p>"
    techniques = ["unicode", "encoding", "minified", "homoglyph", "stego", "entropy"]
    langs = sorted(d.name for d in HIDDEN.iterdir() if d.is_dir())
    header = "<tr><th>Lang</th>" + "".join(f"<th>{t}</th>" for t in techniques) + "</tr>"
    body = []
    for lang in langs:
        cells = [f"<td>{lang}</td>"]
        for tech in techniques:
            n = len(list((HIDDEN / lang).glob(f"{tech}*")))
            cells.append(f"<td>{n}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table class='heat'><thead>{header}</thead><tbody>{''.join(body)}</tbody></table>"


def main() -> None:
    lb = {}
    if LEADERBOARD.is_file():
        lb = json.loads(LEADERBOARD.read_text())
    summary = {}
    sp = PROOF / "HIDDEN_MILITARY_SUMMARY.json"
    if sp.is_file():
        summary = json.loads(sp.read_text())
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SCSP Hidden Military Dashboard</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0f1419; color: #e6edf3; }}
.pass {{ color: #3fb950; font-weight: bold; }}
.fail {{ color: #f85149; font-weight: bold; }}
table {{ border-collapse: collapse; margin: 1rem 0; }}
th, td {{ border: 1px solid #30363d; padding: 0.5rem 0.75rem; }}
th {{ background: #161b22; }}
.heat td {{ text-align: center; }}
.card {{ background: #161b22; padding: 1rem; border-radius: 8px; margin: 1rem 0; max-width: 900px; }}
</style></head><body>
<h1>Hidden Military Security — G41–G48</h1>
<div class="card">
<p><strong>Bundle status:</strong> <span class="{'pass' if summary.get('status')=='PASS' else 'fail'}">{summary.get('status', 'UNKNOWN')}</span></p>
<p>Corpus SHA256: <code>{summary.get('corpus_sha256', '—')}</code></p>
<p>SCSP hidden recall: {lb.get('scsp_recall', '—')} | Sonar-pattern: {lb.get('sonar_recall', '—')} | Δ: {lb.get('delta_recall', '—')}</p>
</div>
<h2>Gate grid</h2>
<table><thead><tr><th>Gate</th><th>Status</th><th>Metrics</th></tr></thead>
<tbody>{_gate_rows()}</tbody></table>
<h2>12×6 technique heatmap (case counts)</h2>
{_heatmap()}
<p><small>Generated from hidden_report_dashboard.py — evidence unfold steps in SARIF evidence_path</small></p>
</body></html>"""
    out = PROOF / "hidden_dashboard.html"
    PROOF.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(str(out))


if __name__ == "__main__":
    main()
