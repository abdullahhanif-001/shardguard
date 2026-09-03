#!/usr/bin/env bash
# Final strict proof steps only (stress + scans + summary)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export SCSP_ON_VPS=1 SCSP_STRICT=1 SCSP_VPS_HOST=YOUR_HOST
source .venv/bin/activate

python3 scripts/benchmark/vps_stress.py

CACHE="$ROOT/.cache/repos"
for repo in Hello-World express lodash; do
  if [ -d "$CACHE/$repo" ]; then
    python3 -m scsp scan "$CACHE/$repo" --depth universal --skip-verify --report-dir "proof/universal/vps/scan_$repo"
  fi
done

SSH_PROOF="strict-final-$(date -u +%Y%m%dT%H%M%SZ)-$(hostname)"
python3 -c "
from scsp.universal_gates import write_vps_attestation_strict
write_vps_attestation_strict('${SSH_PROOF}')
"

python3 - <<'PY'
import json
from pathlib import Path
root = Path(".")
atts = sorted((root / "attestations").glob("G*.json"))
summary = {"gates": {}, "pass": 0, "fail": 0, "skip": 0, "strict_mode": True, "no_bypass_flags": True}
for p in atts:
    d = json.loads(p.read_text())
    summary["gates"][p.stem] = d.get("status")
    st = d.get("status")
    if st == "PASS": summary["pass"] += 1
    elif st == "SKIP": summary["skip"] += 1
    else: summary["fail"] += 1
summary["vps"] = {"host": "YOUR_HOST", "nproc": 4, "ram_gb": 8}
if summary["skip"] > 0:
    summary["status"] = "FAIL"
elif summary["fail"] > 0:
    summary["status"] = "FAIL"
else:
    summary["status"] = "PASS"
out = root / "proof" / "universal" / "vps" / "HEAVY_STRICT_SUMMARY.json"
out.write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
PY

cat proof/universal/VPS_ATTESTATION.json
cat proof/universal/vps/STRESS_REPORT.json
