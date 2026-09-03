#!/usr/bin/env bash
# Sonar parity strict benchmark — G0-G40, no bypass
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export SCSP_ON_VPS=1
export SCSP_STRICT=1
export SCSP_SONAR_PARITY=1
export SCSP_VPS_HOST="${SCSP_VPS_HOST:-YOUR_HOST}"
export SCSP_MAX_PARALLEL=3
unset SCSP_G32_SMOKE SCSP_SKIP_VERIFY SCSP_SKIP_VPS_ATTESTATION 2>/dev/null || true

LOG="$ROOT/proof/universal/vps/SONAR_PARITY_STRICT.log"
mkdir -p "$ROOT/proof/universal/vps" "$ROOT/attestations"

if [ -z "${SCSP_STRICT_DETACHED:-}" ]; then
  export SCSP_STRICT_DETACHED=1
  setsid bash "$0" "$@" </dev/null >>"$LOG" 2>&1 &
  echo "[sonar-strict] detached PID=$! log=$LOG"
  exit 0
fi

exec >>"$LOG" 2>&1
echo "[sonar-strict] start $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ ! -d .venv ]; then python3 -m venv .venv; fi
source .venv/bin/activate
pip install -q z3-solver psutil semgrep 2>/dev/null || true

python3 -m scsp verify-self

echo "[sonar-strict] Phase 1: corpora"
python3 scripts/benchmark/generate_language_fixtures.py
python3 scripts/benchmark/generate_universal_fixtures.py 2>/dev/null || true

echo "[sonar-strict] Phase 2: Military + World-Beat G0-G16"
for g in g0 g1 g2 g3 g4 g5 g6 g7 g8 g9 g10 g11 g12 g13 g14 g15 g16; do
  python3 -m scsp gate "$g"
done

echo "[sonar-strict] Phase 3: Universal + Sonar parity G17-G40"
python3 -m scsp gate sonar-parity

echo "[sonar-strict] Phase 4: Sonar head-to-head + validation"
python3 scripts/benchmark/head_to_head_sonar.py --tiers A,H
python3 scripts/benchmark/validate_reports.py "$ROOT/proof/universal" --strict --require-honest-gaps
python3 scripts/benchmark/check_language_matrix.py --strict
python3 scripts/benchmark/determinism_vps.py --runs 3 --write-vps-hash
python3 scripts/benchmark/report_dashboard.py --proof "$ROOT/proof/universal"
python3 scripts/benchmark/build_universal_proof.py

SSH_PROOF="sonar-strict-$(date -u +%Y%m%dT%H%M%SZ)-$(hostname)"
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
summary["vps"] = {"host": "YOUR_HOST", "sonar_parity": True}
if summary["skip"] > 0 or summary["fail"] > 0:
    summary["status"] = "FAIL"
else:
    summary["status"] = "PASS"
out = root / "proof" / "universal" / "vps" / "SONAR_PARITY_SUMMARY.json"
out.write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
if summary["status"] != "PASS":
    raise SystemExit(1)
PY

echo "[sonar-strict] DONE"
cat proof/universal/VPS_ATTESTATION.json
