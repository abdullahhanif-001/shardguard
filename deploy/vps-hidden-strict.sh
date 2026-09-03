#!/usr/bin/env bash
# Hidden military strict — G41-G48, fail-closed VPS proof
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export SCSP_ON_VPS=1
export SCSP_STRICT=1
export SCSP_HIDDEN_MILITARY=1
export SCSP_VPS_HOST="${SCSP_VPS_HOST:-YOUR_HOST}"
export SCSP_MAX_PARALLEL=3
unset SCSP_G32_SMOKE SCSP_SKIP_VERIFY SCSP_SKIP_VPS_ATTESTATION 2>/dev/null || true

LOG="$ROOT/proof/universal/vps/HIDDEN_STRICT.log"
mkdir -p "$ROOT/proof/universal/vps" "$ROOT/proof/universal/hidden" "$ROOT/attestations"

if [ -z "${SCSP_STRICT_DETACHED:-}" ]; then
  export SCSP_STRICT_DETACHED=1
  setsid bash "$0" "$@" </dev/null >>"$LOG" 2>&1 &
  echo "[hidden-strict] detached PID=$! log=$LOG"
  exit 0
fi

exec >>"$LOG" 2>&1
echo "[hidden-strict] start $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ ! -d .venv ]; then python3 -m venv .venv; fi
source .venv/bin/activate
pip install -q z3-solver psutil semgrep 2>/dev/null || true

python3 -m scsp verify-self

echo "[hidden-strict] Phase 1: hidden corpus + B16-B30"
python3 scripts/benchmark/generate_hidden_fixtures.py
python3 scripts/benchmark/generate_adv_bypass_v2.py

echo "[hidden-strict] Phase 2: baseline G0-G40 (sonar parity)"
python3 -m scsp gate sonar-parity

echo "[hidden-strict] Phase 3: hidden military G41-G48"
python3 -m scsp gate hidden-military

echo "[hidden-strict] Phase 4: head-to-head + dashboard + validation"
python3 scripts/benchmark/head_to_head_hidden.py
python3 scripts/benchmark/hidden_report_dashboard.py
python3 scripts/benchmark/validate_reports.py "$ROOT/proof/universal" --strict --require-honest-gaps

SSH_PROOF="hidden-strict-$(date -u +%Y%m%dT%H%M%SZ)-$(hostname)"
python3 -c "
from scsp.universal_gates import write_vps_attestation_hidden
write_vps_attestation_hidden('${SSH_PROOF}')
"

python3 - <<'PY'
import json
from pathlib import Path
root = Path(".")
summary = {"gates": {}, "pass": 0, "fail": 0, "skip": 0, "strict_mode": True, "hidden_military": True}
for g in range(41, 49):
    for p in (root / "attestations").glob(f"G{g}_*.json"):
        d = json.loads(p.read_text())
        summary["gates"][d.get("gate", p.stem)] = d.get("status")
        st = d.get("status")
        if st == "PASS": summary["pass"] += 1
        elif st == "SKIP": summary["skip"] += 1
        else: summary["fail"] += 1
hidden = root / "proof" / "universal" / "hidden" / "HIDDEN_MILITARY_SUMMARY.json"
if hidden.is_file():
    summary["hidden_summary"] = json.loads(hidden.read_text())
summary["status"] = "PASS" if summary["skip"] == 0 and summary["fail"] == 0 else "FAIL"
out = root / "proof" / "universal" / "vps" / "HIDDEN_STRICT_SUMMARY.json"
out.write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
if summary["status"] != "PASS":
    raise SystemExit(1)
PY

echo "[hidden-strict] PASS $(date -u +%Y-%m-%dT%H:%M:%SZ)"
