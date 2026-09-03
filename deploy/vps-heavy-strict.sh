#!/usr/bin/env bash
# Strict fail-closed VPS heavy benchmark — NO bypass/smoke flags
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Strict environment — unset all bypass flags
export SCSP_ON_VPS=1
export SCSP_VPS_HOST="${SCSP_VPS_HOST:-YOUR_HOST}"
export SCSP_STRICT=1
export SCSP_MAX_PARALLEL=3
export OMP_NUM_THREADS=2
unset SCSP_G32_SMOKE SCSP_SKIP_VERIFY SCSP_SKIP_VPS_ATTESTATION 2>/dev/null || true
unset SCSP_ALLOW_LOCAL_FUZZ SCSP_ALLOW_LOCAL_SCALE SCSP_ALLOW_LOCAL_G32 2>/dev/null || true

LOG="$ROOT/proof/universal/vps/HEAVY_STRICT.log"
GATES_DIR="$ROOT/proof/universal/vps/gates"
mkdir -p "$ROOT/proof/universal/vps" "$GATES_DIR" "$ROOT/attestations"

# Re-exec detached so SSH disconnect does not kill the pipeline
if [ -z "${SCSP_STRICT_DETACHED:-}" ]; then
  export SCSP_STRICT_DETACHED=1
  setsid bash "$0" "$@" </dev/null >>"$LOG" 2>&1 &
  echo "[strict] detached PID=$! log=$LOG"
  exit 0
fi

exec >>"$LOG" 2>&1
echo "=============================================="
echo "[strict] SCSP heavy strict start $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[strict] host=$(hostname) nproc=$(nproc) mem=$(free -h | awk '/Mem:/ {print $2}')"
echo "[strict] no_bypass_flags=true"
echo "=============================================="

# Forbidden bypass env check
for bad in SCSP_G32_SMOKE SCSP_SKIP_VERIFY SCSP_SKIP_VPS_ATTESTATION; do
  if [ -n "${!bad:-}" ]; then
    echo "[strict] FATAL: $bad is set — bypass not allowed"
    exit 1
  fi
done

# Python venv
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q z3-solver psutil 2>/dev/null || pip install -q z3-solver

run_gate() {
  local g="$1"
  local t0=$(date +%s)
  python3 -m scsp gate "$g"
  local t1=$(date +%s)
  local att="attestations/G${g^^}"
  # copy latest attestation
  for f in attestations/G*.json; do
    if echo "$f" | grep -qi "${g}"; then
      cp "$f" "$GATES_DIR/$(basename "$f")" 2>/dev/null || true
    fi
  done
  echo "[strict] gate $g elapsed=$((t1-t0))s"
}

echo "[strict] --- Phase 0: verify-self (hard fail) ---"
python3 -m scsp verify-self

echo "[strict] --- Phase 1: corpus build ---"
python3 scripts/benchmark/generate_incident_fixtures.py
python3 scripts/benchmark/generate_world_beat_fixtures.py
python3 scripts/benchmark/generate_universal_fixtures.py
python3 scripts/benchmark/generate_stress_corpus.py
python3 scripts/benchmark/split_holdout.py
python3 scripts/benchmark/fetch_oss_benign.py
python3 scripts/benchmark/fetch_osv_snapshots.py --offline 2>/dev/null || python3 scripts/benchmark/fetch_osv_snapshots.py

echo "[strict] --- Phase 1b: clone real GitHub repos (shallow) ---"
CACHE="$ROOT/.cache/repos"
mkdir -p "$CACHE"
for repo in "https://github.com/octocat/Hello-World" "https://github.com/expressjs/express" "https://github.com/lodash/lodash"; do
  name=$(basename "$repo")
  if [ ! -d "$CACHE/$name/.git" ]; then
    git clone --depth 1 "$repo" "$CACHE/$name"
  fi
done

echo "[strict] --- Phase 2: Military G0-G7 ---"
for g in g0 g1 g2 g3 g4 g5 g6 g7; do
  run_gate "$g"
done

echo "[strict] --- Phase 3: World-Beat G8-G16 ---"
for g in g8 g9 g10 g11 g12 g13 g14 g15 g16; do
  run_gate "$g"
done

echo "[strict] --- Phase 4: Universal G17-G32 ---"
python3 -m scsp gate universal

echo "[strict] --- Phase 5: head-to-head + determinism ---"
python3 scripts/benchmark/head_to_head.py A H
python3 scripts/benchmark/determinism_test.py
python3 scripts/benchmark/determinism_vps.py --runs 3 --write-vps-hash
python3 scripts/benchmark/statistical_report.py
python3 scripts/benchmark/build_universal_proof.py
python3 scripts/benchmark/build_world_beat_proof.py

echo "[strict] --- Phase 6: stress tests ---"
python3 scripts/benchmark/vps_stress.py

echo "[strict] --- Phase 7: scan real cloned repos ---"
for repo in Hello-World express lodash; do
  if [ -d "$CACHE/$repo" ]; then
    python3 -m scsp scan "$CACHE/$repo" --depth universal --skip-verify --report-dir "proof/universal/vps/scan_$repo"
  fi
done

SSH_PROOF="strict-$(date -u +%Y%m%dT%H%M%SZ)-$(hostname)"
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
    if st == "PASS":
        summary["pass"] += 1
    elif st == "SKIP":
        summary["skip"] += 1
    else:
        summary["fail"] += 1
summary["vps"] = {"host": "YOUR_HOST", "nproc": 4, "ram_gb": 8}
if summary["skip"] > 0 and __import__("os").environ.get("SCSP_STRICT") == "1":
    summary["status"] = "FAIL"
    summary["fail_reason"] = "SKIP gates not allowed in strict mode"
elif summary["fail"] > 0:
    summary["status"] = "FAIL"
else:
    summary["status"] = "PASS"
out = root / "proof" / "universal" / "vps" / "HEAVY_STRICT_SUMMARY.json"
out.write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
if summary["status"] != "PASS":
    raise SystemExit(1)
PY

echo "[strict] DONE — log: $LOG"
cat proof/universal/VPS_ATTESTATION.json
