#!/usr/bin/env bash
# Heavy military + Google-grade benchmark on VPS (4 vCPU / 8GB RAM)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export SCSP_ON_VPS=1
export SCSP_VPS_HOST="${SCSP_VPS_HOST:-YOUR_HOST}"
# 4 vCPU: cap parallel jobs to avoid OOM on 8GB
export SCSP_MAX_PARALLEL="${SCSP_MAX_PARALLEL:-3}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-2}"

NPROC=$(nproc 2>/dev/null || echo 4)
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 8192)
LOG="$ROOT/proof/universal/vps/HEAVY_BENCHMARK.log"
mkdir -p "$ROOT/proof/universal/vps" "$ROOT/attestations"

exec > >(tee -a "$LOG") 2>&1
echo "=============================================="
echo "[heavy] SCSP/URNS VPS benchmark start $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[heavy] host=$(hostname) nproc=$NPROC mem_mb=$MEM_MB"
echo "=============================================="

# Python venv
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q z3-solver 2>/dev/null || true

python3 -m scsp verify-self

echo "[heavy] --- Phase 1: Military gates G0-G7 ---"
for g in g0 g1 g2 g3 g4 g5 g6 g7; do
  python3 -m scsp gate "$g"
done

echo "[heavy] --- Phase 2: World-Beat G8-G16 ---"
for g in g8 g9 g10 g11 g12 g13 g14 g15 g16; do
  python3 -m scsp gate "$g"
done

echo "[heavy] --- Phase 3: Universal corpus + G17-G32 ---"
python3 scripts/benchmark/generate_universal_fixtures.py
python3 -m scsp gate universal

echo "[heavy] --- Phase 4: Head-to-head + determinism ---"
python3 scripts/benchmark/head_to_head.py A H
python3 scripts/benchmark/determinism_vps.py
python3 scripts/benchmark/build_universal_proof.py

echo "[heavy] --- Phase 5: G32 GitHub scan (VPS network) ---"
python3 -m scsp gate g32

SSH_PROOF=$(date -u +%Y%m%dT%H%M%SZ)-$(hostname)
python3 -c "
from scsp.universal_gates import write_vps_attestation
write_vps_attestation('${SSH_PROOF}')
"

# Heavy scan sample (MOCK corpus subset — memory safe)
SAMPLE=$(ls -d fixtures/MOCK_/*/ 2>/dev/null | head -5 | tr '\n' ' ')
if [ -n "$SAMPLE" ]; then
  for d in $SAMPLE; do
    python3 -m scsp scan "$d" --depth universal --skip-verify --format text 2>/dev/null | tail -3 || true
  done
fi

# Summary JSON
python3 - <<'PY'
import json
from pathlib import Path
root = Path(".")
atts = sorted((root / "attestations").glob("G*.json"))
summary = {"gates": {}, "pass": 0, "fail": 0, "skip": 0}
for p in atts:
    d = json.loads(p.read_text())
    name = p.stem
    st = d.get("status", "UNKNOWN")
    summary["gates"][name] = st
    if st == "PASS":
        summary["pass"] += 1
    elif st == "SKIP":
        summary["skip"] += 1
    else:
        summary["fail"] += 1
summary["vps"] = {"host": "YOUR_HOST", "nproc": 4, "ram_gb": 8}
out = root / "proof" / "universal" / "vps" / "HEAVY_BENCHMARK_SUMMARY.json"
out.write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
PY

echo "[heavy] DONE — log: $LOG"
if [ -f proof/universal/VPS_ATTESTATION.json ]; then
  cat proof/universal/VPS_ATTESTATION.json
fi
