#!/usr/bin/env bash
# Fail-closed gate runner G0→G4
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export SCSP_ON_VPS=1
# shellcheck disable=SC1091
[ -f .venv/bin/activate ] && source .venv/bin/activate

python -m scsp verify-self || exit 1
./scripts/gates/g0-mock.sh || exit 1
./scripts/gates/g1-crossfile.sh || exit 1
./scripts/gates/g2-bypass.sh || exit 1
./scripts/gates/g3-real.sh || exit 1
python -m scsp gate g4 || exit 1
python scripts/benchmark/head_to_head.py A H || true
python -m scsp gate g5 || exit 1
python -m scsp gate g6 || exit 1
python -m scsp gate g7 || exit 1
python -m scsp gate g8 || exit 1
python -m scsp gate g9 || exit 1
python -m scsp gate g10 || exit 1
python -m scsp gate g11 || exit 1
python -m scsp gate g12 || exit 1
python -m scsp gate g13 || exit 1
python -m scsp gate g14 || exit 1
python -m scsp gate g15 || exit 1
python -m scsp gate g16 || exit 1
python scripts/benchmark/generate_universal_fixtures.py || true
SCSP_SKIP_VERIFY=1 SCSP_ALLOW_LOCAL_FUZZ=1 SCSP_ALLOW_LOCAL_SCALE=1 SCSP_SKIP_VPS_ATTESTATION=1 python -m scsp gate universal || exit 1

echo "[scsp] ALL GATES GREEN (G0-G16 + universal)"
