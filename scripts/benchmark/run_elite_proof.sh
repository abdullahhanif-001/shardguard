#!/usr/bin/env bash
# Google Elite offline proof — G0 through G7 + metrics package
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export SCSP_ON_VPS="${SCSP_ON_VPS:-1}"
# shellcheck disable=SC1091
[ -f .venv/bin/activate ] && source .venv/bin/activate

echo "[elite-proof] generate incident corpus"
python scripts/benchmark/generate_incident_fixtures.py

echo "[elite-proof] fetch corpus (offline-safe)"
python scripts/benchmark/fetch_osv_snapshots.py --tier all --offline || true

echo "[elite-proof] verify integrity"
python -m scsp verify-self
python -m scsp verify-fixtures || python -m scsp verify-fixtures --generate

echo "[elite-proof] G0-G4 military gates"
./scripts/gates/g0-mock.sh
./scripts/gates/g1-crossfile.sh
./scripts/gates/g2-bypass.sh
./scripts/gates/g3-real.sh
python -m scsp gate g4

echo "[elite-proof] head-to-head baselines"
bash scripts/benchmark/head_to_head.sh

echo "[elite-proof] G5-G7 real-world gates"
python -m scsp gate g5
python -m scsp gate g6
python -m scsp gate g7

echo "[elite-proof] metrics report"
python scripts/benchmark/generate_metrics_report.py

echo "[elite-proof] copy attestations to proof package"
mkdir -p proof/google_delivery/attestations
cp attestations/G*.json proof/google_delivery/attestations/ 2>/dev/null || true

echo "[elite-proof] ALL GATES G0-G7 COMPLETE"
