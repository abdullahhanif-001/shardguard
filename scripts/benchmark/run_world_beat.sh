#!/usr/bin/env bash
# World-Beat full proof pipeline G0-G16
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
[ -f .venv/bin/activate ] && source .venv/bin/activate

echo "[world-beat] fixtures"
python scripts/benchmark/generate_incident_fixtures.py
python scripts/benchmark/generate_world_beat_fixtures.py
python scripts/benchmark/split_holdout.py
python scripts/benchmark/fetch_oss_benign.py

echo "[world-beat] verify"
python -m scsp verify-self --pin || python -m scsp verify-self

echo "[world-beat] gates G0-G7"
python -m scsp gate g0
python -m scsp gate g1
python -m scsp gate g2
python -m scsp gate g3
python -m scsp gate g4
python -m scsp gate g5
python -m scsp gate g6
python -m scsp gate g7

echo "[world-beat] head-to-head"
python scripts/benchmark/head_to_head.py A H

echo "[world-beat] determinism"
python scripts/benchmark/determinism_test.py

echo "[world-beat] gates G8-G16"
python -m scsp gate g8
python -m scsp gate g9
python -m scsp gate g10
python -m scsp gate g11
python -m scsp gate g12
python -m scsp gate g13
python -m scsp gate g14
python -m scsp gate g15
python -m scsp gate g16

echo "[world-beat] reports"
python scripts/benchmark/statistical_report.py
python scripts/benchmark/build_world_beat_proof.py

echo "[world-beat] ALL COMPLETE"
