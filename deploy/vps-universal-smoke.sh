#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export SCSP_ON_VPS=1
python3 scripts/benchmark/generate_universal_fixtures.py
python3 -m scsp gate g17
python3 -m scsp gate g25
echo "[urns] smoke OK"
