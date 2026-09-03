#!/usr/bin/env bash
set -euo pipefail
set -x
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
[ -f .venv/bin/activate ] && source .venv/bin/activate

python -m scsp verify-self
python -m scsp scan fixtures/MOCK_/M01_shard_three_modules --format json | head -c 2000
echo ""
python -m scsp scan fixtures/MOCK_/M04_benign_crypto --format json | head -c 500
echo ""
echo "[vps-smoke] OK"
