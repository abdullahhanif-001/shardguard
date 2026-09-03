#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
bash scripts/oneclick/bootstrap.sh
echo "[install] ready at $ROOT"
