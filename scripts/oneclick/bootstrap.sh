#!/usr/bin/env bash
# SCSP one-click bootstrap — installs engines and pins integrity hash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "[scsp] bootstrap starting in $ROOT"

mkdir -p .scsp vendor attestations benchmarks

# Rust / Nyx (optional but recommended on Linux VPS)
if command -v cargo >/dev/null 2>&1; then
  echo "[scsp] installing nyx-scanner via cargo..."
  cargo install nyx-scanner --locked 2>/dev/null || echo "[scsp] warn: nyx-scanner install failed — using scsp-builtin"
else
  echo "[scsp] cargo not found — using scsp-builtin engine"
fi

# Foxguard reference (rules only, not full build)
if [ ! -d vendor/foxguard ]; then
  echo "[scsp] vendoring foxguard rule reference..."
  git clone --depth 1 https://github.com/0sec-labs/foxguard vendor/foxguard 2>/dev/null || \
    echo "[scsp] warn: foxguard clone failed (offline?)"
fi

# Python venv + scsp package
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v py >/dev/null 2>&1; then
  PY=py
else
  PY=python
fi

if [ ! -d .venv ]; then
  echo "[scsp] creating venv..."
  $PY -m venv .venv || {
    apt-get update -qq && apt-get install -y -qq python3-venv python3-pip 2>/dev/null || true
    $PY -m venv .venv
  }
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[scsp] installing scsp python package..."
pip install -e "$ROOT" -q

# Executable scripts
chmod +x scripts/gates/*.sh scripts/oneclick/*.sh deploy/*.sh 2>/dev/null || true

# Generate fixtures if missing
if [ ! -d fixtures/MOCK_/M01_shard_three_modules ]; then
  echo "[scsp] generating fixtures..."
  python scripts/generate_fixtures.py
fi

# Pin engine + fixture manifest
python -m scsp verify-self --pin
python -m scsp verify-fixtures --generate

echo "[scsp] bootstrap complete"
python -m scsp verify-self
echo "[scsp] run gates: source .venv/bin/activate && python -m scsp gate all"
