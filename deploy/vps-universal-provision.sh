#!/usr/bin/env bash
# One-time VPS provision for URNS strict — YOUR_HOST
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq \
  python3 python3-pip python3-venv git clang llvm curl ca-certificates gnupg

# Node.js 20 LTS (npm for G10 baseline)
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y -qq nodejs
fi

ROOT="${SCSP_ROOT:-/opt/scsp}"
mkdir -p "$ROOT"
cd "$ROOT"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q z3-solver psutil semgrep

# Hard-fail tool verification
for cmd in python3 git clang node npm; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "[provision] FATAL: missing required tool: $cmd"
    exit 1
  fi
done

if ! python3 -c "import z3, psutil" 2>/dev/null; then
  echo "[provision] FATAL: z3-solver or psutil not importable"
  exit 1
fi

if ! semgrep --version &>/dev/null; then
  echo "[provision] FATAL: semgrep not installed"
  exit 1
fi

# verify-self must pass when project is deployed
if [ -f "$ROOT/scsp/__init__.py" ] || [ -f "$ROOT/pyproject.toml" ]; then
  python3 -m scsp verify-self
fi

echo "[provision] VPS provision complete on $(hostname)"
echo "[provision] python=$(python3 --version) node=$(node --version) semgrep=$(semgrep --version 2>&1 | head -1)"
