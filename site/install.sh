#!/usr/bin/env bash
# ShardGuard bootstrap — installs pipx (if needed) then shardguard
set -euo pipefail
if ! command -v pipx >/dev/null 2>&1; then
  python3 -m pip install --user pipx
  python3 -m pipx ensurepath || true
  export PATH="${HOME}/.local/bin:${PATH}"
fi
pipx install --force shardguard || pipx install --force "git+https://github.com/abdullahhanif-001/shardguard.git"
echo "OK — run: shardguard scan ."
