"""npm/pnpm pre-install hook (offline Endor-style local wrapper)."""

from __future__ import annotations

import os
import shutil
import stat
import sys
from pathlib import Path

from scsp.integrity import ROOT

HOOK_DIR = ROOT / ".scsp" / "hooks"


def _wrapper_script() -> str:
    return f"""#!/usr/bin/env bash
# SCSP preinstall hook — scan package before install
set -euo pipefail
TARGET="${{INIT_CWD:-.}}"
if [ -d "$TARGET" ] && [ -f "$TARGET/package.json" ]; then
  python -m scsp scan "$TARGET" --format text --no-nyx || {{
    echo "[scsp-hook] BLOCKED: findings in $TARGET" >&2
    exit 1
  }}
fi
exec "$@"
"""


def install_hooks() -> int:
    HOOK_DIR.mkdir(parents=True, exist_ok=True)
    npm_hook = HOOK_DIR / "npm-preinstall.sh"
    npm_hook.write_text(_wrapper_script(), encoding="utf-8")
    npm_hook.chmod(npm_hook.stat().st_mode | stat.S_IEXEC)

    readme = HOOK_DIR / "README.txt"
    readme.write_text(
        "Add to .npmrc:\n  script-shell=bash\n"
        f"Or run before install:\n  bash {npm_hook} npm install\n",
        encoding="utf-8",
    )
    print(f"installed hook at {npm_hook}")
    return 0


def uninstall_hooks() -> int:
    if HOOK_DIR.is_dir():
        shutil.rmtree(HOOK_DIR)
    print("removed scsp hooks")
    return 0
