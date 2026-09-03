#!/usr/bin/env bash
# Head-to-head v2 wrapper
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
python scripts/benchmark/head_to_head.py "$@"
