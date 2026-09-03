#!/usr/bin/env bash
# Shared helpers for SCSP shell scripts
if command -v py >/dev/null 2>&1; then
  export SCSP_PY=py
elif command -v python3 >/dev/null 2>&1; then
  export SCSP_PY=python3
else
  export SCSP_PY=python
fi

scsp() {
  "$SCSP_PY" -m scsp "$@"
}
