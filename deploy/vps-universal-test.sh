#!/usr/bin/env bash
# Run full universal gate suite on VPS YOUR_HOST
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VPS_HOST="${SCSP_VPS_HOST:-YOUR_HOST}"
VPS_USER="${SCSP_VPS_USER:-root}"
REMOTE_DIR="${SCSP_VPS_REMOTE_DIR:-/opt/scsp}"

echo "[urns] Deploying to ${VPS_USER}@${VPS_HOST}:${REMOTE_DIR}"

if [[ "$(hostname -I 2>/dev/null || echo '')" == *"${VPS_HOST}"* ]] || [[ "${SCSP_ON_VPS:-}" == "1" ]]; then
  export SCSP_ON_VPS=1
  export SCSP_ALLOW_LOCAL_FUZZ=1
  export SCSP_ALLOW_LOCAL_SCALE=1
  python3 scripts/benchmark/generate_universal_fixtures.py
  python3 -m scsp verify-self || true
  python3 -m scsp gate universal
  python3 scripts/benchmark/build_universal_proof.py
  SSH_PROOF=$(date -u +%Y%m%dT%H%M%SZ)
  python3 -c "
from scsp.universal_gates import write_vps_attestation
write_vps_attestation('${SSH_PROOF}')
"
  echo "[urns] VPS local run complete — VPS_ATTESTATION.json written"
  exit 0
fi

# Remote deploy via rsync + ssh
if command -v rsync &>/dev/null && command -v ssh &>/dev/null; then
  rsync -az --exclude node_modules --exclude .git "$ROOT/" "${VPS_USER}@${VPS_HOST}:${REMOTE_DIR}/"
  ssh "${VPS_USER}@${VPS_HOST}" "cd ${REMOTE_DIR} && SCSP_ON_VPS=1 SCSP_ALLOW_LOCAL_FUZZ=1 SCSP_ALLOW_LOCAL_SCALE=1 bash deploy/vps-universal-test.sh"
  rsync -az "${VPS_USER}@${VPS_HOST}:${REMOTE_DIR}/proof/universal/" "$ROOT/proof/universal/"
  echo "[urns] Remote VPS test complete — attestations pulled"
else
  echo "[urns] rsync/ssh not available — set SCSP_ON_VPS=1 and run locally on VPS"
  exit 1
fi
