#!/usr/bin/env python3
"""Build proof/universal/ bundle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROOF = ROOT / "proof" / "universal"


def sha256_dir(base: Path) -> dict[str, str]:
    out = {}
    for p in sorted(base.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(base))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def main() -> None:
    PROOF.mkdir(parents=True, exist_ok=True)
    hashes = sha256_dir(PROOF)
    (PROOF / "EVIDENCE_BUNDLE.sha256").write_text(
        "\n".join(f"{h}  {k}" for k, h in sorted(hashes.items())),
        encoding="utf-8",
    )
    (PROOF / "REPRODUCE_INDEPENDENT.md").write_text(
        """# Reproduce Universal Proof

```bash
python scripts/benchmark/generate_universal_fixtures.py
py -m scsp gate universal
python scripts/benchmark/build_universal_proof.py
```

## VPS (required for G28/G30/G32 full attestation)

```bash
export SCSP_VPS_HOST=YOUR_HOST
./deploy/vps-universal-test.sh
```

See REPRODUCE_VPS.md
""",
        encoding="utf-8",
    )
    (PROOF / "REPRODUCE_VPS.md").write_text(
        """# VPS Reproduce — YOUR_HOST

1. `export SCSP_VPS_HOST=YOUR_HOST SCSP_VPS_USER=root`
2. `./deploy/vps-universal-provision.sh` (one-time)
3. `./deploy/vps-universal-test.sh`
4. Verify `proof/universal/VPS_ATTESTATION.json` has `"host": "YOUR_HOST"`

Gates G28, G30, G32 require `SCSP_ON_VPS=1` on Linux VPS.
""",
        encoding="utf-8",
    )
    print(f"Proof bundle at {PROOF}")


if __name__ == "__main__":
    main()
