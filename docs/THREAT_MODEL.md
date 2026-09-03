# Threat Model — SCSP

## In Scope

| Threat | Description | Detection |
|--------|-------------|-----------|
| Multi-file fragmentation | Malice split across modules; each file clean alone | Cross-file taint + build graph |
| npm lifecycle chains | `postinstall` → hidden require chain | Lifecycle entry sources |
| String/base64 sharding | Payload reassembled at runtime | `fragmentation.yaml` patterns |
| Adversarial evasion | globalThis, Function(), vm, Proxy, workers | G2 bypass suite |

## Out of Scope

| Threat | Reason |
|--------|--------|
| Perfect intent inference | Undecidable (Rice's theorem) |
| Kernel prompt injection | See cyber expert U08 |
| 100% novel obfuscation | Attacker adaptability |

## Residual Risk

| Risk | Mitigation |
|------|------------|
| Dynamic `import(expr)` | `UNKNOWN_RISK` (not silent CLEAN) |
| Minified single-file (B14) | Documented skip; separate rule track |
| Scanner compromise | `verify-self` SHA256 pin |
| Poisoned fixtures | `MANIFEST.sha256` |
| False green in CI | Attestation JSON required |

## Security Controls

- Local-first scanning (no cloud upload)
- Registry allowlist for corpus download
- `set -euo pipefail` on all gate scripts
- SSH keys via env only (never in repo)
