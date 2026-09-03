# Gate Attestation Protocol

## Rule

A gate is **GREEN** only when `attestations/<GATE>.json` exists with `"status": "PASS"`.  
Any **RED** gate blocks ship. No bypass of gate order.

## Reproduce (full pipeline)

```bash
bash scripts/oneclick/bootstrap.sh
scsp verify-self
scsp verify-fixtures
scsp corpus download
scsp gate all
```

Expected exit code: **0**

## Gate Definitions

### G0_MOCK
- Corpus: `fixtures/MOCK_/` (50 packages)
- Pass: recall ≥ 0.98, precision ≥ 0.95
- Every DETECT with `require_cross_file` must have `cross_file: true` and ≥2 files in `evidence_path`

### G1_CROSSFILE
- Requires G0 PASS
- Validates evidence integrity on all CRITICAL findings

### G2_BYPASS
- Corpus: `adversarial/bypass/` (B01–B15)
- Zero silent CLEAN on B01–B12
- B13 must be CLEAN; B14 must be DETECT (minified/deobf re-lift)

### G3_REAL
- Corpus: `fixtures/REAL_/malicious/`
- Pass: recall ≥ 0.85, Wilson 95% CI lower ≥ 0.80
- Minimum 10 packages

### G4_HOST
- Requires G0–G3 PASS
- Optional remote smoke when `SCSP_VPS_HOST` is set to your own host
- Local smoke: M01 CRITICAL, M04 zero CRITICAL

## Attestation Schema

```json
{
  "gate": "G0_MOCK",
  "status": "PASS",
  "timestamp": "ISO8601",
  "engine_sha256": "...",
  "failures": []
}
```

## Fail-Closed

- `scsp verify-self` failure → all gates FAIL
- Engine hash mismatch → do not scan
- Missing prior gate attestation → subsequent gates FAIL

## Maintainer gate runners (optional)

Heavy gate suites can be run on any Linux host you control:

```bash
export SCSP_STRICT=1
export SCSP_ON_VPS=1
export SCSP_VPS_HOST=YOUR_HOST
bash deploy/vps-heavy-strict.sh
```

Replace `YOUR_HOST` with your own machine hostname for attestation metadata. Do not publish private infrastructure addresses.

Proof artifacts (when generated): `proof/universal/VPS_ATTESTATION.json` with `strict_mode`, `no_bypass_flags`, and corpus hashes.

## Language coverage gates (G33–G40)

| Gate | Validates | Pass |
|------|-----------|------|
| G33_LANG_MATRIX | ≥12 languages, tier1 complete | registered plugins |
| G34_CROSSLANG_v2 | Python/Java/Go cross-file | recall ≥85% |
| G35_REPORT_SCHEMA | `validate_reports.py --strict` | 100% pass |
| G36_SONAR_HEADTOHEAD | `SONAR_LEADERBOARD.json` | ShardGuard recall ≥ pattern oracle, zero SKIP |
| G37_OWASP_COVERAGE | OWASP YAML rule packs | ≥8 categories, ≥3 langs |
| G38_PER_LANG_RECALL | `benchmarks/languages/*` | recall ≥90%, FPR ≤2% |
| G39_DETERMINISM_NORM | Normalized hash | 3-run stable, cross-host match when both hashes set |
| G40_PROOF_BUNDLE_v2 | G33–G39 + SHA256 manifest | zero SKIP |

```bash
SCSP_STRICT=1 bash deploy/vps-sonar-parity-strict.sh
# or
shardguard gate sonar-parity
```

## Hidden Military Gates (G41–G48)

| Gate | Validates | Pass (strict) |
|------|-----------|---------------|
| G41_UNIVERSAL_UNICODE | `benchmarks/hidden/*/unicode-*` | recall ≥92%, FPR ≤2% |
| G42_ENCODING_CHAINS | encoding unfold corpus | recall ≥90%, zero silent CLEAN on mal |
| G43_DEOBF_RELIFT | Per-lang minified cases | ≥11/12 langs (shell exempt minify) |
| G44_READABILITY | Hidden malicious corpus | ≥85% flagged via universal scan |
| G45_HIDDEN_CRYPTO | Weak crypto + XOR loops | ≥1 detect per lang with crypto sample |
| G46_STEGO | Whitespace/comment stego | recall ≥88% |
| G47_ADV_BYPASS | B16–B30 adversarial | zero silent miss |
| G48_HIDDEN_PROOF | G41–G47 + SHA256 bundle | gates_skip=0, strict_mode=true |

Run: `SCSP_STRICT=1 bash deploy/vps-hidden-strict.sh` or `scsp gate hidden-military`

Proof: `proof/universal/hidden/HIDDEN_MILITARY_SUMMARY.json`, `VPS_ATTESTATION.json` fields `hidden_gates_pass`, `hidden_corpus_sha256`
