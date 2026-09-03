# Evaluation Results

## Environment

- Platform: Windows 10 / Linux VPS (Ubuntu 6.8)
- Engine: scsp-builtin 0.1.0 (+ optional nyx-scanner)
- Date: 2026-09-01

## Gate Results

| Gate | Status | Key Metrics |
|------|--------|-------------|
| G0_MOCK | PASS | recall 1.0, precision 1.0, n=50 |
| G1_CROSSFILE | PASS | all CRITICAL have ≥2 file evidence |
| G2_BYPASS | PASS | 15/15 cases, 0 silent bypass |
| G3_REAL | PASS | recall 1.0, n=23, Wilson CI [0.86, 1.0] |
| G4_VPS | PASS | SSH smoke YOUR_HOST |

Full attestations in `attestations/`.

## Baseline Comparison (MOCK_ fragmented cases)

| Tool | Multi-file fragmented detection |
|------|--------------------------------|
| npm audit | MISS (metadata only) |
| Semgrep per-file | MISS most |
| scsp-builtin | HIT 50/50 MOCK_ + 15/15 bypass |

## Reproduce

```bash
scsp gate all
cat benchmarks/RESULTS.json
```

## Limitations

- G3 corpus uses advisory samples + curated REAL_ packages (not full MalnpmDB 7000+)
- For full MalnpmDB: place extracted packages under `fixtures/REAL_/malicious/` and re-run G3
- Nyx integration optional; deep profile available when `cargo install nyx-scanner` succeeds
