# Rice's Theorem and Scanner Bounds

## Theorem 1 — Undecidability (Rice)

No algorithm can decide arbitrary non-trivial semantic properties of programs
(e.g. "is malware", "will leak secrets", "contains backdoor") for all inputs.

**URNS consequence:** We never claim 100% coverage. Reports include `OUT_OF_SCOPE`
for undecidable cases and `coverage_pct` per OWASP ASVS chapter.

## Theorem 2 — Sound Taint (P0)

If taint analysis is sound (over-approximate), then **P0 PROVEN** findings imply
a source can reach a sink on **some** execution path. Witness in SARIF `evidence_path`.

## Theorem 3 — SMT Bounded Proof

Z3 proves/disproves **linear** env-guard constraints. Non-linear → `UNKNOWN`, not P0.

## Finding Tiers

| Tier | Meaning | Gate pass? |
|------|---------|------------|
| P0 PROVEN | Taint + Z3 witness | Yes |
| P1 VERIFIED | Pattern + sink, no LLM | Yes |
| P2 SUSPECTED | LLM or heuristic | No |
| P3 INTEL | IOC / campaign / git | No |
| OUT_OF_SCOPE | Undecidable / unsupported | N/A |
