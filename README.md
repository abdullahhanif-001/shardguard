# ShardGuard

Open-source scanner for **multi-file obfuscation** and **hidden supply-chain payloads** across twelve languages.

ShardGuard (SCSP engine) unfolds encoding chains, flags invisible unicode tricks, and follows cross-file taint to execution sinks — then writes an offline triage HTML report you can print, screenshot, or download as ZIP. No account. No hosted upload of your source.

## Install

```bash
pipx install shardguard
```

Or:

```bash
pip install shardguard
```

From this repository:

```bash
pipx install .
# or
pip install -e .
```

## Quick start

```bash
shardguard scan .
shardguard scan ./path/to/project --open
shardguard scan https://github.com/org/repo --depth universal --skip-verify
```

`--open` builds a report under `shardguard-report/` and opens `SECURITY_REPORT.html` (filters, keyboard `j`/`k`, Print/PDF, JSON/SARIF/ZIP).

## What it looks for

- Unicode / zero-width / homoglyph obfuscation near sinks
- Encoding chains (base64 / hex / zlib-style unfold, depth ≤ 3)
- Minified one-liners after deobfuscation re-lift
- Cross-file fragmentation into lifecycle / exec sinks
- Weak or hidden crypto patterns (selected rules)

## Honest limits

Static analysis cannot prove the absence of all bugs. VM-based JavaScript obfuscators without dynamic execution, fully dynamic `import(expr)`, and authorization logic flaws are out of scope or undecidable. See [docs/RICE_BOUNDS.md](docs/RICE_BOUNDS.md).

## Gates & benchmarks

Frozen fixtures under `benchmarks/` and `adversarial/bypass/` support gate attestations (`shardguard gate …`). Run gates on your own machine or CI — do not rely on third-party hosts.

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Links

- Repository: https://github.com/abdullahhanif-001/shardguard
- Docs site: https://abdullahhanif-001.github.io/shardguard/

## Author

Abdullah
