# Bypass Matrix (G2 Red Team)

| ID | Technique | Expected | Notes |
|----|-----------|----------|-------|
| B01 | globalThis shard | DETECT / UNKNOWN_RISK | Cross-module global state |
| B02 | Function('return '+part)() | DETECT | Constructor from required module |
| B03 | dynamic import(expr) | UNKNOWN_RISK | Cannot resolve statically |
| B04 | worker_threads message | DETECT | Cross-file worker bridge |
| B05 | prototype pollution | DETECT | `__proto__` chain |
| B06 | vm.runInNewContext | DETECT | VM bridge |
| B07 | base64 4-file shard | DETECT | Buffer reassembly |
| B08 | postinstall dynamic require | DETECT | Lifecycle + dynamic path |
| B09 | SCC depth recursion | DETECT / SCC_INCOMPLETE | Mutual require |
| B10 | []['constructor'] eval | DETECT | Opaque constructor |
| B11 | WebAssembly shard | UNKNOWN_RISK | WASM instantiate |
| B12 | Proxy hidden sink | DETECT | Proxy wrapper |
| B13 | benign barrel re-export | CLEAN | Must not FP |
| B14 | minified single-file | DETECT | B14 fix — deobf re-lift (JS + 11 langs) |
| B15 | Date.now time bomb | DETECT / SUSPICIOUS | Time trigger |

## Hidden Military Bypasses (B16–B30)

| ID | Technique | Lang | Expected |
|----|-----------|------|----------|
| B16 | unicode zero-width | python | DETECT |
| B17 | unicode homoglyph eval | php | DETECT |
| B18 | unicode homoglyph | go | DETECT |
| B19 | base64 encoding chain | ruby | DETECT |
| B20 | base64 encoding chain | java | DETECT |
| B21 | minified one-liner | kotlin | DETECT |
| B22 | minified one-liner | csharp | DETECT |
| B23 | homoglyph spawn | rust | DETECT |
| B24 | Process() sink | swift | DETECT |
| B25 | whitespace stego | shell | DETECT |
| B26 | whitespace stego + b64 | javascript | DETECT |
| B27 | entropy blob + exec | python | DETECT |
| B28 | weak crypto + system | php | DETECT |
| B29 | createDecipher + exec | javascript | DETECT |
| B30 | polyglot C/PHP comment | c | DETECT |

Run: `scsp gate g47` or `scsp gate hidden-military`
