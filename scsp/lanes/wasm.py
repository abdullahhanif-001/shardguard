"""Lane — WASM/binary module analysis (B11 fix, L19)."""

from __future__ import annotations

import re
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

WASM_PATTERNS = [
    (re.compile(r"WebAssembly\.instantiate"), "wasm-instantiate", "HIGH"),
    (re.compile(r"WebAssembly\.compile"), "wasm-compile", "HIGH"),
    (re.compile(r"new\s+WebAssembly\.Module"), "wasm-module", "HIGH"),
    (re.compile(r"\.wasm['\"]"), "wasm-file-ref", "MEDIUM"),
]


def scan_wasm(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    exts = {".js", ".mjs", ".cjs", ".ts", ".wasm"}
    files = [target] if target.is_file() else [
        p for p in target.rglob("*") if p.suffix.lower() in exts and "node_modules" not in p.parts
    ]
    for fp in files[:1000]:
        if fp.suffix.lower() == ".wasm":
            findings.append(
                LaneFinding(
                    rule_id="urns/wasm-binary",
                    severity="MEDIUM",
                    message="WebAssembly binary present",
                    file=str(fp.resolve()),
                    lane="wasm",
                    tier="P1",
                    status="DETECT",
                    mitre="T1027",
                )
            )
            continue
        text = safe_read_text(fp)
        if not text:
            continue
        fs = str(fp.resolve())
        has_shard = bool(re.search(r"Buffer\.from|base64|0x[0-9a-fA-F]", text))
        for i, line in enumerate(text.splitlines(), 1):
            for pat, name, sev in WASM_PATTERNS:
                if pat.search(line):
                    tier = "P1" if has_shard else "P2"
                    findings.append(
                        LaneFinding(
                            rule_id=f"urns/{name}",
                            severity=sev,
                            message=f"WebAssembly load pattern: {name}",
                            file=fs,
                            line=i,
                            lane="wasm",
                            tier=tier,
                            status="DETECT",
                            mitre="T1027",
                        )
                    )
    return findings
