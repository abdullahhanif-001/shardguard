"""Lane — crypto misuse (ASVS Ch.11)."""

from __future__ import annotations

import re
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

WEAK_CRYPTO = [
    (re.compile(r"\b(MD5|SHA1|DES|RC4|ECB)\b"), "weak-algorithm", "HIGH"),
    (re.compile(r"createHash\s*\(\s*['\"]md5['\"]"), "nodejs-md5", "HIGH"),
    (re.compile(r"Cipher\.getInstance\s*\(\s*['\"][^'\"]*ECB"), "java-ecb", "HIGH"),
    (re.compile(r"hardcoded.*(?:key|iv|salt)", re.I), "hardcoded-crypto", "CRITICAL"),
    (re.compile(r"['\"][0-9a-fA-F]{16}['\"].*(?:iv|IV)"), "hardcoded-iv", "HIGH"),
    (re.compile(r"createDecipher\s*\("), "nodejs-no-auth-tag", "HIGH"),
    (re.compile(r"\^=\s*0x[0-9a-fA-F]{2}"), "xor-loop-key", "MEDIUM"),
    (re.compile(r"for\s*\([^)]*\)\s*\{[^}]*\^="), "xor-loop", "MEDIUM"),
    (re.compile(r"openssl_decrypt\s*\("), "php-openssl-decrypt", "MEDIUM"),
    (re.compile(r"Crypto\.createDecipheriv"), "crypto-decipher-no-aead", "HIGH"),
]

EXT = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".go", ".rs", ".java", ".kt", ".kts",
    ".c", ".cpp", ".h", ".php", ".rb", ".cs", ".swift", ".sh", ".bash",
}


def scan_crypto(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    files = [target] if target.is_file() else [
        p for p in target.rglob("*") if p.suffix.lower() in EXT and "node_modules" not in p.parts
    ]
    for fp in files[:3000]:
        text = safe_read_text(fp)
        if not text:
            continue
        fs = str(fp.resolve())
        for i, line in enumerate(text.splitlines(), 1):
            for pat, name, sev in WEAK_CRYPTO:
                if pat.search(line):
                    findings.append(
                        LaneFinding(
                            rule_id=f"urns/crypto-{name}",
                            severity=sev,
                            message=f"Crypto misuse: {name}",
                            file=fs,
                            line=i,
                            lane="crypto",
                            tier="P1",
                            asvs_chapter="V11",
                        )
                    )
    return findings
