"""Hidden logic runner v2 — full military pipeline."""

from __future__ import annotations

from pathlib import Path

from scsp.hidden.concolic_env import scan_attestation, scan_concolic_env, scan_entropy, scan_ide_hooks
from scsp.hidden.deobfuscate_lang import deobfuscate_all_langs
from scsp.hidden.encoding_chains import scan_encoding_chains
from scsp.hidden.readability import scan_readability
from scsp.hidden.stego import scan_stego
from scsp.lanes.crypto import scan_crypto
from scsp.lanes.types import LaneFinding
from scsp.unicode_scan import scan_unicode_directory


def scan_hidden(target: Path) -> list[LaneFinding]:
    """Pipeline: unicode → readability → encoding → deobf → entropy → stego → crypto."""
    findings: list[LaneFinding] = []

    for uf in scan_unicode_directory(target):
        findings.append(
            LaneFinding(
                rule_id=uf.rule_id,
                severity=uf.severity,
                message=uf.message,
                file=uf.file,
                line=uf.line,
                lane="hidden",
                tier="P1" if uf.status == "DETECT" else "P2",
                status=uf.status,
                mitre="T1027",
            )
        )

    findings.extend(scan_readability(target))
    findings.extend(scan_encoding_chains(target))
    findings.extend(deobfuscate_all_langs(target))
    findings.extend(scan_entropy(target))
    findings.extend(scan_stego(target))
    findings.extend(scan_crypto(target))

    findings.extend(scan_concolic_env(target))
    findings.extend(scan_ide_hooks(target))
    findings.extend(scan_attestation(target))

    return findings
