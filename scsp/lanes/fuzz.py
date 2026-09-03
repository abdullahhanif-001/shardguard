"""Lane 6 — fuzz/sanitizer crash detection (OSS-Fuzz style, L02)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

# Pre-built crash fixtures in benchmarks/universal/fuzz/
CRASH_MARKERS = [
    (re.compile(r"__SANITIZER__|ASAN:|UBSAN:|heap-buffer-overflow"), "sanitizer-crash", "CRITICAL"),
    (re.compile(r"abort\(\)|SIGSEGV|stack-buffer-overflow"), "memory-crash", "CRITICAL"),
]


def scan_fuzz_markers(target: Path) -> list[LaneFinding]:
    """Detect sanitizer crash patterns in fuzz output files or MOCK fixtures."""
    findings: list[LaneFinding] = []
    for fp in target.rglob("*") if target.is_dir() else [target]:
        if not fp.is_file():
            continue
        if fp.suffix not in {".txt", ".log", ".c", ".cpp", ".h"} and "fuzz" not in fp.parts:
            continue
        text = safe_read_text(fp)
        if not text:
            continue
        fs = str(fp.resolve())
        for i, line in enumerate(text.splitlines(), 1):
            for pat, name, sev in CRASH_MARKERS:
                if pat.search(line):
                    findings.append(
                        LaneFinding(
                            rule_id=f"urns/fuzz-{name}",
                            severity=sev,
                            message=f"Fuzz/sanitizer finding: {name}",
                            file=fs,
                            line=i,
                            lane="fuzz",
                            tier="P0",
                            witness_constraints={"type": "sanitizer_crash"},
                            status="DETECT",
                        )
                    )
    return findings


def run_libfuzzer_harness(harness: Path, timeout: int = 10) -> list[LaneFinding]:
    """Optional libFuzzer subprocess — VPS/Linux only."""
    findings: list[LaneFinding] = []
    if not harness.is_file():
        return findings
    try:
        result = subprocess.run(
            ["clang", "-fsanitize=address,fuzzer", str(harness), "-o", "/tmp/scsp_fuzz"],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            return findings
        run = subprocess.run(["/tmp/scsp_fuzz", "-runs=100"], capture_output=True, text=True, timeout=timeout, check=False)
        if "ERROR: AddressSanitizer" in (run.stderr or "") + (run.stdout or ""):
            findings.append(
                LaneFinding(
                    rule_id="urns/fuzz-asan-crash",
                    severity="CRITICAL",
                    message="AddressSanitizer crash in fuzz harness",
                    file=str(harness),
                    lane="fuzz",
                    tier="P0",
                    witness_constraints={"harness": str(harness)},
                    status="DETECT",
                )
            )
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return findings
