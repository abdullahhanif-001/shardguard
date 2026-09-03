"""Z3 path feasibility for env guards (G19)."""

from __future__ import annotations

import re
from typing import Any

from scsp.lanes.types import LaneFinding


ENV_GUARD_RE = re.compile(
    r"if\s*\(\s*process\.env\.(\w+)\s*===?\s*['\"](\w+)['\"]\s*\)"
)


def check_env_guard(text: str, file: str, line: int) -> dict[str, Any]:
    m = ENV_GUARD_RE.search(text)
    if not m:
        return {"result": "UNKNOWN", "guard": None}
    var, val = m.group(1), m.group(2)
    from scsp.fusion.datalog_taint import prove_path_z3

    result = prove_path_z3(f"process.env.{var} === '{val}'")
    return {"result": result, "guard": f"{var}=={val}", "file": file, "line": line}


def scan_env_gates(target_text: str, file: str) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    for i, line in enumerate(target_text.splitlines(), 1):
        if "process.env" not in line:
            continue
        chk = check_env_guard(line, file, i)
        if chk["result"] == "PROVEN":
            findings.append(
                LaneFinding(
                    rule_id="urns/smt-env-gate-proven",
                    severity="HIGH",
                    message=f"Env gate feasible: {chk.get('guard')}",
                    file=file,
                    line=i,
                    lane="fusion",
                    tier="P0",
                    witness_constraints=chk,
                    status="DETECT",
                )
            )
        elif ENV_GUARD_RE.search(line) and re.search(r"eval|exec|child_process", target_text):
            findings.append(
                LaneFinding(
                    rule_id="urns/smt-env-gate-unknown",
                    severity="MEDIUM",
                    message="Env-gated sleeper — path UNKNOWN (SMT bounded)",
                    file=file,
                    line=i,
                    lane="fusion",
                    tier="OUT_OF_SCOPE",
                    status="UNKNOWN_RISK",
                )
            )
    return findings
