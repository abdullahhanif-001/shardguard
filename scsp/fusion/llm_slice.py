"""Optional LLM on slices — P2 only (L10)."""

from __future__ import annotations

import os
import re

from scsp.lanes.types import LaneFinding


def classify_slice(slice_text: str, enabled: bool = False) -> list[LaneFinding]:
    if not enabled or os.environ.get("SCSP_LLM_SLICES") != "1":
        return []
    if len(slice_text) > 4096:
        return []
    # Offline stub — no API call unless SCSP_LLM_API set
    api = os.environ.get("SCSP_LLM_API")
    if not api:
        if re.search(r"eval|exec|backdoor|exfil", slice_text, re.I):
            return [
                LaneFinding(
                    rule_id="urns/llm-slice-suspect",
                    severity="MEDIUM",
                    message="LLM slice heuristic: suspicious execution pattern",
                    file="slice",
                    lane="fusion",
                    tier="P2",
                    status="SUSPICIOUS",
                )
            ]
        return []
    return []


# removed duplicate import
