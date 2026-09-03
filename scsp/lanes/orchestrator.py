"""Run all 8 defense lanes in parallel merge."""

from __future__ import annotations

import os
from pathlib import Path

from scsp.lanes.behavioral import run_gvisor_sandbox, scan_install_behavior
from scsp.lanes.crypto import scan_crypto
from scsp.lanes.fast import scan_fast_patterns, scan_semgrep_optional
from scsp.lanes.fuzz import scan_fuzz_markers
from scsp.lanes.git_forensics import maintainer_risk, scan_git_forensics
from scsp.lanes.iac import scan_iac
from scsp.lanes.secrets import scan_git_secrets, scan_secrets
from scsp.lanes.supply_chain import scan_supply_chain
from scsp.lanes.types import LaneFinding
from scsp.lanes.wasm import scan_wasm
from scsp.scan_limits import ScanLimits


def run_all_lanes(target: Path, limits: ScanLimits | None = None) -> tuple[list[LaneFinding], dict]:
    limits = limits or ScanLimits()
    meta: dict = {"lanes": {}, "maintainer_risk": maintainer_risk(target)}

    lanes = [
        ("fast", lambda: scan_fast_patterns(target) + scan_semgrep_optional(target)),
        ("supply_chain", lambda: scan_supply_chain(target)),
        ("secrets", lambda: scan_secrets(target) + scan_git_secrets(target)),
        ("iac", lambda: scan_iac(target)),
        ("behavioral", lambda: scan_install_behavior(target) + (
            run_gvisor_sandbox(target) if os.environ.get("SCSP_ON_VPS") else []
        )),
        ("fuzz", lambda: scan_fuzz_markers(target)),
        ("git_forensics", lambda: scan_git_forensics(target)),
        ("crypto", lambda: scan_crypto(target)),
        ("wasm", lambda: scan_wasm(target)),
    ]

    # Hidden logic lane hooks
    from scsp.hidden.runner import scan_hidden

    lanes.append(("hidden", lambda: scan_hidden(target)))

    # Campaign lane
    from scsp.campaign.correlator import scan_campaign_signals

    lanes.append(("campaign", lambda: scan_campaign_signals(target)))

    all_findings: list[LaneFinding] = []
    for name, fn in lanes:
        try:
            hits = fn()
            meta["lanes"][name] = len(hits)
            all_findings.extend(hits)
        except Exception as e:  # noqa: BLE001 — lane isolation
            meta["lanes"][name] = f"error:{e}"

    # Deduplicate
    seen: set[tuple] = set()
    unique: list[LaneFinding] = []
    for f in all_findings:
        key = (f.rule_id, f.file, f.line, f.lane)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    meta["total_findings"] = len(unique)
    meta["tier_counts"] = {}
    for f in unique:
        meta["tier_counts"][f.tier] = meta["tier_counts"].get(f.tier, 0) + 1

    return unique, meta
