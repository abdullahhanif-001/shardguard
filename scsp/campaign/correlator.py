"""Cross-repo campaign correlation."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from scsp.campaign.graph import CampaignGraph, CampaignNode
from scsp.lanes.types import LaneFinding
from scsp.sandbox import safe_read_text

CAMPAIGN_STRINGS = [
    "setup.mjs", "Shai-Hulud", "ChainDrop", "OtterCookie", "dead-man",
    "GITHUB_TOKEN", "NPM_TOKEN", "auto-republish",
]


def scan_campaign_signals(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    graph = CampaignGraph()
    pkg_name = target.name
    graph.add(CampaignNode(id=f"pkg:{pkg_name}", kind="package", attrs={"path": str(target)}))

    strings_found: list[str] = []
    for fp in target.rglob("*") if target.is_dir() else [target]:
        if not fp.is_file() or fp.stat().st_size > 500_000:
            continue
        text = safe_read_text(fp) or ""
        for cs in CAMPAIGN_STRINGS:
            if cs.lower() in text.lower():
                strings_found.append(cs)
                graph.add(CampaignNode(id=f"sig:{cs}", kind="campaign_string"))
                graph.link(f"pkg:{pkg_name}", f"sig:{cs}", "contains")
        # C2 domain heuristic
        for m in re.finditer(r"https?://([a-zA-Z0-9.-]+\.[a-z]{2,})", text):
            domain = m.group(1)
            if not any(x in domain for x in ("github.com", "npmjs.org", "localhost")):
                graph.add(CampaignNode(id=f"domain:{domain}", kind="domain"))
                graph.link(f"pkg:{pkg_name}", f"domain:{domain}", "c2_candidate")
                findings.append(
                    LaneFinding(
                        rule_id="urns/campaign-c2-domain",
                        severity="HIGH",
                        message=f"Campaign C2 candidate domain: {domain}",
                        file=str(fp.resolve()),
                        lane="campaign",
                        tier="P3",
                        mitre="T1071",
                    )
                )

    if len(strings_found) >= 2:
        findings.append(
            LaneFinding(
                rule_id="urns/campaign-multi-signal",
                severity="CRITICAL",
                message=f"Multiple campaign signals: {strings_found}",
                file=str(target),
                lane="campaign",
                tier="P3",
                status="DETECT",
                mitre="T1195.002",
            )
        )

    # Store graph hash for cross-repo correlation
    gh = hashlib.sha256(str(graph.to_dict()).encode()).hexdigest()[:16]
    findings.append(
        LaneFinding(
            rule_id="urns/campaign-graph-id",
            severity="INFO",
            message=f"Campaign graph fingerprint: {gh}",
            file=str(target),
            lane="campaign",
            tier="P3",
            witness_constraints={"graph": graph.to_dict()},
        )
    )
    return findings
