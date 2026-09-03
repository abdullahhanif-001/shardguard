"""STIX 2.1 + SARIF campaign tag export."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def to_stix_bundle(findings: list[dict], campaign_id: str = "urns-campaign") -> dict[str, Any]:
    objects = [
        {
            "type": "bundle",
            "id": f"bundle--{campaign_id}",
            "spec_version": "2.1",
            "objects": [],
        }
    ]
    bundle = objects[0]
    for i, f in enumerate(findings):
        if f.get("lane") != "campaign":
            continue
        bundle["objects"].append(
            {
                "type": "indicator",
                "id": f"indicator--{i}",
                "created": datetime.now(timezone.utc).isoformat(),
                "pattern": f"[file:hashes.'SHA-256' = '{f.get('rule_id', '')}']",
                "labels": ["malicious-activity"],
                "description": f.get("message", ""),
            }
        )
    return bundle
