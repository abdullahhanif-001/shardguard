"""Temporal publish burst detection."""

from __future__ import annotations

import json
from pathlib import Path


def detect_publish_burst(packages: list[dict]) -> list[str]:
    """Flag packages published within same hour window."""
    from collections import defaultdict

    buckets: dict[str, list[str]] = defaultdict(list)
    for p in packages:
        ts = p.get("published", "")[:13]  # hour bucket
        buckets[ts].append(p.get("name", ""))
    alerts = []
    for ts, names in buckets.items():
        if len(names) >= 3:
            alerts.append(f"burst:{ts}:{','.join(names[:5])}")
    return alerts
