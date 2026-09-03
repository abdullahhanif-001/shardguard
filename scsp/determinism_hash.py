"""Canonical finding hash for cross-host determinism."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scsp.lanes.types import LaneFinding


def normalize_path(file_path: str, case_root: Path | None = None) -> str:
    """Strip absolute paths; use case-relative posix path."""
    p = Path(file_path)
    if case_root:
        try:
            rel = p.resolve().relative_to(case_root.resolve())
            return rel.as_posix()
        except ValueError:
            pass
    name = p.name
    parts = p.parts
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return name


def canonical_finding(f: LaneFinding, case_root: Path | None = None) -> dict:
    return {
        "rule_id": f.rule_id,
        "file": normalize_path(f.file, case_root),
        "line": f.line,
        "tier": f.tier,
        "status": f.status,
        "lane": f.lane,
    }


def hash_findings(findings: list[LaneFinding], case_root: Path | None = None) -> None:
    pass


def findings_hash_normalized(cases: list[Path], scan_fn) -> str:
    """Hash sorted canonical finding tuples across cases."""
    h = hashlib.sha256()
    for case in cases:
        if not case.is_dir():
            continue
        findings, _, _ = scan_fn(case)
        canon = [canonical_finding(f, case) for f in findings]
        for c in sorted(canon, key=lambda x: (x["rule_id"], x["file"], x["line"])):
            h.update(json.dumps(c, sort_keys=True).encode())
    return h.hexdigest()
