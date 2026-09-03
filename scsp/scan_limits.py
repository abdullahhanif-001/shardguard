"""Scan scale limits (L11)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScanLimits:
    max_files: int = 50_000
    max_loc: int = 500_000
    max_file_bytes: int = 2 * 1024 * 1024
    scc_depth_cap: int = 64
    incremental: bool = False
