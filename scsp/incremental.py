"""Incremental scan cache (L22)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scsp.integrity import ROOT

CACHE_DIR = ROOT / ".scsp" / "cache"


def file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def load_cache(target: Path) -> dict:
    cp = CACHE_DIR / f"{hashlib.sha256(str(target.resolve()).encode()).hexdigest()[:16]}.json"
    if cp.is_file():
        try:
            return json.loads(cp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {}


def save_cache(target: Path, cache: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cp = CACHE_DIR / f"{hashlib.sha256(str(target.resolve()).encode()).hexdigest()[:16]}.json"
    cp.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def changed_files(target: Path, cache: dict) -> list[Path]:
    """Return files whose content hash changed since last scan."""
    changed = []
    for fp in target.rglob("*") if target.is_dir() else [target]:
        if not fp.is_file():
            continue
        h = file_hash(fp)
        key = str(fp.resolve())
        if cache.get(key) != h:
            changed.append(fp)
            cache[key] = h
    return changed
