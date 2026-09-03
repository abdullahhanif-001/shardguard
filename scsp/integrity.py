"""Engine integrity verification."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCSP_DIR = ROOT / ".scsp"
ENGINE_HASH_FILE = SCSP_DIR / "engine.sha256"
NYX_PATH_FILE = SCSP_DIR / "nyx-path.txt"
FIXTURE_MANIFEST = ROOT / "fixtures" / "MANIFEST.sha256"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_nyx() -> str | None:
    if NYX_PATH_FILE.is_file():
        p = NYX_PATH_FILE.read_text(encoding="utf-8").strip()
        if p and Path(p).is_file():
            return p
    found = shutil.which("nyx")
    return found


def pin_engine() -> str:
    SCSP_DIR.mkdir(parents=True, exist_ok=True)
    nyx = find_nyx()
    if nyx:
        NYX_PATH_FILE.write_text(nyx, encoding="utf-8")
        digest = sha256_file(Path(nyx))
        ENGINE_HASH_FILE.write_text(f"{digest}  {nyx}\n", encoding="utf-8")
        return digest
    # Pin scsp package itself as engine when nyx absent
    init_py = Path(__file__).resolve()
    digest = sha256_file(init_py)
    ENGINE_HASH_FILE.write_text(f"{digest}  scsp-builtin\n", encoding="utf-8")
    return digest


def verify_self() -> tuple[bool, str]:
    if not ENGINE_HASH_FILE.is_file():
        return False, "engine not pinned — run: scsp verify-self --pin"
    line = ENGINE_HASH_FILE.read_text(encoding="utf-8").strip().split()
    if len(line) < 2:
        return False, "invalid engine.sha256 format"
    expected, label = line[0], line[1]
    if label == "scsp-builtin":
        actual = sha256_file(Path(__file__).resolve())
    else:
        if not Path(label).is_file():
            return False, f"engine binary missing: {label}"
        actual = sha256_file(Path(label))
    if actual != expected:
        return False, f"engine hash mismatch: expected {expected[:16]}... got {actual[:16]}..."
    return True, "OK"


def verify_fixtures() -> tuple[bool, str]:
    if not FIXTURE_MANIFEST.is_file():
        return False, "fixtures/MANIFEST.sha256 missing — run: scsp verify-fixtures --generate"
    manifest = FIXTURE_MANIFEST.read_text(encoding="utf-8")
    errors = []
    for line in manifest.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest, rel = parts[0], parts[1]
        fp = ROOT / rel
        if not fp.is_file():
            errors.append(f"missing: {rel}")
            continue
        if sha256_file(fp) != digest:
            errors.append(f"hash mismatch: {rel}")
    if errors:
        return False, "; ".join(errors[:5])
    return True, "OK"


def generate_fixture_manifest() -> int:
    fixtures_root = ROOT / "fixtures"
    lines = ["# SCSP fixture manifest — auto-generated", ""]
    count = 0
    for fp in sorted(fixtures_root.rglob("*")):
        if fp.is_file() and fp.name != "MANIFEST.sha256":
            rel = fp.relative_to(ROOT).as_posix()
            lines.append(f"{sha256_file(fp)}  {rel}")
            count += 1
    FIXTURE_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return count
