"""Remote GitHub repo scan — scsp scan <url> (L25, G32)."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from scsp.universal_scan import scan_universal


GITHUB_RE = re.compile(r"https?://(?:www\.)?github\.com/[\w.-]+/[\w.-]+")


def clone_github(url: str, dest: Path, depth: int = 1) -> bool:
    try:
        subprocess.run(
            ["git", "clone", "--depth", str(depth), url, str(dest)],
            capture_output=True,
            timeout=300,
            check=True,
        )
        return True
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return False


def scan_remote(
    url: str,
    report_dir: Path | None = None,
    keep_clone: bool = False,
) -> tuple[list, dict, Path | None]:
    """Shallow clone + universal scan."""
    if not GITHUB_RE.match(url.split("#")[0].rstrip("/")):
        raise ValueError(f"Unsupported URL (GitHub only): {url}")

    tmp = tempfile.mkdtemp(prefix="scsp-clone-")
    clone_path = Path(tmp)
    try:
        if not clone_github(url, clone_path):
            raise RuntimeError(f"git clone failed: {url}")
        out = report_dir or (Path("proof") / "scan_remote" / urlparse(url).path.strip("/").replace("/", "_"))
        findings, meta, report = scan_universal(clone_path, report_dir=out)
        meta["clone_url"] = url
        meta["clone_path"] = str(clone_path)
        if keep_clone:
            return findings, meta, clone_path
        return findings, meta, out
    finally:
        if not keep_clone:
            shutil.rmtree(tmp, ignore_errors=True)
