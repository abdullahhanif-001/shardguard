"""Local IOC name/hash matching — no telemetry."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent
IOC_FILE = ROOT / "benchmarks" / "ioc" / "local_ioc.json"

KNOWN_MALICIOUS_NAMES = {
    "flatmap-stream",
    "event-stream",
    "ua-parser-js",
    "colors",
    "faker",
    "node-ipc",
    "rc",
    "coa",
    "phantom-gyp-sample",
}


def _load_ioc() -> dict:
    if IOC_FILE.is_file():
        return json.loads(IOC_FILE.read_text(encoding="utf-8"))
    return {"names": list(KNOWN_MALICIOUS_NAMES), "sha256": []}


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_ioc(root: Path) -> List[dict]:
    findings: List[dict] = []
    ioc = _load_ioc()
    root = root.resolve()

    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            name = data.get("name", "")
            if name in ioc.get("names", []) or name in KNOWN_MALICIOUS_NAMES:
                findings.append(
                    {
                        "rule_id": "scsp/ioc-known-package",
                        "severity": "HIGH",
                        "message": f"Package name matches known malicious IOC: {name}",
                        "status": "SUSPICIOUS",
                        "file": str(pkg),
                    }
                )
        except (OSError, json.JSONDecodeError):
            pass

    for js in list(root.rglob("*.js"))[:50]:
        if "node_modules" in js.parts:
            continue
        digest = file_sha256(js)
        if digest in ioc.get("sha256", []):
            findings.append(
                {
                    "rule_id": "scsp/ioc-hash-match",
                    "severity": "CRITICAL",
                    "message": f"File hash matches IOC: {js.name}",
                    "status": "DETECT",
                    "file": str(js.resolve()),
                }
            )
    return findings
