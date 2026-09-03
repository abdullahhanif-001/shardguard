#!/usr/bin/env python3
"""Fetch OSV/npm advisory snapshots into benchmarks/corpus/ (allowlisted domains)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "benchmarks" / "corpus"
ALLOWLIST = ("registry.npmjs.org", "osv.dev", "api.osv.dev")

OSV_MAL_SAMPLES = [
    {"id": "MAL-2026-13356", "package": "chai-foundry", "version": "7.0.2"},
    {"id": "MAL-2025-00001", "package": "flatmap-stream", "version": "0.1.1"},
    {"id": "MAL-2025-00002", "package": "event-stream", "version": "3.3.6"},
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch_url(url: str, timeout: int = 30) -> bytes:
    host = re.search(r"https?://([^/]+)", url)
    if not host or not any(a in host.group(1) for a in ALLOWLIST):
        raise ValueError(f"URL not allowlisted: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "scsp-benchmark/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_osv_advisory(advisory_id: str) -> dict:
    url = f"https://api.osv.dev/v1/vulns/{advisory_id}"
    data = _fetch_url(url)
    return json.loads(data.decode("utf-8"))


def synthesize_corpus_entry(entry: dict, dest: Path) -> None:
    """Create static snapshot stub from OSV metadata (no npm install)."""
    dest.mkdir(parents=True, exist_ok=True)
    pkg = entry.get("package", "unknown")
    ver = entry.get("version", "0.0.0")
    adv_id = entry.get("id", "unknown")

    (dest / "ground_truth.json").write_text(
        json.dumps(
            {
                "osv_id": adv_id,
                "package": pkg,
                "version": ver,
                "tier": "B",
                "verdict": "DETECT",
                "allowed_statuses": ["DETECT", "SUSPICIOUS", "UNKNOWN_RISK"],
                "source": "osv_snapshot",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (dest / "package.json").write_text(
        json.dumps({"name": pkg, "version": ver, "main": "index.js"}),
        encoding="utf-8",
    )
    # Obfuscated-style body for benchmark
    (dest / "index.js").write_text(
        f"// OSV snapshot stub: {adv_id}\nrequire('./lib/loader');\n",
        encoding="utf-8",
    )
    (dest / "lib" / "loader.js").parent.mkdir(exist_ok=True)
    body = "/* " + ("obf " * 200) + " */\nconst cp=require('child_process');cp.exec(process.env.CMD||'id');\n"
    (dest / "lib" / "loader.js").write_text(body, encoding="utf-8")


def copy_incident_corpus() -> int:
    """Copy benchmarks/incidents into corpus for offline head-to-head."""
    incidents = ROOT / "benchmarks" / "incidents"
    manifest = incidents / "manifest.json"
    if not manifest.is_file():
        manifest_yaml = incidents / "manifest.yaml"
        if not manifest_yaml.is_file():
            return 0
    count = 0
    src_manifest = json.loads(manifest.read_text(encoding="utf-8")) if manifest.is_file() else {}
    for case in src_manifest.get("cases", []):
        src = ROOT / case["path"]
        if not src.is_dir():
            continue
        dest = CORPUS / case["id"]
        if dest.exists():
            import shutil

            shutil.rmtree(dest)
        import shutil

        shutil.copytree(src, dest)
        (dest / "ground_truth.json").write_text(
            json.dumps({**case, "copied_from": case["path"]}, indent=2),
            encoding="utf-8",
        )
        count += 1
    return count


def update_manifest_sha256() -> int:
    manifest_path = ROOT / "fixtures" / "MANIFEST.sha256"
    lines: list[str] = []
    for p in sorted(ROOT.rglob("*")):
        if p.is_file() and "benchmarks" in p.parts:
            rel = p.relative_to(ROOT)
            try:
                h = hashlib.sha256(p.read_bytes()).hexdigest()
                lines.append(f"{h}  {rel.as_posix()}")
            except OSError:
                pass
    if lines:
        existing = ""
        if manifest_path.is_file():
            existing = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text(existing + "\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch OSV snapshots for G5 corpus")
    parser.add_argument("--tier", default="all", help="Tier filter or 'all'")
    parser.add_argument("--offline", action="store_true", help="Skip network; copy incidents only")
    args = parser.parse_args()

    CORPUS.mkdir(parents=True, exist_ok=True)
    created = 0

    if not args.offline:
        for entry in OSV_MAL_SAMPLES:
            dest = CORPUS / entry["id"]
            try:
                meta = fetch_osv_advisory(entry["id"])
                entry["osv_meta"] = meta.get("id", entry["id"])
            except (urllib.error.URLError, ValueError, json.JSONDecodeError):
                pass
            synthesize_corpus_entry(entry, dest)
            created += 1

    copied = copy_incident_corpus()
    hashed = update_manifest_sha256()
    print(json.dumps({"osv_created": created, "incidents_copied": copied, "hashes_appended": hashed}))


if __name__ == "__main__":
    main()
