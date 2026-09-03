#!/usr/bin/env python3
"""Check SCSP language coverage against LANGUAGE_MATRIX.json."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "benchmarks" / "LANGUAGE_MATRIX.json"


def _registered_plugins() -> set[str]:
    reg = (ROOT / "scsp" / "plugins" / "registry.py").read_text(encoding="utf-8")
    names = set(re.findall(r'(\w+Plugin)\(\)', reg))
    mapping = {
        "JavaScriptPlugin": "javascript",
        "PythonPlugin": "python",
        "GoPlugin": "go",
        "RustPlugin": "rust",
        "JavaPlugin": "java",
        "CPlugin": "c",
        "PHPPlugin": "php",
        "RubyPlugin": "ruby",
        "CSharpPlugin": "csharp",
        "KotlinPlugin": "kotlin",
        "SwiftPlugin": "swift",
        "ShellPlugin": "shell",
    }
    return {mapping.get(n, n.replace("Plugin", "").lower()) for n in names}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("matrix", nargs="?", default=str(MATRIX_PATH))
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    matrix = json.loads(Path(args.matrix).read_text(encoding="utf-8"))
    registered = _registered_plugins()
    tier0 = set(matrix["tiers"]["tier0_core"])
    tier1 = set(matrix["tiers"]["tier1"])
    required = tier0 | tier1
    missing = sorted(required - registered)
    report = {
        "registered_count": len(registered),
        "registered": sorted(registered),
        "required_for_g33": matrix.get("scsp_minimum_for_g33", 12),
        "tier0_complete": tier0 <= registered,
        "tier1_complete": tier1 <= registered,
        "missing_tier1": missing,
        "status": "PASS" if len(registered) >= matrix.get("scsp_minimum_for_g33", 12) and not missing else "FAIL",
    }
    print(json.dumps(report, indent=2))
    if args.strict and report["status"] != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
