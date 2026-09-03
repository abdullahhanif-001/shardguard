#!/usr/bin/env py
"""Generate MOCK_ (50+) and adversarial bypass (B01-B15) fixtures."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MOCK = ROOT / "fixtures" / "MOCK_"
BYPASS = ROOT / "adversarial" / "bypass"


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_expected(dir_path: Path, data: dict) -> None:
    write(dir_path / "expected.json", json.dumps(data, indent=2) + "\n")


def gen_m01():
    d = MOCK / "M01_shard_three_modules"
    write(d / "encoder.js", "module.exports = function encode(s) { return Buffer.from(s).toString('base64'); };\n")
    write(d / "decoder.js", "const enc = require('./encoder');\nmodule.exports = function decode(b) { return Buffer.from(b, 'base64').toString(); };\n")
    write(
        d / "runner.js",
        "const dec = require('./decoder');\nconst { exec } = require('child_process');\nconst cmd = dec(process.env.PAYLOAD || 'd2hvYW1p');\nexec(cmd);\n",
    )
    write_expected(d, {"verdict": "DETECT", "require_cross_file": True})


def gen_m02():
    d = MOCK / "M02_postinstall_chain"
    write(d / "package.json", json.dumps({"name": "m02", "scripts": {"postinstall": "node bootstrap.js"}}, indent=2))
    write(d / "bootstrap.js", "const h = require('./helper');\nh.run();\n")
    write(d / "helper.js", "const { exec } = require('child_process');\nexports.run = () => exec(process.env.INSTALL_CMD || 'id');\n")
    write_expected(d, {"verdict": "DETECT", "require_cross_file": True, "require_lifecycle": True})


def gen_m03():
    d = MOCK / "M03_async_setimmediate"
    write(d / "routes.js", "const w = require('./worker');\nmodule.exports = (req) => { setImmediate(() => w.handle(req.query.data)); };\n")
    write(d / "worker.js", "const { exec } = require('child_process');\nexports.handle = (data) => exec(data);\n")
    write_expected(d, {"verdict": "DETECT", "require_cross_file": True})


def gen_m04():
    d = MOCK / "M04_benign_crypto"
    write(d / "hash.js", "const crypto = require('crypto');\nmodule.exports = (s) => crypto.createHash('sha256').update(s).digest('hex');\n")
    write(d / "util.js", "const hash = require('./hash');\nmodule.exports = { digest: hash };\n")
    write_expected(d, {"verdict": "CLEAN"})


def gen_m05():
    d = MOCK / "M05_string_concat_eval"
    write(d / "part1.js", "module.exports = 'ev';\n")
    write(d / "part2.js", "module.exports = 'al';\n")
    write(d / "combine.js", "const a = require('./part1');\nconst b = require('./part2');\neval(a + b);\n")
    write_expected(d, {"verdict": "DETECT", "require_cross_file": True})


def gen_variants():
    """M06–M50: variants of fragmentation patterns."""
    patterns = [
        ("env_shard", "process.env.A", "process.env.B", "exec"),
        ("fs_read_chain", "fs.readFileSync('/etc/passwd')", "data", "exec"),
        ("fetch_exfil", "fetch(url)", "body", "fs.writeFileSync"),
        ("barrel_export", "barrel", "reexport", "eval"),
        ("lazy_require", "lazy", "dynamic", "exec"),
    ]
    idx = 6
    for i in range(45):
        name = f"M{idx:02d}_variant_{i:02d}"
        d = MOCK / name
        pat = patterns[i % len(patterns)]
        write(
            d / "a.js",
            f"module.exports = function src() {{ return {pat[1] if 'process' in pat[1] or 'fetch' in pat[1] else repr(pat[1])}; }};\n",
        )
        write(d / "b.js", f"const src = require('./a');\nmodule.exports = function mid() {{ return src(); }};\n")
        if pat[3] == "eval":
            write(d / "c.js", "const mid = require('./b');\nconst x = mid();\neval(x);\n")
        elif pat[3] == "exec":
            write(d / "c.js", "const mid = require('./b');\nconst {exec} = require('child_process');\nexec(mid());\n")
        else:
            write(d / "c.js", "const mid = require('./b');\nconst fs = require('fs');\nfs.writeFileSync('/tmp/out', mid());\n")
        write_expected(d, {"verdict": "DETECT", "require_cross_file": True})
        idx += 1


def gen_bypass():
    cases = {
        "B01_globalthis_shard": (
            {"verdict": "DETECT", "allowed_statuses": ["DETECT", "UNKNOWN_RISK"], "bypass_id": "B01"},
            "globalThis._p = process.env.X;\n",
            "const x = globalThis._p;\nrequire('child_process').exec(x);\n",
        ),
        "B02_function_constructor": (
            {"verdict": "DETECT", "bypass_id": "B02"},
            "module.exports = 'return process.env.CMD';\n",
            "const p = require('./a');\nFunction(p)();\n",
        ),
        "B03_dynamic_import": (
            {"verdict": "DETECT", "allowed_statuses": ["DETECT", "UNKNOWN_RISK"], "bypass_id": "B03"},
            "const m = './sink';\nimport(m);\n",
            "",
        ),
        "B04_worker_threads": (
            {"verdict": "DETECT", "bypass_id": "B04"},
            "const { Worker } = require('worker_threads');\nnew Worker('./worker.js');\n",
            "const { parentPort } = require('worker_threads');\nconst {exec} = require('child_process');\nparentPort.on('message', (m) => exec(m));\n",
        ),
        "B05_prototype_pollution": (
            {"verdict": "DETECT", "bypass_id": "B05"},
            "exports.pollute = (o) => { o.__proto__.cmd = process.env.X; };\n",
            "const p = require('./pollute');\nconst o = {};\np.pollute(o);\nrequire('child_process').exec(o.cmd);\n",
        ),
        "B06_vm_bridge": (
            {"verdict": "DETECT", "bypass_id": "B06"},
            "module.exports = process.env.CODE;\n",
            "const vm = require('vm');\nconst code = require('./code');\nvm.runInNewContext(code);\n",
        ),
        "B07_base64_four_files": (
            {"verdict": "DETECT", "bypass_id": "B07"},
            "module.exports = 'Y2';\n",
            "module.exports = 'hd';\n",
            "module.exports = 'mF';\n",
            "module.exports = 'p';\n",
            "const a=require('./a'),b=require('./b'),c=require('./c'),d=require('./d');\nconst {exec}=require('child_process');\nexec(Buffer.from(a+b+c+d,'base64').toString());\n",
        ),
        "B08_postinstall_dynamic": (
            {"verdict": "DETECT", "bypass_id": "B08", "require_lifecycle": True},
            json.dumps({"scripts": {"postinstall": "node go.js"}}),
            "const m='./sink';\nrequire(m);\n",
            "require('child_process').exec(process.env.CMD||'id');\n",
        ),
        "B09_scc_depth": (
            {"verdict": "DETECT", "allowed_statuses": ["DETECT", "SCC_INCOMPLETE"], "bypass_id": "B09"},
            "const n=require('./b');\nmodule.exports=()=>n()+process.env.X;\n",
            "const n=require('./a');\nmodule.exports=()=>n();\n",
            "const a=require('./a');\nrequire('child_process').exec(a());\n",
        ),
        "B10_constructor_eval": (
            {"verdict": "DETECT", "bypass_id": "B10"},
            "const fn = [][ 'constructor' ];\nconst src = require('./src');\nfn('return '+src)();\n",
            "module.exports = 'process.env.X';\n",
        ),
        "B11_wasm_shard": (
            {"verdict": "DETECT", "allowed_statuses": ["DETECT", "UNKNOWN_RISK"], "bypass_id": "B11"},
            "module.exports = Buffer.from('AGFzbQE=', 'base64');\n",
            "const bytes = require('./bytes');\nWebAssembly.instantiate(bytes);\n",
        ),
        "B12_proxy_sink": (
            {"verdict": "DETECT", "bypass_id": "B12"},
            "const target = { run: (x) => require('child_process').exec(x) };\nmodule.exports = new Proxy(target, { get: (t,p) => t[p] });\n",
            "const p = require('./proxy');\np.run(process.env.CMD);\n",
        ),
        "B13_benign_barrel": (
            {"verdict": "CLEAN", "bypass_id": "B13"},
            "module.exports = { add: (a,b) => a+b };\n",
            "module.exports = require('./math');\n",
            "const lib = require('./index');\nconsole.log(lib.add(1,2));\n",
        ),
        "B14_minified_single": (
            {"verdict": "DOCUMENTED_SKIP", "bypass_id": "B14"},
            "eval(process.env.X);",
        ),
        "B15_time_bomb": (
            {"verdict": "DETECT", "allowed_statuses": ["DETECT", "SUSPICIOUS"], "bypass_id": "B15"},
            "module.exports = () => Date.now() > 0;\n",
            "const t = require('./trigger');\nif(t()) require('child_process').exec(process.env.CMD);\n",
        ),
    }

    file_maps = {
        "B01_globalthis_shard": {"a.js": cases["B01_globalthis_shard"][1], "b.js": cases["B01_globalthis_shard"][2]},
        "B02_function_constructor": {"a.js": cases["B02_function_constructor"][1], "b.js": cases["B02_function_constructor"][2]},
        "B03_dynamic_import": {"main.js": cases["B03_dynamic_import"][1]},
        "B04_worker_threads": {"main.js": cases["B04_worker_threads"][1], "worker.js": cases["B04_worker_threads"][2]},
        "B05_prototype_pollution": {"pollute.js": cases["B05_prototype_pollution"][1], "b.js": cases["B05_prototype_pollution"][2]},
        "B06_vm_bridge": {"code.js": cases["B06_vm_bridge"][1], "b.js": cases["B06_vm_bridge"][2]},
        "B07_base64_four_files": {
            "a.js": cases["B07_base64_four_files"][1],
            "b.js": cases["B07_base64_four_files"][2],
            "c.js": cases["B07_base64_four_files"][3],
            "d.js": cases["B07_base64_four_files"][4],
            "run.js": cases["B07_base64_four_files"][5],
            "index.js": "require('./run');\n",
        },
        "B08_postinstall_dynamic": {
            "package.json": cases["B08_postinstall_dynamic"][1],
            "go.js": cases["B08_postinstall_dynamic"][2],
            "sink.js": cases["B08_postinstall_dynamic"][3],
        },
        "B09_scc_depth": {"a.js": cases["B09_scc_depth"][1], "b.js": cases["B09_scc_depth"][2], "c.js": cases["B09_scc_depth"][3]},
        "B10_constructor_eval": {"src.js": cases["B10_constructor_eval"][2], "a.js": cases["B10_constructor_eval"][1]},
        "B11_wasm_shard": {"bytes.js": cases["B11_wasm_shard"][1], "b.js": cases["B11_wasm_shard"][2]},
        "B12_proxy_sink": {"proxy.js": cases["B12_proxy_sink"][1], "b.js": cases["B12_proxy_sink"][2]},
        "B13_benign_barrel": {"math.js": cases["B13_benign_barrel"][1], "index.js": cases["B13_benign_barrel"][2], "c.js": cases["B13_benign_barrel"][3]},
        "B14_minified_single": {"min.js": cases["B14_minified_single"][1]},
        "B15_time_bomb": {"trigger.js": cases["B15_time_bomb"][1], "b.js": cases["B15_time_bomb"][2]},
    }

    for name, fmap in file_maps.items():
        d = BYPASS / name
        write_expected(d, cases[name][0])
        for fname, content in fmap.items():
            write(d / fname, content)


def main():
    MOCK.mkdir(parents=True, exist_ok=True)
    BYPASS.mkdir(parents=True, exist_ok=True)
    gen_m01()
    gen_m02()
    gen_m03()
    gen_m04()
    gen_m05()
    gen_variants()
    gen_bypass()
    mock_count = sum(1 for p in MOCK.iterdir() if p.is_dir())
    bypass_count = sum(1 for p in BYPASS.iterdir() if p.is_dir())
    print(f"Generated {mock_count} MOCK_ fixtures and {bypass_count} bypass fixtures")


if __name__ == "__main__":
    main()
