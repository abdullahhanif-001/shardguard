"""Cross-file taint analysis engine (two-pass, JS)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from scsp.build_graph import IMPORT_RE, LIFECYCLE_SCRIPTS, build_graph, resolve_import

# Sources — attacker-controlled or untrusted entry
SOURCE_PATTERNS = [
    (re.compile(r"process\.env\b"), "process.env"),
    (re.compile(r"process\.argv\b"), "process.argv"),
    (re.compile(r"req\.(query|body|params|headers)\b"), "http.request"),
    (re.compile(r"fs\.readFile(?:Sync)?\s*\("), "fs.read"),
    (re.compile(r"http\.createServer\s*\("), "http.server"),
    (re.compile(r"globalThis\b"), "globalThis"),
    (re.compile(r"__dirname\b"), "dirname"),
    (re.compile(r"Date\.now\s*\("), "time.trigger"),
    (re.compile(r"worker_threads"), "worker"),
    (re.compile(r"import\s*\(\s*[^'\"]"), "dynamic.import"),
]

# Sinks — dangerous operations
SINK_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval", "CRITICAL"),
    (re.compile(r"\bFunction\s*\("), "Function", "CRITICAL"),
    (re.compile(r"child_process\.(exec|execSync|spawn)\s*\("), "command.exec", "CRITICAL"),
    (re.compile(r"require\s*\(\s*['\"]child_process['\"]"), "child_process", "HIGH"),
    (re.compile(r"vm\.runInNewContext\s*\("), "vm.exec", "CRITICAL"),
    (re.compile(r"fs\.writeFile(?:Sync)?\s*\("), "fs.write", "HIGH"),
    (re.compile(r"https?\.request\s*\("), "network.out", "HIGH"),
    (re.compile(r"\bfetch\s*\("), "fetch", "MEDIUM"),
    (re.compile(r"WebAssembly\.instantiate"), "wasm.load", "HIGH"),
    (re.compile(r"__proto__|prototype\s*\["), "prototype.pollution", "HIGH"),
    (re.compile(r"\[\s*['\"]constructor['\"]\s*\]"), "constructor.eval", "CRITICAL"),
]

EXPORT_RE = re.compile(
    r"module\.exports\s*=\s*\{([^}]+)\}|module\.exports\s*=\s*(\w+)|exports\.(\w+)\s*=",
    re.MULTILINE,
)
FUNC_RE = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE)
ARROW_EXPORT_RE = re.compile(r"(?:exports\.|module\.exports\s*=\s*)(\w+)\s*=\s*(?:\([^)]*\)|[\w]+)\s*=>", re.MULTILINE)
CALL_RE = re.compile(r"(\w+)\s*\(([^)]*)\)", re.MULTILINE)
STRING_CONCAT_RE = re.compile(r"['\"][^'\"]{1,20}['\"]\s*\+")
BASE64_RE = re.compile(r"Buffer\.from\s*\([^,]+,\s*['\"]base64['\"]\)")
PROMISE_CHAIN_RE = re.compile(r"\.then\s*\(|new\s+Promise\s*\(")
ASYNC_AWAIT_RE = re.compile(r"\basync\s+function|\bawait\s+")


@dataclass
class TaintSummary:
    file: str
    function: str
    params_tainted: Set[int] = field(default_factory=set)
    returns_tainted: bool = False
    has_source: bool = False
    has_sink: bool = False
    sink_rules: List[str] = field(default_factory=list)
    source_rules: List[str] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    cross_file: bool = False
    evidence_path: List[str] = field(default_factory=list)
    fragmentation_pattern: Optional[str] = None
    status: str = "DETECT"  # DETECT, CLEAN, UNKNOWN_RISK, SUSPICIOUS, SCC_INCOMPLETE

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "cross_file": self.cross_file,
            "evidence_path": self.evidence_path,
            "fragmentation_pattern": self.fragmentation_pattern,
            "status": self.status,
        }


def _line_of(text: str, pos: int) -> int:
    return text[:pos].count("\n") + 1


def _analyze_function(file: str, func_name: str, body: str, full_text: str) -> TaintSummary:
    summary = TaintSummary(file=file, function=func_name)
    for pat, name in SOURCE_PATTERNS:
        if pat.search(body):
            summary.has_source = True
            summary.source_rules.append(name)
    for pat, name, _ in SINK_PATTERNS:
        if pat.search(body):
            summary.has_sink = True
            summary.sink_rules.append(name)
    if STRING_CONCAT_RE.search(body) and re.search(r"eval|Function|exec", body):
        summary.has_source = True
        summary.source_rules.append("string.shard")
    if BASE64_RE.search(body):
        summary.has_source = True
        summary.source_rules.append("base64.shard")
    if summary.has_source:
        summary.returns_tainted = True
        summary.params_tainted.add(0)
    return summary


def _extract_summaries(file_path: Path) -> List[TaintSummary]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    summaries: List[TaintSummary] = []
    file_str = str(file_path.resolve())

    # Module-level analysis
    mod = _analyze_function(file_str, "<module>", text, text)
    summaries.append(mod)

    for m in FUNC_RE.finditer(text):
        name, _ = m.group(1), m.group(2)
        start = m.start()
        end = min(start + 2000, len(text))
        body = text[start:end]
        summaries.append(_analyze_function(file_str, name, body, text))

    return summaries


def _import_map(file_path: Path, text: str) -> Dict[str, Path]:
    mapping: Dict[str, Path] = {}
    for spec in IMPORT_RE.findall(text):
        resolved = resolve_import(file_path, spec, file_path.parent)
        if resolved:
            binding = Path(spec).stem
            if "/" in spec or "\\" in spec:
                binding = Path(spec).stem
            mapping[binding] = resolved
            mapping[Path(spec).name.replace(".js", "")] = resolved
    # require('./foo') destructuring
    for m in re.finditer(r"const\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]", text):
        bindings, spec = m.group(1), m.group(2)
        resolved = resolve_import(file_path, spec, file_path.parent)
        if resolved:
            for b in bindings.split(","):
                b = b.strip().split(":")[0].strip()
                mapping[b] = resolved
    for m in re.finditer(r"const\s+(\w+)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]", text):
        binding, spec = m.group(1), m.group(2)
        resolved = resolve_import(file_path, spec, file_path.parent)
        if resolved:
            mapping[binding] = resolved
    return mapping


AES_DECIPHER_RE = re.compile(r"createDecipher(?:iv)?\s*\(")
NPM_DESC_RE = re.compile(r"process\.env\.npm_package_description")
LARGE_FILE_BYTES = 500_000
IMPORT_TIME_MAIN_RE = re.compile(r"^(index|main)\.(js|cjs|mjs)$", re.I)


def _heuristic_findings(target: Path, js_files: List[Path], file_texts: Dict[str, str]) -> List[Finding]:
    """Import-time, AES/hex dormant, large-file obfuscation heuristics."""
    extra: List[Finding] = []
    pkg_json = target / "package.json"
    main_field = ""
    if pkg_json.is_file():
        try:
            import json as _json

            pdata = _json.loads(pkg_json.read_text(encoding="utf-8"))
            main_field = pdata.get("main", "index.js")
        except (OSError, ValueError):
            main_field = "index.js"

    for jf in js_files:
        fs = str(jf.resolve())
        text = file_texts.get(fs, "")
        if not text:
            continue

        # Large obfuscated entry (chai-foundry signal)
        if jf.stat().st_size > LARGE_FILE_BYTES and re.search(r"child_process|eval|Function", text):
            extra.append(
                Finding(
                    rule_id="scsp/large-obfuscated-entry",
                    severity="HIGH",
                    message="Large JS entry with execution primitives (obfuscation heuristic)",
                    file=fs,
                    line=1,
                    cross_file=False,
                    evidence_path=[fs],
                    status="SUSPICIOUS",
                )
            )

        # AES/hex dormant pattern (event-stream signature)
        if (
            AES_DECIPHER_RE.search(text)
            and NPM_DESC_RE.search(text)
            and re.search(r"require\s*\(\s*['\"]\.\/test\/data", text)
        ):
            extra.append(
                Finding(
                    rule_id="scsp/aes-hex-dormant",
                    severity="HIGH",
                    message="AES decipher + npm_package_description + test/data shard (dormant payload heuristic)",
                    file=fs,
                    line=1,
                    cross_file=True,
                    evidence_path=[fs],
                    status="SUSPICIOUS",
                )
            )

        # Import-time entry: main file reads fs / network at top level
        if jf.name == Path(main_field).name or IMPORT_TIME_MAIN_RE.match(jf.name):
            if re.search(r"readFileSync|readFile\s*\(", text) and re.search(r"child_process|exec\s*\(", text):
                extra.append(
                    Finding(
                        rule_id="scsp/import-time-entry",
                        severity="HIGH",
                        message="Import-time file read with command execution",
                        file=fs,
                        line=1,
                        cross_file=False,
                        evidence_path=[fs],
                        status="SUSPICIOUS",
                    )
                )

    return extra


def scan_directory(target: Path) -> Tuple[List[Finding], dict]:
    target = target.resolve()
    graph = build_graph(target)
    findings: List[Finding] = []
    all_summaries: Dict[str, List[TaintSummary]] = {}

    js_files: List[Path] = []
    if target.is_file():
        js_files = [target]
    else:
        js_files = [
            p
            for p in list(target.rglob("*.js")) + list(target.rglob("*.mjs")) + list(target.rglob("*.cjs"))
            if "node_modules" not in p.parts
        ]

    # Pass 1: summaries
    for jf in js_files:
        all_summaries[str(jf.resolve())] = _extract_summaries(jf)

    # Reverse import map: who imports this file?
    imported_by: Dict[str, List[str]] = {}
    file_texts: Dict[str, str] = {}
    file_imaps: Dict[str, Dict[str, Path]] = {}
    for jf in js_files:
        try:
            text = jf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fs = str(jf.resolve())
        file_texts[fs] = text
        imap = _import_map(jf, text)
        file_imaps[fs] = imap
        for _, imported in imap.items():
            imp_str = str(imported.resolve())
            imported_by.setdefault(imp_str, []).append(fs)

    # Pass 2: cross-file + sinks
    multi_file_package = len(js_files) > 1
    pkg_json_path = str((target / "package.json").resolve()) if (target / "package.json").is_file() else None

    for jf in js_files:
        try:
            text = file_texts.get(str(jf.resolve())) or jf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        file_str = str(jf.resolve())
        imap = file_imaps.get(file_str, _import_map(jf, text))

        local = all_summaries.get(file_str, [])
        local_tainted = any(s.has_source or s.returns_tainted for s in local)
        local_sink = any(s.has_sink for s in local)

        evidence: List[str] = [file_str]
        cross = False
        frag_pattern: Optional[str] = None

        for binding, imported in imap.items():
            imp_str = str(imported.resolve())
            imp_summaries = all_summaries.get(imp_str, [])
            used_in_file = re.search(rf"\b{re.escape(binding)}\b", text) is not None
            if used_in_file or any(s.returns_tainted or s.has_source or s.has_sink for s in imp_summaries):
                local_tainted = True
                evidence.append(imp_str)
                cross = True

        # Require() present with sink = cross-file composition
        if imap and (local_sink or any(p.search(text) for p, _, _ in SINK_PATTERNS)):
            cross = True
            for _, imported in imap.items():
                evidence.append(str(imported.resolve()))

        # Lifecycle entry
        if graph.lifecycle_entries:
            if file_str in graph.lifecycle_entries or pkg_json_path:
                if any(s in graph.lifecycle_entries for s in [file_str]) or re.search(
                    r"postinstall|preinstall|prepare", text
                ):
                    pass
            if pkg_json_path and multi_file_package:
                pkg_data = ""
                try:
                    pkg_data = (target / "package.json").read_text(encoding="utf-8")
                except OSError:
                    pkg_data = ""
                if any(k in pkg_data for k in LIFECYCLE_SCRIPTS):
                    evidence.append(pkg_json_path)
                    cross = True
                    local_tainted = True

        if multi_file_package and imap:
            cross = True
            frag_pattern = frag_pattern or "multi.file.fragmentation"

        # Imported by other modules (callee file in cross-file chain)
        for parent in imported_by.get(file_str, []):
            evidence.append(parent)
            cross = True
            parent_text = file_texts.get(parent, "")
            if re.search(r"req\.(query|body|params)", parent_text) or "process.env" in parent_text:
                local_tainted = True

        evidence = list(dict.fromkeys(evidence))
        cross = cross or len(evidence) >= 2

        # String concat across requires → tainted
        if imap and (STRING_CONCAT_RE.search(text) or re.search(r"\beval\s*\(", text)):
            for binding in imap:
                if re.search(rf"\b{re.escape(binding)}\b", text):
                    local_tainted = True
                    cross = True

        # Detect sinks with taint
        for pat, sink_name, severity in SINK_PATTERNS:
            for m in pat.finditer(text):
                line = _line_of(text, m.start())
                has_sink_here = True
                if local_tainted or local_sink or (imap and has_sink_here):
                    if STRING_CONCAT_RE.search(text):
                        frag_pattern = "string.shard.reassembly"
                    if BASE64_RE.search(text):
                        frag_pattern = frag_pattern or "base64.shard.reassembly"
                    if cross:
                        frag_pattern = frag_pattern or "multi.file.fragmentation"
                    findings.append(
                        Finding(
                            rule_id=f"scsp/taint-{sink_name}",
                            severity=severity,
                            message=f"Tainted data reaches {sink_name}" + (" across files" if cross else ""),
                            file=file_str,
                            line=line,
                            cross_file=cross,
                            evidence_path=list(dict.fromkeys(evidence)),
                            fragmentation_pattern=frag_pattern,
                            status="DETECT",
                        )
                    )

        # Dynamic import — UNKNOWN_RISK
        if re.search(r"import\s*\(\s*[^'\"`]", text):
            findings.append(
                Finding(
                    rule_id="scsp/dynamic-import",
                    severity="HIGH",
                    message="Dynamic import expression — cannot resolve statically",
                    file=file_str,
                    line=1,
                    cross_file=False,
                    evidence_path=[file_str],
                    status="UNKNOWN_RISK",
                )
            )

        # Source without sink in same package — SUSPICIOUS for time bombs
        if local_tainted and not local_sink and not findings:
            source_rules_flat = [r for s in local for r in s.source_rules]
            if "time.trigger" in source_rules_flat:
                findings.append(
                    Finding(
                        rule_id="scsp/time-trigger",
                        severity="MEDIUM",
                        message="Time-based trigger with taint sources",
                        file=file_str,
                        line=1,
                        cross_file=cross,
                        evidence_path=evidence,
                        status="SUSPICIOUS",
                    )
                )

        # Wasm shard
        if re.search(r"WebAssembly", text) and BASE64_RE.search(text):
            findings.append(
                Finding(
                    rule_id="scsp/wasm-shard",
                    severity="HIGH",
                    message="WebAssembly load from sharded bytes",
                    file=file_str,
                    line=1,
                    cross_file=cross,
                    evidence_path=evidence,
                    status="UNKNOWN_RISK",
                )
            )

        # Async / Promise callback taint bridge
        if (PROMISE_CHAIN_RE.search(text) or ASYNC_AWAIT_RE.search(text)) and re.search(
            r"child_process|eval|exec|Function", text
        ):
            if local_tainted or imap or "process.env" in text:
                findings.append(
                    Finding(
                        rule_id="scsp/async-callback-taint",
                        severity="HIGH",
                        message="Async/Promise chain with execution sink and taint sources",
                        file=file_str,
                        line=1,
                        cross_file=cross,
                        evidence_path=evidence,
                        status="SUSPICIOUS",
                    )
                )

        # Deobfuscation signals
        from scsp.deobfuscate import detect_obfuscation_patterns

        for rule_id, msg in detect_obfuscation_patterns(text):
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity="MEDIUM",
                    message=msg,
                    file=file_str,
                    line=1,
                    cross_file=False,
                    evidence_path=[file_str],
                    status="SUSPICIOUS",
                )
            )

    # Heuristic pass
    findings.extend(_heuristic_findings(target, js_files, file_texts))

    # Unicode / steganography layer
    from scsp.unicode_scan import scan_unicode_directory

    for uf in scan_unicode_directory(target):
        findings.append(
            Finding(
                rule_id=uf.rule_id,
                severity=uf.severity,
                message=uf.message,
                file=uf.file,
                line=uf.line,
                cross_file=False,
                evidence_path=[uf.file],
                status=uf.status,
            )
        )

    # GYP / install surfaces
    from scsp.gyp_scan import scan_install_surfaces

    for gf in scan_install_surfaces(target):
        findings.append(
            Finding(
                rule_id=gf.rule_id,
                severity=gf.severity,
                message=gf.message,
                file=gf.file,
                line=gf.line,
                cross_file=False,
                evidence_path=[gf.file],
                status=gf.status,
            )
        )

    # IOC layer
    from scsp.ioc_match import scan_ioc

    for ir in scan_ioc(target):
        findings.append(
            Finding(
                rule_id=ir["rule_id"],
                severity=ir["severity"],
                message=ir["message"],
                file=ir.get("file", str(target)),
                line=1,
                cross_file=False,
                evidence_path=[ir.get("file", str(target))],
                status=ir.get("status", "SUSPICIOUS"),
            )
        )

    # Env-gated dormant (symbolic)
    from scsp.symbolic_env import scan_symbolic_env

    for sf in scan_symbolic_env(target, file_texts):
        findings.append(sf)

    # Transitive dependency risk
    from scsp.transitive_deps import scan_transitive_risk

    for tr in scan_transitive_risk(target):
        findings.append(
            Finding(
                rule_id=tr["rule_id"],
                severity=tr["severity"],
                message=tr["message"],
                file=str((target / "package.json").resolve()) if (target / "package.json").is_file() else str(target),
                line=1,
                cross_file=True,
                evidence_path=tr.get("evidence_path", []),
                status=tr.get("status", "SUSPICIOUS"),
            )
        )

    # Deduplicate
    seen: Set[tuple] = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    meta = {"build_graph": graph.to_dict(), "files_scanned": len(js_files)}
    return unique, meta


def scan_with_nyx_fallback(target: Path, nyx_path: Optional[str] = None) -> Tuple[List[Finding], dict, str]:
    """Try nyx if available, always run built-in for fragmentation rules."""
    engine = "scsp-builtin"
    builtin_findings, meta = scan_directory(target)

    if nyx_path:
        import json
        import subprocess
        import tempfile

        try:
            with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
                out = tmp.name
            subprocess.run(
                [nyx_path, "scan", str(target), "--format", "sarif", "-o", out],
                check=False,
                capture_output=True,
                timeout=120,
            )
            engine = "nyx+scsp"
            meta["nyx_sarif"] = out
        except (OSError, subprocess.TimeoutExpired):
            engine = "scsp-builtin"

    return builtin_findings, meta, engine
