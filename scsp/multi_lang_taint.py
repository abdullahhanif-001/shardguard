"""Cross-file taint for Python, Java, Go (v2)."""

from __future__ import annotations

import re
from pathlib import Path

from scsp.cross_file_taint import Finding, SOURCE_PATTERNS as JS_SOURCES, SINK_PATTERNS as JS_SINKS
from scsp.lanes.types import LaneFinding

PY_IMPORT = re.compile(r"from\s+([\w.]+)\s+import|import\s+([\w.]+)")
JAVA_IMPORT = re.compile(r"import\s+([\w.]+)")
GO_IMPORT = re.compile(r"import\s+(?:\([\w\s\"/]+\)|\"([^\"]+)\")")

LANG_CONFIG = {
    ".py": {
        "import_re": PY_IMPORT,
        "sources": [
            (re.compile(r"os\.environ|sys\.argv|input\s*\(|request\."), "py.source"),
        ],
        "sinks": [
            (re.compile(r"\beval\s*\(|\bexec\s*\(|os\.system|subprocess\."), "py.sink", "CRITICAL"),
        ],
    },
    ".java": {
        "import_re": JAVA_IMPORT,
        "sources": [(re.compile(r"getParameter|request\.|System\.getenv"), "java.source")],
        "sinks": [
            (re.compile(r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder|ObjectInputStream"), "java.sink", "CRITICAL"),
        ],
    },
    ".go": {
        "import_re": GO_IMPORT,
        "sources": [(re.compile(r"os\.Getenv|flag\.|r\.URL\.Query"), "go.source")],
        "sinks": [
            (re.compile(r"exec\.Command|os\.StartProcess|template\.HTML"), "go.sink", "CRITICAL"),
        ],
    },
}


def _scan_single_lang_file(path: Path, cfg: dict) -> tuple[bool, bool, list[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    has_src = has_sink = False
    rules: list[str] = []
    for i, line in enumerate(text.splitlines(), 1):
        for pat, label in cfg["sources"]:
            if pat.search(line):
                has_src = True
                rules.append(label)
        for pat, label, _ in cfg["sinks"]:
            if pat.search(line):
                has_sink = True
                rules.append(label)
    return has_src, has_sink, rules


def scan_multi_lang_directory(target: Path) -> list[LaneFinding]:
    findings: list[LaneFinding] = []
    files_by_lang: dict[str, list[Path]] = {}
    for fp in target.rglob("*"):
        if not fp.is_file():
            continue
        ext = fp.suffix.lower()
        if ext in LANG_CONFIG:
            files_by_lang.setdefault(ext, []).append(fp)

    for ext, files in files_by_lang.items():
        cfg = LANG_CONFIG[ext]
        importers: dict[str, list[Path]] = {}
        for fp in files:
            text = fp.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                m = cfg["import_re"].search(line)
                if m:
                    spec = next(g for g in m.groups() if g)
                    importers.setdefault(spec.split(".")[-1], []).append(fp)
        for fp in files:
            src, sink, rules = _scan_single_lang_file(fp, cfg)
            if src and sink:
                findings.append(
                    LaneFinding(
                        rule_id=f"urns/crosslang-{ext[1:]}-intra",
                        severity="HIGH",
                        message=f"Same-file source+sink ({ext})",
                        file=str(fp.resolve()),
                        lane="supply_chain",
                        tier="P1",
                        status="DETECT",
                    )
                )
        for spec, importers_list in importers.items():
            for fp in files:
                if fp in importers_list:
                    continue
                src, _, _ = _scan_single_lang_file(fp, cfg)
                for imp_fp in importers_list:
                    _, sink, _ = _scan_single_lang_file(imp_fp, cfg)
                    if src and sink:
                        findings.append(
                            LaneFinding(
                                rule_id=f"urns/crosslang-{ext[1:]}-inter",
                                severity="CRITICAL",
                                message=f"Cross-file taint {fp.name} -> {imp_fp.name}",
                                file=str(imp_fp.resolve()),
                                lane="supply_chain",
                                tier="P0",
                                cross_file=True,
                                evidence_path=[str(fp.resolve()), str(imp_fp.resolve())],
                                status="DETECT",
                            )
                        )
    return findings


def crosslang_recall_on_corpus(corpus: Path) -> tuple[float, int]:
    if not corpus.is_dir():
        return 0.0, 0
    import json

    cases: list[Path] = []
    if (corpus / "expected.json").is_file():
        cases = [corpus]
    else:
        cases = [d for d in sorted(corpus.iterdir()) if d.is_dir() and (d / "expected.json").is_file()]
    tp = n = 0
    for case in cases:
        exp_f = case / "expected.json"
        if not exp_f.is_file():
            continue
        n += 1
        exp = json.loads(exp_f.read_text())
        from scsp.universal_scan import scan_universal

        findings, _, _ = scan_universal(case)
        from scsp.multi_lang_taint import scan_multi_lang_directory

        ml = scan_multi_lang_directory(case)
        all_f = findings + ml
        if exp.get("verdict") == "DETECT":
            min_d = exp.get("min_detect", 1)
            detects = [f for f in all_f if f.status in ("DETECT", "SUSPICIOUS") or f.tier in ("P0", "P1")]
            if len(detects) >= min_d:
                tp += 1
        else:
            tp += 1
    return tp / max(n, 1), n
