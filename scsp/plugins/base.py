"""Language plugin protocol for universal IR lift."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Protocol, runtime_checkable

from scsp.ir.schema import IRGraph, IRNode, NodeKind
from scsp.sandbox import safe_read_text


@runtime_checkable
class LanguagePlugin(Protocol):
    name: str
    extensions: list[str]

    def lift_ir(self, path: Path) -> IRGraph: ...
    def resolve_import(self, base: Path, spec: str) -> Path | None: ...


class BasePlugin(ABC):
    name: str = "base"
    extensions: list[str] = []

  # Source/sink patterns per language — subclasses override
    SOURCE_PATTERNS: list[tuple[re.Pattern, str]] = []
    SINK_PATTERNS: list[tuple[re.Pattern, str, str]] = []
    IMPORT_RE: re.Pattern | None = None
    CALL_RE: re.Pattern = re.compile(r"(\w+)\s*\(")

    def lift_ir(self, path: Path) -> IRGraph:
        graph = IRGraph(language=self.name)
        text = safe_read_text(path)
        if text is None:
            return graph
        file_str = str(path.resolve())
        graph.add_node(IRNode(id=f"file:{file_str}", kind=NodeKind.FILE, file=file_str, label=path.name))

        for i, line in enumerate(text.splitlines(), 1):
            for pat, label in self.SOURCE_PATTERNS:
                if pat.search(line):
                    graph.add_node(
                        IRNode(
                            id=f"src:{file_str}:{i}:{label}",
                            kind=NodeKind.SOURCE,
                            file=file_str,
                            line=i,
                            label=label,
                        )
                    )
            for pat, label, _sev in self.SINK_PATTERNS:
                if pat.search(line):
                    graph.add_node(
                        IRNode(
                            id=f"sink:{file_str}:{i}:{label}",
                            kind=NodeKind.SINK,
                            file=file_str,
                            line=i,
                            label=label,
                        )
                    )
            if self.IMPORT_RE:
                for m in self.IMPORT_RE.finditer(line):
                    spec = m.group(1) if m.lastindex else m.group(0)
                    graph.add_node(
                        IRNode(
                            id=f"imp:{file_str}:{i}:{spec}",
                            kind=NodeKind.IMPORT,
                            file=file_str,
                            line=i,
                            label=spec,
                        )
                    )
            for m in self.CALL_RE.finditer(line):
                graph.add_node(
                    IRNode(
                        id=f"call:{file_str}:{i}:{m.group(1)}",
                        kind=NodeKind.CALL,
                        file=file_str,
                        line=i,
                        label=m.group(1),
                    )
                )
        return graph

    def resolve_import(self, base: Path, spec: str) -> Path | None:
        return None
