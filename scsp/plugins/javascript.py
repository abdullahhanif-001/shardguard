"""JavaScript/TypeScript plugin — wraps semantic lift from cross_file_taint patterns."""

from __future__ import annotations

import re
from pathlib import Path

from scsp.cross_file_taint import SOURCE_PATTERNS, SINK_PATTERNS
from scsp.plugins.base import BasePlugin

IMPORT_RE = re.compile(
    r"(?:require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)|import\s+.*?from\s+['\"]([^'\"]+)['\"])"
)


class JavaScriptPlugin(BasePlugin):
    name = "javascript"
    extensions = [".js", ".mjs", ".cjs", ".ts", ".tsx"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE

    def resolve_import(self, base: Path, spec: str) -> Path | None:
        from scsp.build_graph import resolve_import

        return resolve_import(base, spec)
