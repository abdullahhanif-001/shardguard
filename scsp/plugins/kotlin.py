"""Kotlin language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"intent\.(getStringExtra|getData)"), "android.intent"),
    (re.compile(r"System\.getenv"), "env"),
    (re.compile(r"readLine\s*\("), "stdin"),
]

SINK_PATTERNS = [
    (re.compile(r"Runtime\.getRuntime\(\)\.exec"), "runtime.exec", "CRITICAL"),
    (re.compile(r"loadUrl\s*\("), "webview.loadurl", "HIGH"),
    (re.compile(r"ObjectInputStream"), "deser", "HIGH"),
    (re.compile(r"eval\s*\("), "eval", "CRITICAL"),
]

IMPORT_RE = re.compile(r"import\s+([\w.]+)")


class KotlinPlugin(BasePlugin):
    name = "kotlin"
    extensions = [".kt", ".kts"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
