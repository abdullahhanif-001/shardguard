"""Swift language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"ProcessInfo\.processInfo\.environment"), "process.env"),
    (re.compile(r"URL\(string:"), "url.input"),
    (re.compile(r"UserDefaults"), "userdefaults"),
]

SINK_PATTERNS = [
    (re.compile(r"NSTask|Process\s*\("), "process.exec", "CRITICAL"),
    (re.compile(r"evaluateJavaScript"), "webview.js", "HIGH"),
    (re.compile(r"NSKeyedUnarchiver"), "deser", "HIGH"),
    (re.compile(r"open\s*\(\s*url"), "url.open", "MEDIUM"),
]

IMPORT_RE = re.compile(r"import\s+([\w.]+)")


class SwiftPlugin(BasePlugin):
    name = "swift"
    extensions = [".swift"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
