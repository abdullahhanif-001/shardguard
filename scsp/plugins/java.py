"""Java language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"System\.getenv"), "env"),
    (re.compile(r"getParameter"), "http.param"),
    (re.compile(r"readLine\s*\("), "input"),
]

SINK_PATTERNS = [
    (re.compile(r"Runtime\.getRuntime\(\)\.exec"), "exec", "CRITICAL"),
    (re.compile(r"ProcessBuilder"), "process", "CRITICAL"),
    (re.compile(r"ObjectInputStream"), "deserialization", "HIGH"),
    (re.compile(r"ScriptEngine"), "script.eval", "HIGH"),
]

IMPORT_RE = re.compile(r"import\s+([\w.]+)")


class JavaPlugin(BasePlugin):
    name = "java"
    extensions = [".java"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
