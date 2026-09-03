"""Python language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"os\.environ"), "os.environ"),
    (re.compile(r"sys\.argv"), "sys.argv"),
    (re.compile(r"input\s*\("), "input"),
    (re.compile(r"request\.(args|form|json|data)"), "flask.request"),
    (re.compile(r"open\s*\("), "file.read"),
]

SINK_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval", "CRITICAL"),
    (re.compile(r"\bexec\s*\("), "exec", "CRITICAL"),
    (re.compile(r"subprocess\.(run|Popen|call)"), "subprocess", "CRITICAL"),
    (re.compile(r"os\.system\s*\("), "os.system", "CRITICAL"),
    (re.compile(r"pickle\.loads"), "pickle", "HIGH"),
    (re.compile(r"__import__\s*\("), "dynamic.import", "HIGH"),
]

IMPORT_RE = re.compile(r"(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))")


class PythonPlugin(BasePlugin):
    name = "python"
    extensions = [".py"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
