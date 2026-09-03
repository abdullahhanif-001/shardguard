"""Shell language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"\$1|\$@|\$\*"), "argv"),
    (re.compile(r"\$\{?[A-Za-z_][\w]*\}?"), "env.var"),
    (re.compile(r"read\s+-"), "read.input"),
]

SINK_PATTERNS = [
    (re.compile(r"curl\s+[^|]*\|\s*(ba)?sh"), "curl-pipe-sh", "CRITICAL"),
    (re.compile(r"wget\s+.*\|\s*(ba)?sh"), "wget-pipe-sh", "CRITICAL"),
    (re.compile(r"\beval\s+"), "eval", "CRITICAL"),
    (re.compile(r"`[^`]+`"), "backtick", "CRITICAL"),
    (re.compile(r"\$\([^)]+\)"), "command.subst", "HIGH"),
]

IMPORT_RE = re.compile(r"source\s+([^\s;]+)|\.\s+([^\s;]+)")


class ShellPlugin(BasePlugin):
    name = "shell"
    extensions = [".sh", ".bash"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
