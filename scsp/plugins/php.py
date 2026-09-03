"""PHP language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"\$_GET\b|\$_POST\b|\$_REQUEST\b|\$_COOKIE\b"), "superglobal.input"),
    (re.compile(r"\$_SERVER\b|\$_ENV\b"), "superglobal.server"),
    (re.compile(r"file_get_contents\s*\("), "file.read"),
]

SINK_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval", "CRITICAL"),
    (re.compile(r"\bexec\s*\("), "exec", "CRITICAL"),
    (re.compile(r"\bsystem\s*\("), "system", "CRITICAL"),
    (re.compile(r"\bshell_exec\s*\("), "shell_exec", "CRITICAL"),
    (re.compile(r"\binclude\s*\(\s*\$"), "include.taint", "HIGH"),
    (re.compile(r"mysqli?_.*query\s*\(.*\."), "sql.concat", "HIGH"),
    (re.compile(r"echo\s+\$"), "xss.echo", "HIGH"),
]

IMPORT_RE = re.compile(r"(?:require|include)(?:_once)?\s*[\('\"]([^'\"]+)")


class PHPPlugin(BasePlugin):
    name = "php"
    extensions = [".php"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
