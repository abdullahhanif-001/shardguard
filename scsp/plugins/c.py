"""C/C++ language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"getenv\s*\("), "getenv"),
    (re.compile(r"argv\s*\["), "argv"),
    (re.compile(r"read\s*\("), "read"),
    (re.compile(r"recv\s*\("), "network.in"),
]

SINK_PATTERNS = [
    (re.compile(r"\b(system|popen|exec[lvpe]?)\s*\("), "command.exec", "CRITICAL"),
    (re.compile(r"\b(strcpy|strcat|sprintf|gets)\s*\("), "buffer.overflow", "CRITICAL"),
    (re.compile(r"\b(malloc|free|realloc)\s*\("), "memory", "HIGH"),
]

IMPORT_RE = re.compile(r'#include\s*[<"]([^>"]+)[>"]')


class CPlugin(BasePlugin):
    name = "c"
    extensions = [".c", ".cpp", ".cc", ".h", ".hpp"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
