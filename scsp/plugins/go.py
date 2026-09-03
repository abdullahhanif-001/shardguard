"""Go language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"os\.Getenv"), "os.Getenv"),
    (re.compile(r"os\.Args"), "os.Args"),
    (re.compile(r"http\.Request"), "http.request"),
    (re.compile(r"ioutil\.ReadFile|os\.ReadFile"), "file.read"),
]

SINK_PATTERNS = [
    (re.compile(r"exec\.Command"), "exec.Command", "CRITICAL"),
    (re.compile(r"syscall\."), "syscall", "HIGH"),
    (re.compile(r"unsafe\."), "unsafe", "HIGH"),
    (re.compile(r"template\.HTML"), "xss.sink", "MEDIUM"),
]

IMPORT_RE = re.compile(r'import\s+(?:\(\s*)?["\']([^"\']+)["\']')


class GoPlugin(BasePlugin):
    name = "go"
    extensions = [".go"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
