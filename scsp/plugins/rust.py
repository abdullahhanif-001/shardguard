"""Rust language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"std::env::"), "env"),
    (re.compile(r"std::fs::read"), "file.read"),
    (re.compile(r"req\."), "http.request"),
]

SINK_PATTERNS = [
    (re.compile(r"Command::new"), "command.exec", "CRITICAL"),
    (re.compile(r"std::process::"), "process", "HIGH"),
    (re.compile(r"unsafe\s*\{"), "unsafe.block", "HIGH"),
]

IMPORT_RE = re.compile(r"use\s+([\w:]+)")


class RustPlugin(BasePlugin):
    name = "rust"
    extensions = [".rs"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
