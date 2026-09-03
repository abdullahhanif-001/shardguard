"""Ruby language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"\bparams\s*\[|\bparams\."), "rails.params"),
    (re.compile(r"\bENV\s*\["), "ENV"),
    (re.compile(r"\bARGV\b"), "ARGV"),
    (re.compile(r"request\.(query|body|params)"), "rack.request"),
]

SINK_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval", "CRITICAL"),
    (re.compile(r"\bsystem\s*\("), "system", "CRITICAL"),
    (re.compile(r"`[^`]+`"), "backtick", "CRITICAL"),
    (re.compile(r"\bexec\s*\("), "exec", "CRITICAL"),
    (re.compile(r"\.send\s*\("), "send.dynamic", "HIGH"),
    (re.compile(r"Marshal\.load"), "marshal.load", "CRITICAL"),
    (re.compile(r"ERB\.new|erb\s*<<"), "erb.xss", "HIGH"),
]

IMPORT_RE = re.compile(r"require\s+['\"]([^'\"]+)['\"]")


class RubyPlugin(BasePlugin):
    name = "ruby"
    extensions = [".rb"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
