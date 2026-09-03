"""C# language plugin."""

from __future__ import annotations

import re

from scsp.plugins.base import BasePlugin

SOURCE_PATTERNS = [
    (re.compile(r"Request\.(Query|Form|Body|Cookies)"), "aspnet.request"),
    (re.compile(r"Console\.ReadLine"), "console.input"),
    (re.compile(r"Environment\.GetEnvironmentVariable"), "env.var"),
]

SINK_PATTERNS = [
    (re.compile(r"Process\.Start\s*\("), "process.start", "CRITICAL"),
    (re.compile(r"BinaryFormatter|ObjectStateFormatter"), "deser.unsafe", "CRITICAL"),
    (re.compile(r"SqlCommand.*\+|string\.Format.*SELECT"), "sql.concat", "HIGH"),
    (re.compile(r"MD5\.Create|SHA1\.Create|DES\.Create"), "weak.crypto", "MEDIUM"),
    (re.compile(r"HttpClient\.GetStringAsync\s*\(\s*\$"), "ssrf", "HIGH"),
]

IMPORT_RE = re.compile(r"using\s+([\w.]+)")


class CSharpPlugin(BasePlugin):
    name = "csharp"
    extensions = [".cs"]
    SOURCE_PATTERNS = SOURCE_PATTERNS
    SINK_PATTERNS = SINK_PATTERNS
    IMPORT_RE = IMPORT_RE
