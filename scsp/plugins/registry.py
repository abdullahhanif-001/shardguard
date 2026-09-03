"""Plugin registry."""

from __future__ import annotations

from pathlib import Path

from scsp.plugins.base import LanguagePlugin
from scsp.plugins.c import CPlugin
from scsp.plugins.csharp import CSharpPlugin
from scsp.plugins.go import GoPlugin
from scsp.plugins.java import JavaPlugin
from scsp.plugins.javascript import JavaScriptPlugin
from scsp.plugins.kotlin import KotlinPlugin
from scsp.plugins.php import PHPPlugin
from scsp.plugins.python import PythonPlugin
from scsp.plugins.ruby import RubyPlugin
from scsp.plugins.rust import RustPlugin
from scsp.plugins.shell import ShellPlugin
from scsp.plugins.swift import SwiftPlugin

_PLUGINS: list[LanguagePlugin] = [
    JavaScriptPlugin(),
    PythonPlugin(),
    GoPlugin(),
    RustPlugin(),
    JavaPlugin(),
    CPlugin(),
    PHPPlugin(),
    RubyPlugin(),
    CSharpPlugin(),
    KotlinPlugin(),
    SwiftPlugin(),
    ShellPlugin(),
]

_EXT_MAP: dict[str, LanguagePlugin] = {}
for p in _PLUGINS:
    for ext in p.extensions:
        _EXT_MAP[ext.lower()] = p


def list_plugins() -> list[LanguagePlugin]:
    return list(_PLUGINS)


def get_plugin_for_file(path: Path) -> LanguagePlugin | None:
    return _EXT_MAP.get(path.suffix.lower())
