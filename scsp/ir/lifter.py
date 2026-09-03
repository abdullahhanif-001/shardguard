"""IR lift orchestrator across language plugins."""

from __future__ import annotations

from pathlib import Path

from scsp.ir.schema import IRGraph
from scsp.plugins.registry import get_plugin_for_file, list_plugins


def lift_file(path: Path) -> IRGraph | None:
    plugin = get_plugin_for_file(path)
    if not plugin:
        return None
    return plugin.lift_ir(path)


def lift_directory(root: Path, max_files: int = 500) -> list[IRGraph]:
    graphs: list[IRGraph] = []
    count = 0
    for plugin in list_plugins():
        for ext in plugin.extensions:
            pattern = f"*{ext}"
            for p in root.rglob(pattern):
                if count >= max_files:
                    return graphs
                if "node_modules" in p.parts:
                    continue
                g = lift_file(p)
                if g and g.nodes:
                    graphs.append(g)
                    count += 1
    return graphs
