"""Optional tree-sitter IR lift with regex fallback."""

from __future__ import annotations

from pathlib import Path

from scsp.ir.schema import IRGraph, IRNode, IREdge, NodeKind
from scsp.plugins.registry import get_plugin_for_file


def _try_tree_sitter_lift(path: Path, plugin) -> IRGraph | None:
    try:
        from tree_sitter import Language, Parser  # type: ignore
    except ImportError:
        return None
    lang_name = plugin.name
    grammar_map = {
        "python": "tree_sitter_python",
        "javascript": "tree_sitter_javascript",
        "java": "tree_sitter_java",
        "go": "tree_sitter_go",
        "rust": "tree_sitter_rust",
        "c": "tree_sitter_c",
    }
    mod_name = grammar_map.get(lang_name)
    if not mod_name:
        return None
    try:
        import importlib

        mod = importlib.import_module(mod_name)
        lang = Language(mod.language())
    except Exception:
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    parser = Parser(lang)
    tree = parser.parse(text.encode())
    graph = IRGraph(language=lang_name)
    file_str = str(path.resolve())
    graph.add_node(IRNode(id=f"file:{file_str}", kind=NodeKind.FILE, file=file_str, label=path.name))

    def walk(node, depth: int = 0):
        if depth > 200:
            return
        ntype = node.type
        if ntype in ("function_definition", "method_definition", "function_declaration", "function_item"):
            name = "fn"
            for i in range(node.child_count):
                ch = node.child(i)
                if ch and ch.type in ("identifier", "property_identifier", "name"):
                    name = text[ch.start_byte : ch.end_byte]
                    break
            graph.add_node(
                IRNode(
                    id=f"method:{file_str}:{name}:{node.start_point[0]}",
                    kind=NodeKind.METHOD,
                    file=file_str,
                    line=node.start_point[0] + 1,
                    label=name,
                )
            )
        if ntype in ("call_expression", "call", "invocation_expression"):
            callee = "call"
            if node.child_count:
                ch = node.child(0)
                if ch:
                    callee = text[ch.start_byte : ch.end_byte][:40]
            line = node.start_point[0] + 1
            cid = f"call:{file_str}:{line}:{callee}"
            graph.add_node(IRNode(id=cid, kind=NodeKind.CALL, file=file_str, line=line, label=callee))
        if ntype in ("import_statement", "import_from_statement", "import_declaration", "import_spec"):
            spec = text[node.start_byte : node.end_byte][:80]
            line = node.start_point[0] + 1
            iid = f"imp:{file_str}:{line}:{spec[:20]}"
            graph.add_node(IRNode(id=iid, kind=NodeKind.IMPORT, file=file_str, line=line, label=spec))
            graph.add_edge(IREdge(src=iid, dst=f"file:{file_str}", kind="IMPORT"))
        for i in range(node.child_count):
            ch = node.child(i)
            if ch:
                walk(ch, depth + 1)

    walk(tree.root_node)
    return graph if graph.semantic_lift_ok() else None


def lift_file_enhanced(path: Path) -> IRGraph:
    plugin = get_plugin_for_file(path)
    if not plugin:
        return IRGraph(language="unknown")
    ts_graph = _try_tree_sitter_lift(path, plugin)
    if ts_graph is not None:
        return ts_graph
    return plugin.lift_ir(path)


def lift_directory_enhanced(root: Path, max_files: int = 500) -> list[IRGraph]:
    from scsp.plugins.registry import list_plugins

    exts = set()
    for p in list_plugins():
        exts.update(p.extensions)
    graphs: list[IRGraph] = []
    count = 0
    for fp in root.rglob("*"):
        if count >= max_files:
            break
        if not fp.is_file() or fp.suffix.lower() not in exts:
            continue
        if "node_modules" in fp.parts:
            continue
        graphs.append(lift_file_enhanced(fp))
        count += 1
    return graphs
