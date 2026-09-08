"""What the CDP bridge says on each side of the wire, read from its source with `ast`.

The bridge translates between two protocols. Everything it does with a protocol name falls into
one of four roles, each checked against the spec that governs it:

- a CDP method it handles itself (the handler tables)      -> must be a real CDP method
- a WebKit event it translates (the dispatch table)        -> must be a real WebKit event
- a message it sends the device (`_send_message_to_target`, `send_message_with_result`, ...)
                                                           -> a real WebKit command, with real parameters
- an event it emits to the editor (`output_queue.put`, `_send_event`, ...)
                                                           -> a real CDP event

Classification is by the enclosing call in the AST, not by text, so it cannot mistake a method
rename sent to the device for an event emitted to the editor. Names in neither spec are typos or
undocumented inventions, and are reported as such.
"""

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, cast

REPO = Path(__file__).resolve().parents[3]
SOURCES = [
    REPO / "pymobiledevice3/services/web_protocol/cdp_target.py",
    REPO / "pymobiledevice3/services/web_protocol/cdp_browser.py",
    REPO / "pymobiledevice3/services/web_protocol/cdp_server.py",
]
SPECS = Path(__file__).resolve().parent / "protocol"
NAME = re.compile(r"^[A-Z][A-Za-z]+\.[a-z][A-Za-z]+$")

WEBKIT_BOUND_CALLS = {
    "_send_message_to_target",
    "send_message_with_result",
    "send_message_with_result_across_swaps",
    "_forward_and_translate",
    "send_command",
    "_send_message_flat",
}
CLIENT_BOUND_CALLS = {"put", "_send_event", "_send", "append", "send_json"}
WEBKIT_EVENT_TABLES = {"to_cdp_special_dispatched_messages_methods", "to_cdp_special_messages_methods"}


@dataclass
class Send:
    method: str
    params: Optional[frozenset[str]]  # literal parameter keys, or None when not a literal dict
    where: str


@dataclass
class Inventory:
    client_handled: dict[str, str] = field(default_factory=dict)  # CDP method -> table
    webkit_events_handled: dict[str, str] = field(default_factory=dict)
    webkit_bound: list[Send] = field(default_factory=list)
    client_bound_events: list[Send] = field(default_factory=list)
    all_names: dict[str, set[str]] = field(default_factory=dict)  # name -> files
    constants: dict[str, set[str]] = field(default_factory=dict)  # module-level NAME = frozenset({...}) / {...: ...}


def _const_str(node: ast.AST) -> Optional[str]:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _dict_get(d: ast.Dict, key: str) -> Optional[ast.AST]:
    for k, v in zip(d.keys, d.values):
        if k is not None and _const_str(k) == key:
            return v
    return None


def _literal_keys(node: Optional[ast.AST]) -> Optional[frozenset[str]]:
    if not isinstance(node, ast.Dict):
        return None
    keys: set[str] = set()
    for k in node.keys:
        if k is None:  # **spread - not fully literal
            return None
        s = _const_str(k)
        if s is None:
            return None
        keys.add(s)
    return frozenset(keys)


def _func_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def _enclosing(node: ast.AST, parents: dict[int, ast.AST]) -> str:
    cur: Optional[ast.AST] = node
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur.name
        cur = parents.get(id(cur))
    return "<module>"


def _message_dicts(node: ast.AST) -> list[ast.Dict]:
    """Dict literals carrying a "method" key, anywhere under `node`."""
    return [d for d in ast.walk(node) if isinstance(d, ast.Dict) and _dict_get(d, "method") is not None]


def collect() -> Inventory:
    inv = Inventory()
    for path in SOURCES:
        text = path.read_text()
        tree = ast.parse(text)
        parents: dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent
        for statement in tree.body:
            # module-level string sets and string-keyed dicts: NAME = frozenset({...}) / NAME = {...}
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                target = statement.targets[0] if isinstance(statement, ast.Assign) else statement.target
                value = statement.value
                if isinstance(value, ast.Call) and _func_name(value) == "frozenset" and value.args:
                    value = value.args[0]
                if isinstance(target, ast.Name) and isinstance(value, (ast.Set, ast.Dict)):
                    elements = value.keys if isinstance(value, ast.Dict) else value.elts
                    strings = [_const_str(e) for e in elements if e is not None]
                    if strings and all(strings):
                        inv.constants[target.id] = {cast(str, x) for x in strings}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and NAME.match(node.value):
                inv.all_names.setdefault(node.value, set()).add(path.name)
            # a method rename before a forward: message["method"] = "Domain.name"  -> sent to WebKit
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                for target in targets:
                    if (
                        isinstance(target, ast.Subscript)
                        and _const_str(target.slice) == "method"
                        and value is not None
                        and _const_str(value)
                        and NAME.match(_const_str(value) or "")
                    ):
                        inv.webkit_bound.append(Send(cast(str, _const_str(value)), None, _enclosing(node, parents)))
            # handler / dispatch tables: self.<table> = { "Domain.name": ..., }  (plain or annotated)
            table_value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
            if isinstance(table_value, ast.Dict):
                target = (
                    node.targets[0]
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    else (node.target if isinstance(node, ast.AnnAssign) else None)
                )
                node = cast(Any, node)
                node.value = table_value
                if target is None:
                    continue
                attr = (
                    target.attr
                    if isinstance(target, ast.Attribute)
                    else (target.id if isinstance(target, ast.Name) else "")
                )
                keys = [s for s in (_const_str(k) for k in table_value.keys if k is not None) if s and NAME.match(s)]
                if not keys:
                    continue
                if attr in WEBKIT_EVENT_TABLES:
                    for k in keys:
                        inv.webkit_events_handled[k] = attr
                elif all(isinstance(v, (ast.Attribute, ast.Call, ast.Name)) for v in table_value.values):
                    # any other Domain.name-keyed table of callables is a client handler table
                    for k in keys:
                        inv.client_handled.setdefault(k, attr)
            if isinstance(node, ast.Call):
                name = _func_name(node)
                where = _enclosing(node, parents)
                if name in WEBKIT_BOUND_CALLS:
                    if (
                        name in ("send_message_with_result", "send_message_with_result_across_swaps", "send_command")
                        and node.args
                    ):
                        method = _const_str(node.args[0])
                        if method:
                            params = (
                                _literal_keys(node.args[1])
                                if len(node.args) > 1
                                else frozenset(kw.arg for kw in node.keywords if kw.arg)
                            )
                            inv.webkit_bound.append(Send(method, params, where))
                            continue
                    for d in [
                        a for a in list(node.args) + [kw.value for kw in node.keywords] for a in _message_dicts(a)
                    ]:
                        method = _const_str(_dict_get(d, "method") or ast.Constant(value=None))
                        if method:
                            inv.webkit_bound.append(Send(method, _literal_keys(_dict_get(d, "params")), where))
                elif name in CLIENT_BOUND_CALLS:
                    if name == "_send_event" and node.args:
                        method = _const_str(node.args[0])
                        if method:
                            inv.client_bound_events.append(Send(method, None, where))
                            continue
                    for d in [a for a in node.args for a in _message_dicts(a)]:
                        method = _const_str(_dict_get(d, "method") or ast.Constant(value=None))
                        if method and NAME.match(method):
                            inv.client_bound_events.append(Send(method, None, where))
    return inv


def load_spec(name: str) -> dict[str, Any]:
    return json.loads((SPECS / f"{name}_protocol.json").read_text())["domains"]


def split(name: str) -> tuple[str, str]:
    domain, _, member = name.partition(".")
    return domain, member


def in_commands(spec: dict[str, Any], name: str) -> bool:
    d, m = split(name)
    return m in spec.get(d, {}).get("commands", {})


def in_events(spec: dict[str, Any], name: str) -> bool:
    d, m = split(name)
    return m in spec.get(d, {}).get("events", {})


def command_params(spec: dict[str, Any], name: str) -> dict[str, Any]:
    d, m = split(name)
    return spec.get(d, {}).get("commands", {}).get(m, {}).get("params", {})
