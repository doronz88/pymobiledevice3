"""Conversions behind Chrome DevTools' Memory and Performance panels.

WebKit and V8 expose the same three things - a heap snapshot, sampled call stacks and a record of
what the main thread did - in different shapes. Chrome's frontend only reads V8's, so the bridge
reshapes WebKit's payloads into them:

- ``Heap.snapshot`` (WebKit's "Inspector" heap snapshot, a version-3 JSON document, see
  JavaScriptCore/heap/HeapSnapshotBuilder.cpp) becomes V8's heap snapshot as
  ``HeapProfiler.takeHeapSnapshot`` streams it.
- ``ScriptProfiler.trackingComplete`` samples (stack traces, innermost frame first, in stopwatch
  seconds) become a ``Profiler.Profile`` call tree with per-sample time deltas.
- ``Timeline.eventRecorded`` records (a tree per rendering frame, in stopwatch seconds) become the
  trace events ``Tracing.dataCollected`` delivers, in the categories and payload shapes the
  frontend's trace handlers key on.

Everything here is pure: dicts in, dicts out, no protocol I/O.
"""

import json
from collections.abc import Collection, Iterator
from typing import Any, Optional

# V8 heap snapshot layout, as the frontend's HeapSnapshotWorker reads it from `snapshot.meta`.
V8_NODE_FIELDS = ("type", "name", "id", "self_size", "edge_count", "trace_node_id", "detachedness")
V8_NODE_TYPES = (
    "hidden",
    "array",
    "string",
    "object",
    "code",
    "closure",
    "regexp",
    "number",
    "native",
    "synthetic",
    "concatenated string",
    "sliced string",
    "symbol",
    "bigint",
    "object shape",
)
V8_EDGE_FIELDS = ("type", "name_or_index", "to_node")
V8_EDGE_TYPES = ("context", "element", "property", "internal", "hidden", "shortcut", "weak")

# WebKit node flags (HeapSnapshotBuilder.cpp).
_NODE_FLAG_INTERNAL = 1 << 0

# WebKit class names with a V8 node type of their own. Everything else is an "object" (a JS
# value the user can reason about) or, when flagged internal, engine machinery: compiled code
# for the executables and code blocks, "hidden" for the rest, which the frontend groups as
# "(system)" just as it does V8's own internals.
_CLASS_NODE_TYPES = {
    "<root>": "synthetic",
    "string": "string",
    "symbol": "symbol",
    "Function": "closure",
    "GeneratorFunction": "closure",
    "AsyncFunction": "closure",
    "AsyncGeneratorFunction": "closure",
    "RegExp": "regexp",
    "Structure": "object shape",
}
_CODE_CLASS_SUFFIXES = ("Executable", "CodeBlock")

# WebKit edge type -> V8 edge type.
_EDGE_TYPES = {"Internal": "internal", "Property": "property", "Index": "element", "Variable": "context"}

# Frames of WebKit's own inspector machinery, at the bottom of every stack sampled while the
# console evaluates something: the injected script's wrapper (`_wrapCall` and its anonymous
# callee) and the native evaluate that runs the expression. Chrome shows no such frames, so they
# are stripped from the outer end of a stack; a sample entirely inside them (the injected
# script being built) is VM time, which Chrome names "(program)".
INSPECTOR_FRAME_NAMES = frozenset({
    "createInspectorInjectedScript",
    "InjectedScript",
    "_wrapCall",
    "evaluateWithScopeExtension",
})
INSPECTOR_URL_MARKERS = ("__InjectedScript", "__WebInspector")

ROOT_NODE_ID = 1

# WebKit's sampling profiler takes a stack about every millisecond, and only while JavaScript
# runs; between two runs of script it takes none. Chrome charges the time up to the next sample
# to the sampled frame, so a gap longer than a few sampling intervals would show idle time as
# script. Such a gap gets a synthetic idle sample one interval after the frame's own sample.
SAMPLE_INTERVAL = 0.001
IDLE_GAP = 0.005

# Trace-event categories the frontend filters on.
_CAT_TIMELINE = "devtools.timeline"
_CAT_TIMELINE_DISABLED = "disabled-by-default-devtools.timeline"
_CAT_SCREENSHOT = "disabled-by-default-devtools.screenshot"
_CAT_CPU_PROFILE = "disabled-by-default-v8.cpu_profiler"
_CAT_CONSOLE = "blink.console"
_CAT_LOADING = "loading,rail,devtools.timeline"

# Chrome's process/thread layout as the frontend's MetaHandler expects it: the browser process
# announces tracing and the renderer's frames; the renderer's main thread carries the work.
BROWSER_THREAD_ID = 1
RENDERER_MAIN_THREAD_ID = 1


class _Strings:
    """An interning string table, as V8's snapshot carries one."""

    def __init__(self) -> None:
        self.values: list[str] = []
        self._index: dict[str, int] = {}

    def __call__(self, value: str) -> int:
        index = self._index.get(value)
        if index is None:
            index = len(self.values)
            self.values.append(value)
            self._index[value] = index
        return index


def _node_type(class_name: str, flags: int) -> str:
    known = _CLASS_NODE_TYPES.get(class_name)
    if known is not None:
        return known
    if flags & _NODE_FLAG_INTERNAL:
        return "code" if class_name.endswith(_CODE_CLASS_SUFFIXES) else "hidden"
    return "object"


def convert_heap_snapshot(webkit: dict[str, Any]) -> dict[str, Any]:
    """Reshape a WebKit "Inspector" heap snapshot into V8's heap snapshot document.

    Node ids are WebKit's, so an id the frontend hands back (HeapProfiler.getObjectByHeapObjectId)
    still names the object for Heap.getRemoteObject. WebKit's root stays first, as V8's root
    must be. Edges are regrouped under their source node in node order, with the per-node count
    V8 stores instead of the source id, and point at node array indexes as V8's do.
    """
    strings = _Strings()
    node_types = {name: index for index, name in enumerate(V8_NODE_TYPES)}
    edge_types = {name: index for index, name in enumerate(V8_EDGE_TYPES)}
    class_names: list[str] = webkit["nodeClassNames"]
    edge_names: list[str] = webkit["edgeNames"]
    webkit_edge_types: list[str] = webkit["edgeTypes"]

    raw_nodes: list[int] = webkit["nodes"]
    node_width = len(V8_NODE_FIELDS)
    node_index_of_id: dict[int, int] = {}
    for position, offset in enumerate(range(0, len(raw_nodes), 4)):
        node_index_of_id[raw_nodes[offset]] = position * node_width

    # Bucket edges by source id; WebKit lists them sorted by source id, V8 wants them in the
    # source node's array order.
    # WebKit repeats edges (the root in particular retains most objects several times over); the
    # frontend seeds its distance search with one entry per root edge and overflows when a
    # target recurs, so the root keeps one edge per target and every node one per distinct edge.
    raw_edges: list[int] = webkit["edges"]
    root_id = raw_nodes[0] if raw_nodes else 0
    edges_of: dict[int, list[tuple[int, int, int]]] = {}
    seen_of: dict[int, set[tuple[int, int, int]]] = {}
    internal_name = strings("")
    for offset in range(0, len(raw_edges), 4):
        source, target, type_index, extra = raw_edges[offset : offset + 4]
        to_node = node_index_of_id.get(target)
        if to_node is None:
            continue
        edge_type = _EDGE_TYPES.get(webkit_edge_types[type_index], "internal")
        if edge_type == "element":
            name_or_index = extra
        elif edge_type == "internal":
            name_or_index = internal_name
        else:
            name_or_index = strings(edge_names[extra])
        edge = (edge_types[edge_type], name_or_index, to_node)
        key = (0, 0, to_node) if source == root_id else edge
        seen = seen_of.setdefault(source, set())
        if key in seen:
            continue
        seen.add(key)
        edges_of.setdefault(source, []).append(edge)

    nodes: list[int] = []
    edges: list[int] = []
    for offset in range(0, len(raw_nodes), 4):
        node_id, size, class_index, flags = raw_nodes[offset : offset + 4]
        class_name = class_names[class_index]
        own_edges = edges_of.get(node_id, ())
        name = "(root)" if class_name == "<root>" else class_name
        nodes.extend((node_types[_node_type(class_name, flags)], strings(name), node_id, size, len(own_edges), 0, 0))
        for edge in own_edges:
            edges.extend(edge)

    return {
        "snapshot": {
            "meta": {
                "node_fields": list(V8_NODE_FIELDS),
                "node_types": [list(V8_NODE_TYPES), "string", "number", "number", "number", "number", "number"],
                "edge_fields": list(V8_EDGE_FIELDS),
                "edge_types": [list(V8_EDGE_TYPES), "string_or_number", "node"],
                "trace_function_info_fields": ["function_id", "name", "script_name", "script_id", "line", "column"],
                "trace_node_fields": ["id", "function_info_index", "count", "size", "children"],
                "sample_fields": ["timestamp_us", "last_assigned_id"],
                "location_fields": ["object_index", "script_id", "line", "column"],
            },
            "node_count": len(nodes) // node_width,
            "edge_count": len(edges) // len(V8_EDGE_FIELDS),
            "trace_function_count": 0,
        },
        "nodes": nodes,
        "edges": edges,
        "trace_function_infos": [],
        "trace_tree": [],
        "samples": [],
        "locations": [],
        "strings": strings.values,
    }


def snapshot_chunks(snapshot: dict[str, Any], chunk_size: int = 250_000) -> Iterator[str]:
    """The snapshot serialized as the text chunks HeapProfiler.addHeapSnapshotChunk carries."""
    text = json.dumps(snapshot, separators=(",", ":"))
    for start in range(0, len(text), chunk_size):
        yield text[start : start + chunk_size]


def _microseconds(seconds: float) -> int:
    return round(seconds * 1e6)


def _is_inspector_frame(frame: dict[str, Any], internal_script_ids: Collection[str]) -> bool:
    url = frame.get("url") or ""
    return (
        frame.get("name") in INSPECTOR_FRAME_NAMES
        or str(frame.get("sourceID", "")) in internal_script_ids
        or any(marker in url for marker in INSPECTOR_URL_MARKERS)
    )


def _user_frames(frames: list[dict[str, Any]], internal_script_ids: Collection[str]) -> list[dict[str, Any]]:
    """A sample's frames outermost first, without the inspector's own frames beneath the user's.

    The injected script's anonymous frames carry no name to recognize them by; any script one of
    the named inspector frames belongs to is the inspector's, whether or not the client had the
    Debugger domain on to learn its id."""
    internal_ids = set(internal_script_ids)
    for frame in frames:
        if frame.get("name") in INSPECTOR_FRAME_NAMES and "sourceID" in frame:
            internal_ids.add(str(frame["sourceID"]))
    outermost_first = list(reversed(frames))
    while outermost_first and _is_inspector_frame(outermost_first[0], internal_ids):
        outermost_first.pop(0)
    return outermost_first


def convert_samples_to_profile(
    samples: dict[str, Any], start_time: float, end_time: float, internal_script_ids: Collection[str] = ()
) -> dict[str, Any]:
    """Build a Profiler.Profile call tree from ScriptProfiler samples.

    WebKit lists a sample's frames innermost first with 1-based lines and columns; the tree is
    rooted at the outermost frame with 0-based locations, one node per distinct frame at a
    distinct position in the tree (so recursion nests). The inspector's own frames under a console
    evaluation are dropped (`internal_script_ids` are the scripts WebKit's injected script was
    parsed as, when known). A sample with no frames is idle time and one entirely inside the
    inspector is VM time, named as Chrome names them; global code is "(anonymous)" as in Chrome.
    Times are the stopwatch seconds turned into microseconds; deltas are between consecutive
    samples, the first one from `start_time`.
    """
    nodes: list[dict[str, Any]] = []
    children_of: dict[int, dict[tuple[Any, ...], int]] = {}

    def add_node(parent: Optional[int], call_frame: dict[str, Any], key: tuple[Any, ...]) -> int:
        node_id = len(nodes) + ROOT_NODE_ID
        nodes.append({"id": node_id, "callFrame": call_frame, "hitCount": 0})
        if parent is not None:
            nodes[parent - ROOT_NODE_ID].setdefault("children", []).append(node_id)
            children_of.setdefault(parent, {})[key] = node_id
        return node_id

    def child(parent: int, call_frame: dict[str, Any], key: tuple[Any, ...]) -> int:
        existing = children_of.get(parent, {}).get(key)
        return existing if existing is not None else add_node(parent, call_frame, key)

    def synthetic(name: str) -> dict[str, Any]:
        return {"functionName": name, "scriptId": "0", "url": "", "lineNumber": -1, "columnNumber": -1}

    root = add_node(None, synthetic("(root)"), ("(root)",))
    sample_ids: list[int] = []
    deltas: list[int] = []

    def take_sample(node: int, timestamp: float) -> None:
        nonlocal previous
        nodes[node - ROOT_NODE_ID]["hitCount"] += 1
        sample_ids.append(node)
        deltas.append(max(_microseconds(timestamp - previous), 0))
        previous = max(previous, timestamp)

    previous = start_time
    idle_after_gap: Optional[int] = None
    for trace in samples.get("stackTraces", []):
        frames: list[dict[str, Any]] = trace.get("stackFrames", [])
        timestamp = float(trace.get("timestamp", previous))
        if timestamp - previous > IDLE_GAP:
            if idle_after_gap is None:
                idle_after_gap = child(root, synthetic("(idle)"), ("(idle)",))
            take_sample(idle_after_gap, previous + SAMPLE_INTERVAL if sample_ids else previous)
        user_frames = _user_frames(frames, internal_script_ids)
        if not frames:
            node = child(root, synthetic("(idle)"), ("(idle)",))
        elif not user_frames:
            node = child(root, synthetic("(program)"), ("(program)",))
        else:
            node = root
            for frame in user_frames:
                name = frame.get("name") or ""
                call_frame: dict[str, Any] = {
                    "functionName": "(anonymous)" if name in ("", "(program)") else name,
                    "scriptId": str(frame.get("sourceID", "0")),
                    "url": frame.get("url") or "",
                    "lineNumber": max(int(frame.get("line", 0)) - 1, 0),
                    "columnNumber": max(int(frame.get("column", 0)) - 1, 0),
                }
                key: tuple[Any, ...] = tuple(call_frame.values())
                node = child(node, call_frame, key)
        take_sample(node, timestamp)

    return {
        "nodes": nodes,
        "startTime": _microseconds(start_time),
        "endTime": _microseconds(end_time),
        "samples": sample_ids,
        "timeDeltas": deltas,
    }


def profile_to_trace_events(profile: dict[str, Any], pid: int, tid: int) -> list[dict[str, Any]]:
    """A Profiler.Profile as the Profile + ProfileChunk pair a trace carries a CPU profile in.
    Chunk nodes name their parent instead of listing children."""
    parent_of: dict[int, int] = {}
    for node in profile["nodes"]:
        for child_id in node.get("children", []):
            parent_of[child_id] = node["id"]
    chunk_nodes: list[dict[str, Any]] = []
    for node in profile["nodes"]:
        chunk_node: dict[str, Any] = {"id": node["id"], "callFrame": node["callFrame"]}
        if node["id"] in parent_of:
            chunk_node["parent"] = parent_of[node["id"]]
        chunk_nodes.append(chunk_node)
    profile_id = "0x1"
    common: dict[str, Any] = {"cat": _CAT_CPU_PROFILE, "ph": "P", "pid": pid, "tid": tid, "id": profile_id}
    return [
        {
            "name": "Profile",
            "ts": profile["startTime"],
            "args": {"data": {"startTime": profile["startTime"]}},
            **common,
        },
        {
            "name": "ProfileChunk",
            "ts": profile["startTime"],
            "args": {
                "data": {
                    "cpuProfile": {"nodes": chunk_nodes, "samples": profile["samples"]},
                    "timeDeltas": profile["timeDeltas"],
                }
            },
            **common,
        },
    ]


def build_trace_events(
    records: list[dict[str, Any]],
    *,
    start_time: float,
    end_time: float,
    pid: int,
    frame_id: str,
    url: str,
    profile: Optional[dict[str, Any]],
    screenshots: bool,
) -> list[dict[str, Any]]:
    """Turn a Timeline recording into the trace events of a Chrome Performance recording.

    The renderer is the page's process with one main thread; a synthetic browser process
    announces tracing and the page's frame, which is how the frontend finds the main thread.
    Each timed record at the top of a WebKit rendering frame is one main-thread task; the
    records beneath it keep their nesting.
    """
    browser_pid = 1 if pid != 1 else 2
    tid = RENDERER_MAIN_THREAD_ID
    # WebKit's first record can begin before the recordingStarted timestamp (the frame that was
    # in flight when recording began); the trace must open before its first event.
    first_record = min((float(record.get("startTime", start_time)) for record in records), default=start_time)
    start = _microseconds(min(start_time, first_record))
    events: list[dict[str, Any]] = [
        _metadata("process_name", browser_pid, BROWSER_THREAD_ID, "Browser"),
        _metadata("thread_name", browser_pid, BROWSER_THREAD_ID, "CrBrowserMain"),
        _metadata("process_name", pid, tid, "Renderer"),
        _metadata("thread_name", pid, tid, "CrRendererMain"),
        {
            "name": "TracingStartedInBrowser",
            "cat": _CAT_TIMELINE_DISABLED,
            "ph": "I",
            "s": "t",
            "pid": browser_pid,
            "tid": BROWSER_THREAD_ID,
            "ts": start,
            "args": {
                "data": {
                    "frameTreeNodeId": 1,
                    "persistentIds": True,
                    "frames": [
                        {
                            "frame": frame_id,
                            "url": url,
                            "name": "",
                            "processId": pid,
                            "isInPrimaryMainFrame": True,
                            "isOutermostMainFrame": True,
                        }
                    ],
                }
            },
        },
    ]
    converter = _RecordConverter(pid, tid, frame_id, screenshots, events)
    for record in records:
        converter.convert(record, top_level=True)
    if profile is not None:
        events.extend(profile_to_trace_events(profile, pid, tid))
    # Parents before their children at the same instant, instants after the spans they fall in.
    events.sort(key=lambda event: (event["ts"], -event.get("dur", -1)))
    return events


def _metadata(name: str, pid: int, tid: int, value: str) -> dict[str, Any]:
    return {"name": name, "cat": "__metadata", "ph": "M", "pid": pid, "tid": tid, "ts": 0, "args": {"name": value}}


class _RecordConverter:
    def __init__(self, pid: int, tid: int, frame_id: str, screenshots: bool, out: list[dict[str, Any]]) -> None:
        self.pid = pid
        self.tid = tid
        self.frame = frame_id
        self.screenshots = screenshots
        self.out = out

    def convert(self, record: dict[str, Any], top_level: bool = False) -> None:
        """Emit a record and its children. A WebKit rendering frame is not work of its own: it
        spans from the first activity of a frame to its composite, idle time included (a static
        page yields one frame record covering the whole recording), and Chrome would show that
        span as one long task. Each timed piece of work in it is a main-thread task instead."""
        kind = record.get("type", "")
        children: list[dict[str, Any]] = record.get("children", [])
        if kind == "RenderingFrame":
            for child in children:
                self.convert(child, top_level=True)
            return
        data: dict[str, Any] = record.get("data") or {}
        start = _microseconds(float(record.get("startTime", 0.0)))
        end = _microseconds(float(record["endTime"])) if "endTime" in record else None
        if top_level and end is not None:
            self.out.append(self._span("RunTask", _CAT_TIMELINE_DISABLED, start, end, {}))
        event = self._translate(kind, data, start, end)
        if event is not None:
            self.out.append(event)
        for child in children:
            self.convert(child)

    def _translate(self, kind: str, data: dict[str, Any], start: int, end: Optional[int]) -> Optional[dict[str, Any]]:
        frame = self.frame
        if kind == "FunctionCall":
            return self._span(
                "FunctionCall",
                _CAT_TIMELINE,
                start,
                end,
                {
                    "data": {
                        "frame": frame,
                        "url": data.get("scriptName", ""),
                        "lineNumber": max(int(data.get("scriptLine", 1)) - 1, 0),
                        "columnNumber": max(int(data.get("scriptColumn", 1)) - 1, 0),
                    }
                },
            )
        if kind == "EvaluateScript":
            return self._span(
                "EvaluateScript",
                _CAT_TIMELINE,
                start,
                end,
                {
                    "data": {
                        "frame": frame,
                        "url": data.get("url", ""),
                        "lineNumber": max(int(data.get("lineNumber", 1)) - 1, 0),
                        "columnNumber": max(int(data.get("columnNumber", 1)) - 1, 0),
                    }
                },
            )
        if kind == "TimerInstall":
            payload: dict[str, Any] = {
                "timerId": data.get("timerId"),
                "timeout": data.get("timeout"),
                "singleShot": data.get("singleShot"),
            }
            return self._instant("TimerInstall", _CAT_TIMELINE, start, {"data": {**payload, "frame": frame}})
        if kind == "TimerRemove":
            return self._instant(
                "TimerRemove", _CAT_TIMELINE, start, {"data": {"timerId": data.get("timerId"), "frame": frame}}
            )
        if kind == "TimerFire":
            return self._span(
                "TimerFire", _CAT_TIMELINE, start, end, {"data": {"timerId": data.get("timerId"), "frame": frame}}
            )
        if kind in ("RequestAnimationFrame", "CancelAnimationFrame"):
            return self._instant(kind, _CAT_TIMELINE, start, {"data": {"id": data.get("id"), "frame": frame}})
        if kind == "FireAnimationFrame":
            return self._span(
                "FireAnimationFrame", _CAT_TIMELINE, start, end, {"data": {"id": data.get("id"), "frame": frame}}
            )
        if kind == "EventDispatch":
            return self._span("EventDispatch", _CAT_TIMELINE, start, end, {"data": {"type": data.get("type", "")}})
        if kind == "ScheduleStyleRecalculation":
            return self._instant("ScheduleStyleRecalculation", _CAT_TIMELINE, start, {"data": {"frame": frame}})
        if kind == "RecalculateStyles":
            return self._span(
                "UpdateLayoutTree", _CAT_TIMELINE, start, end, {"beginData": {"frame": frame}, "elementCount": 0}
            )
        if kind == "InvalidateLayout":
            return self._instant("InvalidateLayout", _CAT_TIMELINE, start, {"data": {"frame": frame}})
        if kind == "Layout":
            roots: list[dict[str, Any]] = [{"depth": 0, "nodeId": 0, "quads": [data["root"]]}] if "root" in data else []
            return self._span(
                "Layout",
                _CAT_TIMELINE,
                start,
                end,
                {
                    "beginData": {"frame": frame, "dirtyObjects": 0, "totalObjects": 0, "partialLayout": False},
                    "endData": {"layoutRoots": roots},
                },
            )
        if kind == "Paint":
            payload: dict[str, Any] = {"clip": data.get("clip", [0] * 8), "frame": frame, "layerId": 0, "nodeId": 0}
            return self._span("Paint", _CAT_TIMELINE, start, end, {"data": payload})
        if kind == "Composite":
            return self._span("CompositeLayers", _CAT_TIMELINE, start, end, {"data": {"layerTreeId": 1}})
        if kind == "Screenshot":
            if not self.screenshots:
                return None
            image = data.get("imageData", "")
            snapshot = image.split(",", 1)[1] if image.startswith("data:") else image
            return {
                "name": "Screenshot",
                "cat": _CAT_SCREENSHOT,
                "ph": "O",
                "id": "0x1",
                "pid": self.pid,
                "tid": self.tid,
                "ts": start,
                "args": {"snapshot": snapshot},
            }
        if kind == "TimeStamp":
            return self._instant("TimeStamp", _CAT_TIMELINE, start, {"data": {"message": data.get("message", "")}})
        if kind in ("Time", "TimeEnd"):
            message = str(data.get("message", ""))
            return {
                "name": "ConsoleTime",
                "cat": _CAT_CONSOLE,
                "ph": "b" if kind == "Time" else "e",
                "id2": {"local": f"0x{abs(hash(message)) & 0xFFFFFFFF:x}"},
                "pid": self.pid,
                "tid": self.tid,
                "ts": start,
                "args": {"data": {"name": message}},
            }
        if kind == "FirstContentfulPaint":
            return self._mark("firstContentfulPaint", start, {"frame": frame, "data": {"navigationId": ""}})
        if kind == "LargestContentfulPaint":
            payload: dict[str, Any] = {**data, "isOutermostMainFrame": True, "isMainFrame": True, "navigationId": ""}
            return self._mark("largestContentfulPaint::Candidate", start, {"frame": frame, "data": payload})
        if kind in ("ProbeSample", "ConsoleProfile"):
            return None
        # Anything else is shown under its WebKit name as a generic main-thread entry.
        if end is None:
            return self._instant(kind, _CAT_TIMELINE_DISABLED, start, {"data": data})
        return self._span(kind, _CAT_TIMELINE_DISABLED, start, end, {"data": data})

    def _span(self, name: str, cat: str, start: int, end: Optional[int], args: dict[str, Any]) -> dict[str, Any]:
        if end is None:
            return self._instant(name, cat, start, args)
        return {
            "name": name,
            "cat": cat,
            "ph": "X",
            "pid": self.pid,
            "tid": self.tid,
            "ts": start,
            "dur": max(end - start, 0),
            "args": args,
        }

    def _instant(self, name: str, cat: str, start: int, args: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": name,
            "cat": cat,
            "ph": "I",
            "s": "t",
            "pid": self.pid,
            "tid": self.tid,
            "ts": start,
            "args": args,
        }

    def _mark(self, name: str, start: int, args: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": name,
            "cat": _CAT_LOADING,
            "ph": "R",
            "pid": self.pid,
            "tid": self.tid,
            "ts": start,
            "args": args,
        }
