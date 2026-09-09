"""The conversions behind Chrome DevTools' Memory and Performance panels: WebKit's heap snapshot,
ScriptProfiler samples and Timeline records into V8's heap snapshot, CPU profile and trace-event
formats. Checked against real payloads captured from a device (see profiling/README.md)."""

import json
from pathlib import Path
from typing import Any

import pytest

from pymobiledevice3.services.web_protocol.cdp_profiling import (
    V8_EDGE_FIELDS,
    V8_NODE_FIELDS,
    build_trace_events,
    convert_heap_snapshot,
    convert_samples_to_profile,
    profile_to_trace_events,
    snapshot_chunks,
)
from tests.services.test_web_protocol.test_cdp_server import offline_cdp_target

FIXTURES = Path(__file__).resolve().parent / "profiling"


@pytest.fixture(scope="module")
def webkit_snapshot() -> dict[str, Any]:
    return json.loads((FIXTURES / "webkit_heap_snapshot_jscontext.json").read_text())


@pytest.fixture(scope="module")
def v8_snapshot(webkit_snapshot: dict[str, Any]) -> dict[str, Any]:
    return convert_heap_snapshot(webkit_snapshot)


@pytest.fixture(scope="module")
def tracking_complete() -> dict[str, Any]:
    return json.loads((FIXTURES / "webkit_scriptprofiler_tracking_complete.json").read_text())


@pytest.fixture(scope="module")
def timeline_events() -> list[dict[str, Any]]:
    return json.loads((FIXTURES / "webkit_timeline_events_page.json").read_text())


def _nodes(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """The flat node array as one dict per node, resolving type and name."""
    meta = snapshot["snapshot"]["meta"]
    fields = meta["node_fields"]
    types = meta["node_types"][fields.index("type")]
    strings = snapshot["strings"]
    width = len(fields)
    raw = snapshot["nodes"]
    out = []
    for offset in range(0, len(raw), width):
        node = dict(zip(fields, raw[offset : offset + width]))
        node["type"] = types[node["type"]]
        node["name"] = strings[node["name"]]
        node["index"] = offset
        out.append(node)
    return out


def _edges(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """The flat edge array as one dict per edge, with the owning node's index attached."""
    meta = snapshot["snapshot"]["meta"]
    fields = meta["edge_fields"]
    types = meta["edge_types"][fields.index("type")]
    node_width = len(meta["node_fields"])
    edge_count_at = meta["node_fields"].index("edge_count")
    width = len(fields)
    raw = snapshot["edges"]
    out = []
    cursor = 0
    for node_offset in range(0, len(snapshot["nodes"]), node_width):
        for _ in range(snapshot["nodes"][node_offset + edge_count_at]):
            edge = dict(zip(fields, raw[cursor : cursor + width]))
            edge["type"] = types[edge["type"]]
            edge["from_index"] = node_offset
            out.append(edge)
            cursor += width
    assert cursor == len(raw), "every edge belongs to exactly one node, in node order"
    return out


# --- heap snapshot -------------------------------------------------------------------------------


def test_snapshot_meta_is_what_the_heap_snapshot_worker_reads(v8_snapshot: dict[str, Any]) -> None:
    meta = v8_snapshot["snapshot"]["meta"]
    assert meta["node_fields"] == list(V8_NODE_FIELDS)
    assert meta["edge_fields"] == list(V8_EDGE_FIELDS)
    node_types = meta["node_types"][0]
    for required in (
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
    ):
        assert required in node_types
    assert meta["edge_types"][0] == ["context", "element", "property", "internal", "hidden", "shortcut", "weak"]
    assert v8_snapshot["snapshot"]["node_count"] == len(v8_snapshot["nodes"]) // len(V8_NODE_FIELDS)
    assert v8_snapshot["snapshot"]["edge_count"] == len(v8_snapshot["edges"]) // len(V8_EDGE_FIELDS)
    for empty in ("trace_function_infos", "trace_tree", "samples", "locations"):
        assert v8_snapshot[empty] == []


def test_snapshot_keeps_every_webkit_node_with_its_id_and_size(
    webkit_snapshot: dict[str, Any], v8_snapshot: dict[str, Any]
) -> None:
    webkit_nodes = webkit_snapshot["nodes"]
    expected = {webkit_nodes[i]: webkit_nodes[i + 1] for i in range(0, len(webkit_nodes), 4)}
    nodes = _nodes(v8_snapshot)
    assert {node["id"]: node["self_size"] for node in nodes} == expected
    assert nodes[0]["id"] == 0 and nodes[0]["type"] == "synthetic", "WebKit's <root> stays first, as V8's root"
    assert all(node["trace_node_id"] == 0 and node["detachedness"] == 0 for node in nodes)


def test_snapshot_types_follow_the_webkit_class_names(v8_snapshot: dict[str, Any]) -> None:
    by_name: dict[str, set[str]] = {}
    for node in _nodes(v8_snapshot):
        by_name.setdefault(node["name"], set()).add(node["type"])
    assert by_name["Widget"] == {"object"}, "an Object subclassification keeps its constructor name"
    assert by_name["string"] == {"string"}
    assert by_name["Function"] == {"closure"}
    assert by_name["Structure"] == {"object shape"}
    assert by_name["FunctionExecutable"] == {"code"}, "compiled-code internals are code, as in V8"
    assert by_name["PropertyTable"] == {"hidden"}, "other engine internals are hidden, as V8's are"
    assert by_name["Array"] == {"object"}, "JS arrays are objects named Array; V8's 'array' is the hidden backing store"


def test_snapshot_edges_are_grouped_per_node_and_point_at_node_indexes(v8_snapshot: dict[str, Any]) -> None:
    width = len(V8_NODE_FIELDS)
    node_indexes = set(range(0, len(v8_snapshot["nodes"]), width))
    edges = _edges(v8_snapshot)
    assert edges, "the fixture has edges"
    assert all(edge["to_node"] in node_indexes for edge in edges), "to_node is an index into the node array"
    nodes = {node["index"]: node for node in _nodes(v8_snapshot)}
    strings = v8_snapshot["strings"]
    widget_properties = {
        strings[edge["name_or_index"]]
        for edge in edges
        if edge["type"] == "property" and nodes[edge["from_index"]]["name"] == "Widget"
    }
    assert {"label", "data"} <= widget_properties, (
        "property edges carry their WebKit names (index is an inline number, not a cell)"
    )
    array_elements = [
        edge for edge in edges if edge["type"] == "element" and nodes[edge["from_index"]]["name"] == "Array"
    ]
    assert array_elements and all(isinstance(edge["name_or_index"], int) for edge in array_elements)
    internal = [edge for edge in edges if edge["type"] == "internal"]
    assert internal and all(strings[edge["name_or_index"]] == "" for edge in internal)
    assert any(edge["type"] == "context" for edge in edges), "WebKit's Variable edges become context edges"
    root_edges = [edge for edge in edges if edge["from_index"] == 0]
    assert root_edges, "the root retains the heap"


def test_snapshot_edges_are_unique_so_the_frontends_distance_search_does_not_overflow(
    webkit_snapshot: dict[str, Any], v8_snapshot: dict[str, Any]
) -> None:
    """WebKit lists the root's edge to an object once per reason it is retained; the frontend's
    HeapSnapshotWorker seeds its BFS with one slot per root edge and throws "BFS failed" when a
    target recurs. Elsewhere an exact duplicate edge is just noise."""
    webkit_edges = webkit_snapshot["edges"]
    root_targets = [webkit_edges[i + 1] for i in range(0, len(webkit_edges), 4) if webkit_edges[i] == 0]
    assert len(root_targets) > len(set(root_targets)), "the fixture exhibits WebKit's repeated root edges"
    edges = _edges(v8_snapshot)
    seeds = [edge["to_node"] for edge in edges if edge["from_index"] == 0]
    assert len(seeds) == len(set(seeds)) == len(set(root_targets))
    triples = [(edge["from_index"], edge["type"], edge["name_or_index"], edge["to_node"]) for edge in edges]
    assert len(triples) == len(set(triples))


def test_snapshot_string_references_are_in_range(v8_snapshot: dict[str, Any]) -> None:
    strings = v8_snapshot["strings"]
    assert all(
        0 <= node["name"] < len(strings) for node in _nodes({**v8_snapshot, "strings": list(range(len(strings)))})
    )
    for edge in _edges(v8_snapshot):
        if edge["type"] != "element":
            assert 0 <= edge["name_or_index"] < len(strings)


def test_snapshot_chunks_reassemble_to_the_snapshot(v8_snapshot: dict[str, Any]) -> None:
    chunks = list(snapshot_chunks(v8_snapshot, chunk_size=10_000))
    assert len(chunks) > 1 and all(len(chunk) <= 10_000 for chunk in chunks)
    assert json.loads("".join(chunks)) == v8_snapshot


def test_snapshot_of_an_empty_heap_is_just_the_root() -> None:
    snapshot = convert_heap_snapshot({
        "version": 3,
        "type": "Inspector",
        "nodes": [0, 0, 0, 0],
        "nodeClassNames": ["<root>"],
        "edges": [],
        "edgeTypes": ["Internal", "Property", "Index", "Variable"],
        "edgeNames": [],
    })
    assert snapshot["snapshot"]["node_count"] == 1 and snapshot["snapshot"]["edge_count"] == 0
    assert _nodes(snapshot)[0]["name"] == "(root)"


# --- CPU profile ---------------------------------------------------------------------------------


def test_profile_is_a_call_tree_with_one_sample_per_stack_trace(tracking_complete: dict[str, Any]) -> None:
    traces = tracking_complete["samples"]["stackTraces"]
    profile = convert_samples_to_profile(
        tracking_complete["samples"], start_time=46.15, end_time=tracking_complete["timestamp"]
    )
    nodes = {node["id"]: node for node in profile["nodes"]}
    root = profile["nodes"][0]
    assert root["id"] == 1 and root["callFrame"]["functionName"] == "(root)"
    assert len(profile["samples"]) == len(profile["timeDeltas"]) >= len(traces)
    assert all(sample in nodes for sample in profile["samples"])
    sampled = [nodes[sample]["callFrame"]["functionName"] for sample in profile["samples"]]
    assert len([name for name in sampled if name != "(idle)"]) == len(traces), "one sample per stack trace"
    assert sum(node["hitCount"] for node in profile["nodes"]) == len(profile["samples"])
    parents: dict[int, int] = {}
    for node in profile["nodes"]:
        for child in node.get("children", []):
            assert child in nodes and child not in parents, "every node has exactly one parent"
            parents[child] = node["id"]
    assert set(nodes) - {1} == set(parents), "every node but the root is reachable from it"
    assert all(delta >= 0 for delta in profile["timeDeltas"])
    assert profile["startTime"] == 46_150_000 and profile["endTime"] == round(tracking_complete["timestamp"] * 1e6)
    assert profile["startTime"] + sum(profile["timeDeltas"]) <= profile["endTime"]


def test_profile_frames_are_zero_based_and_keyed_by_location(tracking_complete: dict[str, Any]) -> None:
    profile = convert_samples_to_profile(tracking_complete["samples"], start_time=46.15, end_time=46.17)
    fib = [node for node in profile["nodes"] if node["callFrame"]["functionName"] == "fib"]
    assert fib, "the recursion is in the tree"
    frame = fib[0]["callFrame"]
    assert frame == {"functionName": "fib", "scriptId": "3", "url": "", "lineNumber": 6, "columnNumber": 12}
    assert all(node["callFrame"] == frame for node in fib), "the same function at the same location is one frame"
    depths = {len(_path_to_root(profile, node["id"])) for node in fib}
    assert len(depths) > 1, "recursion nests the frame under itself rather than merging the levels"
    path = _path_to_root(profile, fib[0]["id"])
    assert [node["callFrame"]["functionName"] for node in path[-3:]] == ["busy", "(anonymous)", "(root)"], (
        "stacks are rooted at the outermost user frame; the evaluated expression's global code is anonymous"
    )
    assert path[-2]["callFrame"]["scriptId"] == "4"


def test_profile_drops_the_inspectors_own_frames(tracking_complete: dict[str, Any]) -> None:
    """A console evaluation runs inside WebKit's injected script and a native evaluate; Chrome
    shows none of that machinery. A sample entirely inside it is VM time."""
    profile = convert_samples_to_profile(tracking_complete["samples"], start_time=46.15, end_time=46.17)
    names = {node["callFrame"]["functionName"] for node in profile["nodes"]}
    for internal in ("createInspectorInjectedScript", "InjectedScript", "_wrapCall", "evaluateWithScopeExtension"):
        assert internal not in names
    assert "(program)" in names, "the sample taken while the injected script was built is VM time"
    assert names >= {"busy", "fib"}


def test_profile_drops_frames_of_known_internal_scripts() -> None:
    samples = {
        "stackTraces": [
            {
                "timestamp": 1.0,
                "stackFrames": [
                    {"sourceID": "9", "name": "work", "line": 3, "column": 5, "url": "app.js"},
                    {"sourceID": "2", "name": "helper", "line": 1, "column": 1, "url": ""},
                ],
            }
        ]
    }
    profile = convert_samples_to_profile(samples, start_time=0.999, end_time=1.5, internal_script_ids={"2"})
    assert [node["callFrame"]["functionName"] for node in profile["nodes"]] == ["(root)", "work"]


def test_profile_charges_gaps_between_script_runs_to_idle() -> None:
    """WebKit samples only while script runs; Chrome charges each sample until the next one.
    A gap longer than a few intervals gets an idle sample right after the frame's own."""
    frame = {"sourceID": "1", "name": "work", "line": 1, "column": 1, "url": "app.js"}
    samples = {
        "stackTraces": [
            {"timestamp": 10.000, "stackFrames": [frame]},
            {"timestamp": 10.001, "stackFrames": [frame]},
            {"timestamp": 10.002, "stackFrames": [frame]},
            {"timestamp": 12.000, "stackFrames": [frame]},  # two idle seconds later
        ]
    }
    profile = convert_samples_to_profile(samples, start_time=9.0, end_time=13.0)
    names = {node["id"]: node["callFrame"]["functionName"] for node in profile["nodes"]}
    sequence = [(names[node_id], delta) for node_id, delta in zip(profile["samples"], profile["timeDeltas"])]
    assert sequence == [
        ("(idle)", 0),  # the second before the first sample is idle, not "work"
        ("work", 1_000_000),
        ("work", 1000),
        ("work", 1000),
        ("(idle)", 1000),  # the last dense sample keeps one interval; the rest of the gap is idle
        ("work", 1_997_000),
    ]
    dense = convert_samples_to_profile({"stackTraces": samples["stackTraces"][:3]}, start_time=10.0, end_time=10.003)
    dense_names = {node["id"]: node["callFrame"]["functionName"] for node in dense["nodes"]}
    assert all(dense_names[node_id] != "(idle)" for node_id in dense["samples"]), "dense sampling stays as sampled"


def test_profile_of_no_samples_is_idle() -> None:
    profile = convert_samples_to_profile({"stackTraces": []}, start_time=1.0, end_time=2.0)
    assert [node["callFrame"]["functionName"] for node in profile["nodes"]] == ["(root)"]
    assert profile["samples"] == [] and profile["timeDeltas"] == []
    empty = convert_samples_to_profile(
        {"stackTraces": [{"timestamp": 1.5, "stackFrames": []}]}, start_time=1.0, end_time=2.0
    )
    idle = [node for node in empty["nodes"] if node["callFrame"]["functionName"] == "(idle)"]
    assert len(idle) == 1, "the gap before the sample and the empty sample are the same idle node"
    assert empty["samples"] == [idle[0]["id"]] * 2 and empty["timeDeltas"] == [0, 500_000]


def _path_to_root(profile: dict[str, Any], node_id: int) -> list[dict[str, Any]]:
    parents = {child: node for node in profile["nodes"] for child in node.get("children", [])}
    nodes = {node["id"]: node for node in profile["nodes"]}
    path = [nodes[node_id]]
    while path[-1]["id"] in parents:
        path.append(parents[path[-1]["id"]])
    return path


def test_profile_becomes_a_profile_and_a_chunk_event(tracking_complete: dict[str, Any]) -> None:
    profile = convert_samples_to_profile(tracking_complete["samples"], start_time=46.15, end_time=46.17)
    events = profile_to_trace_events(profile, pid=7, tid=1)
    assert [event["name"] for event in events] == ["Profile", "ProfileChunk"]
    head, chunk = events
    assert head["ph"] == chunk["ph"] == "P" and head["id"] == chunk["id"]
    assert head["cat"] == "disabled-by-default-v8.cpu_profiler" and head["ts"] == profile["startTime"]
    assert head["args"]["data"]["startTime"] == profile["startTime"]
    cpu = chunk["args"]["data"]["cpuProfile"]
    assert cpu["samples"] == profile["samples"] and chunk["args"]["data"]["timeDeltas"] == profile["timeDeltas"]
    by_id = {node["id"]: node for node in cpu["nodes"]}
    assert "parent" not in by_id[1] and all("children" not in node for node in cpu["nodes"])
    assert all(node["parent"] in by_id for node in cpu["nodes"] if node["id"] != 1), "chunk nodes carry their parent"


# --- trace events --------------------------------------------------------------------------------


def _records(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event["params"]["record"] for event in events if event["method"] == "Timeline.eventRecorded"]


def _trace(events: list[dict[str, Any]], **overrides: Any) -> list[dict[str, Any]]:
    started = next(e["params"]["startTime"] for e in events if e["method"] == "Timeline.recordingStarted")
    stopped = next(e["params"]["endTime"] for e in events if e["method"] == "Timeline.recordingStopped")
    options: dict[str, Any] = {
        "start_time": started,
        "end_time": stopped,
        "pid": 419,
        "frame_id": "PID:419:1",
        "url": "https://example.com/",
        "profile": None,
        "screenshots": False,
    }
    options.update(overrides)
    return build_trace_events(_records(events), **options)


def test_trace_opens_with_the_process_metadata_the_frontend_locates_the_main_thread_by(
    timeline_events: list[dict[str, Any]],
) -> None:
    trace = _trace(timeline_events)
    metadata = [event for event in trace if event["ph"] == "M"]
    names = {(event["name"], event["args"]["name"]) for event in metadata}
    assert {("process_name", "Renderer"), ("thread_name", "CrRendererMain"), ("thread_name", "CrBrowserMain")} <= names
    renderer_tid = next(e["tid"] for e in metadata if e["args"]["name"] == "CrRendererMain")
    started = next(event for event in trace if event["name"] == "TracingStartedInBrowser")
    frames = started["args"]["data"]["frames"]
    assert frames == [
        {
            "frame": "PID:419:1",
            "url": "https://example.com/",
            "name": "",
            "processId": 419,
            "isInPrimaryMainFrame": True,
            "isOutermostMainFrame": True,
        }
    ]
    assert started["pid"] != 419, "the browser process is distinct from the renderer whose frames it announces"
    work = [event for event in trace if event["ph"] in ("X", "I") and event["name"] != "TracingStartedInBrowser"]
    assert all(event["pid"] == 419 and event["tid"] == renderer_tid for event in work), (
        "the page's work is on its main thread"
    )


def test_trace_events_are_complete_events_in_microseconds_nested_within_their_parents(
    timeline_events: list[dict[str, Any]],
) -> None:
    trace = _trace(timeline_events)
    assert trace == sorted(trace, key=lambda event: event["ts"])
    assert all(isinstance(event["ts"], int) for event in trace)
    tasks = [event for event in trace if event["name"] == "RunTask"]
    timed_children = [
        child for record in _records(timeline_events) for child in record.get("children", []) if "endTime" in child
    ]
    assert len(tasks) == len(timed_children), "each timed record under a WebKit RenderingFrame is one task"
    assert not any(event["dur"] > 1_000_000 for event in tasks), "a frame's idle time is not a task"
    assert all(event["dur"] >= 0 for event in trace if event["ph"] == "X")
    for event in trace:
        if event["ph"] != "X" or event["name"] in ("RunTask", "TracingStartedInBrowser"):
            continue
        parent = [task for task in tasks if task["ts"] <= event["ts"] <= task["ts"] + task["dur"]]
        assert parent, f"{event['name']} at {event['ts']} lies inside a task"
    announced = next(event["ts"] for event in trace if event["name"] == "TracingStartedInBrowser")
    assert announced == min(event["ts"] for event in trace if event["ph"] != "M"), (
        "tracing opens before the first event"
    )
    started = next(e["params"]["startTime"] for e in timeline_events if e["method"] == "Timeline.recordingStarted")
    assert announced <= round(started * 1e6)


def test_trace_maps_webkit_record_types_onto_chromes_names_and_payloads(timeline_events: list[dict[str, Any]]) -> None:
    trace = _trace(timeline_events)
    by_name: dict[str, list[dict[str, Any]]] = {}
    for event in trace:
        by_name.setdefault(event["name"], []).append(event)
    fire = by_name["TimerFire"][0]
    assert fire["ph"] == "X" and fire["dur"] > 0 and fire["args"]["data"] == {"timerId": 1, "frame": "PID:419:1"}
    install = by_name["TimerInstall"][0]
    assert install["ph"] == "I" and install["s"] == "t"
    assert install["args"]["data"] == {"timerId": 1, "timeout": 50, "singleShot": True, "frame": "PID:419:1"}
    call = by_name["FunctionCall"][0]["args"]["data"]
    assert call["url"] == "" and call["lineNumber"] == 0 and call["columnNumber"] == 36 and call["frame"] == "PID:419:1"
    assert (
        "RecalculateStyles" not in by_name
        and by_name["UpdateLayoutTree"][0]["args"]["beginData"]["frame"] == "PID:419:1"
    )
    layout = by_name["Layout"][0]["args"]
    assert layout["beginData"]["frame"] == "PID:419:1" and layout["endData"]["layoutRoots"][0]["quads"] == [
        [0, 0, 430, 0, 430, 775, 0, 775]
    ]
    paint = by_name["Paint"][0]["args"]["data"]
    assert len(paint["clip"]) == 8 and paint["frame"] == "PID:419:1"
    assert by_name["FireAnimationFrame"][0]["args"]["data"] == {"id": 1, "frame": "PID:419:1"}
    assert by_name["RequestAnimationFrame"][0]["ph"] == "I"
    assert "Composite" not in by_name and "CompositeLayers" in by_name
    console_time = [event for event in trace if event["name"] == "ConsoleTime"]
    assert [event["ph"] for event in console_time] == ["b", "e"] and console_time[0]["id2"] == console_time[1]["id2"]
    for event in trace:
        assert event["cat"], "every event has a category the frontend filters on"


def test_trace_carries_screenshots_only_when_asked(timeline_events: list[dict[str, Any]]) -> None:
    without = _trace(timeline_events)
    assert not any(event["name"] == "Screenshot" for event in without)
    with_screenshots = [event for event in _trace(timeline_events, screenshots=True) if event["name"] == "Screenshot"]
    assert with_screenshots
    shot = with_screenshots[0]
    assert shot["ph"] == "O" and shot["cat"] == "disabled-by-default-devtools.screenshot"
    assert shot["args"]["snapshot"].startswith("iVBORw0KGgo"), (
        "the data-URL prefix is stripped; Chrome sends bare base64"
    )


def test_trace_embeds_the_cpu_profile_on_the_main_thread(
    timeline_events: list[dict[str, Any]], tracking_complete: dict[str, Any]
) -> None:
    profile = convert_samples_to_profile(tracking_complete["samples"], start_time=46.15, end_time=46.17)
    trace = _trace(timeline_events, profile=profile)
    profile_events = [event for event in trace if event["name"] in ("Profile", "ProfileChunk")]
    assert [event["name"] for event in profile_events] == ["Profile", "ProfileChunk"]
    renderer_tid = next(e["tid"] for e in trace if e["ph"] == "M" and e["args"]["name"] == "CrRendererMain")
    assert all(event["pid"] == 419 and event["tid"] == renderer_tid for event in profile_events)


def test_trace_of_an_empty_recording_still_announces_the_page() -> None:
    trace = build_trace_events(
        [], start_time=10.0, end_time=11.0, pid=5, frame_id="F", url="u", profile=None, screenshots=False
    )
    assert [event["name"] for event in trace if event["ph"] != "M"] == ["TracingStartedInBrowser"]


# --- the bridge's handlers -----------------------------------------------------------------------

MINIMAL_WEBKIT_SNAPSHOT = {
    "version": 3,
    "type": "Inspector",
    "nodes": [0, 0, 0, 0, 7, 32, 1, 0],
    "nodeClassNames": ["<root>", "Object"],
    "edges": [0, 7, 0, 0],
    "edgeTypes": ["Internal", "Property", "Index", "Variable"],
    "edgeNames": [],
}


def _device_messages(sent: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What reached the device, unwrapped from the Target envelope a page session uses."""
    return [json.loads(m["params"]["message"]) if "message" in m.get("params", {}) else m for m in sent]


async def _handle(target: Any, message: dict[str, Any]) -> None:
    """Run a client request through the handler the bridge's table routes it to."""
    await target.from_cdp_special_messages_methods[message["method"]](message)


def _drain(target: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    while not target.output_queue.empty():
        out.append(target.output_queue.get_nowait())
    return out


async def test_collect_garbage_is_webkits_gc(monkeypatch: pytest.MonkeyPatch) -> None:
    with offline_cdp_target(monkeypatch) as (target, sent):
        await _handle(target, {"id": 3, "method": "HeapProfiler.collectGarbage", "params": {}})
        assert _device_messages(sent)[-1] == {"id": 3, "method": "Heap.gc", "params": {}}


async def test_take_heap_snapshot_streams_progress_and_chunks_before_answering(monkeypatch: pytest.MonkeyPatch) -> None:
    with offline_cdp_target(monkeypatch) as (target, sent):
        await _handle(
            target,
            {
                "id": 5,
                "method": "HeapProfiler.takeHeapSnapshot",
                "params": {"reportProgress": True},
            },
        )
        assert _device_messages(sent)[-1] == {"id": 5, "method": "Heap.snapshot", "params": {}}
        await target._dispatch_target_message({
            "id": 5,
            "result": {"timestamp": 1.0, "snapshotData": json.dumps(MINIMAL_WEBKIT_SNAPSHOT)},
        })
        out = _drain(target)
    assert [m.get("method") for m in out[:2]] == ["HeapProfiler.reportHeapSnapshotProgress"] * 2
    assert out[0]["params"] == {"done": 0, "total": 2}
    assert out[1]["params"] == {"done": 2, "total": 2, "finished": True}
    chunks = [m for m in out if m.get("method") == "HeapProfiler.addHeapSnapshotChunk"]
    assert chunks and out[-1] == {"id": 5, "result": {}}
    snapshot = json.loads("".join(m["params"]["chunk"] for m in chunks))
    assert snapshot["snapshot"]["node_count"] == 2 and snapshot["snapshot"]["edge_count"] == 1


async def test_take_heap_snapshot_relays_webkits_error(monkeypatch: pytest.MonkeyPatch) -> None:
    with offline_cdp_target(monkeypatch) as (target, _sent):
        await _handle(target, {"id": 5, "method": "HeapProfiler.takeHeapSnapshot", "params": {}})
        await target._dispatch_target_message({"id": 5, "error": {"code": -32000, "message": "nope"}})
        assert _drain(target) == [{"id": 5, "error": {"code": -32000, "message": "nope"}}]


@pytest.mark.parametrize("event_first", [False, True])
async def test_allocation_timeline_answers_stop_after_the_closing_snapshot(
    monkeypatch: pytest.MonkeyPatch, event_first: bool
) -> None:
    """WebKit's stopTracking reply and its trackingComplete event come in either order; Chrome
    delivers the snapshot before answering stopTrackingHeapObjects."""
    with offline_cdp_target(monkeypatch) as (target, sent):
        await _handle(target, {"id": 1, "method": "HeapProfiler.startTrackingHeapObjects", "params": {}})
        assert _device_messages(sent)[-1] == {"id": 1, "method": "Heap.startTracking", "params": {}}
        await target._dispatch_target_message({
            "method": "Heap.trackingStart",
            "params": {"timestamp": 1, "snapshotData": "{}"},
        })
        await _handle(
            target,
            {
                "id": 2,
                "method": "HeapProfiler.stopTrackingHeapObjects",
                "params": {"reportProgress": False},
            },
        )
        assert _device_messages(sent)[-1] == {"id": 2, "method": "Heap.stopTracking", "params": {}}
        complete = {
            "method": "Heap.trackingComplete",
            "params": {"timestamp": 2.0, "snapshotData": json.dumps(MINIMAL_WEBKIT_SNAPSHOT)},
        }
        reply = {"id": 2, "result": {}}
        for message in [complete, reply] if event_first else [reply, complete]:
            assert _drain(target) == [], "nothing is answered until both are in"
            await target._dispatch_target_message(message)
        out = _drain(target)
    assert [m.get("method") for m in out[:-1]] == ["HeapProfiler.addHeapSnapshotChunk"]
    assert out[-1] == {"id": 2, "result": {}}
    assert target._heap_tracking is None


async def test_heap_object_lookup_maps_onto_get_remote_object(monkeypatch: pytest.MonkeyPatch) -> None:
    with offline_cdp_target(monkeypatch) as (target, sent):
        await _handle(
            target,
            {
                "id": 9,
                "method": "HeapProfiler.getObjectByHeapObjectId",
                "params": {"objectId": "42", "objectGroup": "console"},
            },
        )
        assert _device_messages(sent)[-1] == {
            "id": 9,
            "method": "Heap.getRemoteObject",
            "params": {"heapObjectId": 42, "objectGroup": "console"},
        }
        await _handle(
            target,
            {
                "id": 10,
                "method": "HeapProfiler.getObjectByHeapObjectId",
                "params": {"objectId": "not-a-number"},
            },
        )
        assert _drain(target)[-1]["error"]["code"] == -32602


async def test_allocation_sampling_is_refused_with_a_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    with offline_cdp_target(monkeypatch) as (target, sent):
        await _handle(target, {"id": 4, "method": "HeapProfiler.startSampling", "params": {}})
        assert sent == []
        (reply,) = _drain(target)
    assert reply["id"] == 4 and reply["error"]["code"] == -32000
    assert "allocation sampling" in reply["error"]["message"]


async def test_cpu_profile_is_built_from_the_samples_that_follow_the_stop(
    monkeypatch: pytest.MonkeyPatch, tracking_complete: dict[str, Any]
) -> None:
    with offline_cdp_target(monkeypatch) as (target, sent):
        await _handle(target, {"id": 1, "method": "Profiler.start", "params": {}})
        assert _device_messages(sent)[-1] == {
            "id": 1,
            "method": "ScriptProfiler.startTracking",
            "params": {"includeSamples": True},
        }
        await target._dispatch_target_message({
            "method": "ScriptProfiler.trackingStart",
            "params": {"timestamp": 46.15},
        })
        await _handle(target, {"id": 2, "method": "Profiler.stop", "params": {}})
        assert _device_messages(sent)[-1] == {"id": 2, "method": "ScriptProfiler.stopTracking", "params": {}}
        await target._dispatch_target_message({"id": 2, "result": {}})
        assert _drain(target) == [], "the profile is not answered until the samples arrive"
        await target._dispatch_target_message({
            "method": "ScriptProfiler.trackingComplete",
            "params": tracking_complete,
        })
        (reply,) = _drain(target)
    profile = reply["result"]["profile"]
    assert reply["id"] == 2 and profile["startTime"] == 46_150_000
    assert {node["callFrame"]["functionName"] for node in profile["nodes"]} >= {"(root)", "busy", "fib"}
    assert target._profile is None


async def test_profiler_stop_without_a_recording_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    with offline_cdp_target(monkeypatch) as (target, sent):
        await _handle(target, {"id": 2, "method": "Profiler.stop", "params": {}})
        assert sent == []
        (reply,) = _drain(target)
    assert reply["error"]["code"] == -32000


async def test_tracing_is_for_pages_and_advertises_what_it_records(monkeypatch: pytest.MonkeyPatch) -> None:
    with offline_cdp_target(monkeypatch) as (target, sent):
        await _handle(target, {"id": 1, "method": "Tracing.getCategories", "params": {}})
        assert "devtools.timeline" in _drain(target)[0]["result"]["categories"]
        target._flat = True  # a JSContext
        await _handle(target, {"id": 2, "method": "Tracing.start", "params": {}})
        assert sent == []
        (reply,) = _drain(target)
    assert reply["error"]["code"] == -32000 and "Profiler.start" in reply["error"]["message"]


async def test_tracing_records_the_timeline_and_delivers_a_trace_on_end(
    monkeypatch: pytest.MonkeyPatch, timeline_events: list[dict[str, Any]], tracking_complete: dict[str, Any]
) -> None:
    with offline_cdp_target(monkeypatch) as (target, sent):
        started: list[tuple[str, dict[str, Any]]] = []

        async def fake_result(method: str, params: dict[str, Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
            started.append((method, params))
            return {"result": {}}

        monkeypatch.setattr(target, "send_message_with_result", fake_result)
        await _handle(
            target,
            {
                "id": 1,
                "method": "Tracing.start",
                "params": {
                    "transferMode": "ReportEvents",
                    "traceConfig": {
                        "includedCategories": ["devtools.timeline", "disabled-by-default-devtools.screenshot"]
                    },
                },
            },
        )
        assert started == [
            ("Timeline.enable", {}),
            ("Timeline.setInstruments", {"instruments": ["Timeline", "Screenshot"]}),
            ("Timeline.start", {"maxCallStackDepth": 20}),
            ("ScriptProfiler.startTracking", {"includeSamples": True}),
        ]
        assert _drain(target) == [{"id": 1, "result": {}}]
        # An unrelated recording event before ours would be noise for Chrome: it is dropped.
        for event in timeline_events:
            if event["method"] in ("Timeline.recordingStarted", "Timeline.eventRecorded"):
                await target._dispatch_target_message(event)
        await target._dispatch_target_message({
            "method": "ScriptProfiler.trackingStart",
            "params": {"timestamp": 51014.0},
        })
        assert _drain(target) == [], "WebKit's timeline events never reach the client raw"
        await _handle(target, {"id": 2, "method": "Tracing.end", "params": {}})
        assert _drain(target) == [{"id": 2, "result": {}}], "Tracing.end is answered before the data, as in Chrome"
        stops = [m["method"] for m in _device_messages(sent)[-2:]]
        assert stops == ["Timeline.stop", "ScriptProfiler.stopTracking"]
        stopped = next(e for e in timeline_events if e["method"] == "Timeline.recordingStopped")
        await target._dispatch_target_message(stopped)
        assert _drain(target) == [], "the trace waits for the CPU samples too"
        await target._dispatch_target_message({
            "method": "ScriptProfiler.trackingComplete",
            "params": tracking_complete,
        })
        out = _drain(target)
        assert _device_messages(sent)[-1]["method"] == "Timeline.disable"
    assert [m["method"] for m in out] == ["Tracing.dataCollected", "Tracing.tracingComplete"]
    events = out[0]["params"]["value"]
    names = {event["name"] for event in events}
    assert {"TracingStartedInBrowser", "RunTask", "TimerFire", "Screenshot", "Profile", "ProfileChunk"} <= names
    assert out[1]["params"] == {"dataLossOccurred": False}
    assert target._trace is None and target._profile is None


async def test_timeline_events_outside_a_trace_are_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    with offline_cdp_target(monkeypatch) as (target, _sent):
        await target._dispatch_target_message({
            "method": "Timeline.eventRecorded",
            "params": {"record": {"type": "Layout"}},
        })
        await target._dispatch_target_message({"method": "Heap.garbageCollected", "params": {"collection": {}}})
        await target._dispatch_target_message({"method": "ScriptProfiler.trackingUpdate", "params": {"event": {}}})
        assert _drain(target) == []
