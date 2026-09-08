import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pymobiledevice3.services.web_protocol import cdp_server
from pymobiledevice3.services.web_protocol.cdp_trace import (
    BRIDGE_TO_DEVICE,
    BRIDGE_TO_EDITOR,
    DEVICE_TO_BRIDGE,
    EDITOR_TO_BRIDGE,
    ProtocolTrace,
)
from pymobiledevice3.services.webinspector import WebinspectorService


def _lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_trace_writes_one_json_line_per_message_and_flushes(tmp_path: Path) -> None:
    """Each message is one line with its direction, session, page and a timestamp, written
    through immediately - a bridge that crashes right after must not lose the last exchange."""
    trace = ProtocolTrace(tmp_path / "t.jsonl")
    trace.record(EDITOR_TO_BRIDGE, {"id": 1, "method": "Runtime.evaluate"}, session="S", page="P:1")
    # Read before close: flushed per message.
    first = _lines(tmp_path / "t.jsonl")
    assert len(first) == 1
    assert first[0]["dir"] == EDITOR_TO_BRIDGE
    assert first[0]["session"] == "S" and first[0]["page"] == "P:1"
    assert first[0]["msg"] == {"id": 1, "method": "Runtime.evaluate"}
    assert first[0]["t"] >= 0
    trace.record(BRIDGE_TO_EDITOR, {"id": 1, "result": {}}, session="S", page="P:1")
    trace.close()
    assert [entry["dir"] for entry in _lines(tmp_path / "t.jsonl")] == [EDITOR_TO_BRIDGE, BRIDGE_TO_EDITOR]


def test_trace_survives_an_unserializable_message(tmp_path: Path) -> None:
    """Whatever a message carries, the trace never raises into the bridge."""
    trace = ProtocolTrace(tmp_path / "t.jsonl")
    trace.record(DEVICE_TO_BRIDGE, {"blob": b"\x00\xff"}, session="S")
    trace.close()
    (entry,) = _lines(tmp_path / "t.jsonl")
    assert entry["dir"] == DEVICE_TO_BRIDGE and "blob" in entry["msg"]


def test_trace_stops_quietly_when_the_file_cannot_be_written(tmp_path: Path) -> None:
    trace = ProtocolTrace(tmp_path / "t.jsonl")
    trace.close()
    trace.record(EDITOR_TO_BRIDGE, {"id": 1})  # closed: must be a no-op, not an error
    assert (tmp_path / "t.jsonl").read_text() == ""


async def test_inspector_hooks_record_both_device_directions(tmp_path: Path) -> None:
    """The inspector service reports what crosses a page socket: what the bridge sends the
    device, and what the device sends back, keyed by the session it belongs to."""
    inspector = WebinspectorService.__new__(WebinspectorService)
    inspector.wir_message_results = {}
    inspector.wir_events = {}
    inspector.trace = None
    trace = ProtocolTrace(tmp_path / "t.jsonl")
    inspector.trace = trace.device_hook
    sent: list[dict[str, Any]] = []

    async def fake_send_message(selector: str, args: dict[str, Any]) -> None:
        sent.append(args)

    inspector._send_message = fake_send_message  # pyright: ignore[reportAttributeAccessIssue]
    await inspector._forward_socket_data("SESSION", "PID:1", 1, {"id": 7, "method": "Runtime.enable"})
    await inspector._handle_application_sent_data({
        "WIRDestinationKey": "SESSION",
        "WIRMessageDataKey": json.dumps({"id": 7, "result": {}}),
    })
    await inspector._handle_application_sent_data({
        "WIRDestinationKey": "SESSION",
        "WIRMessageDataKey": json.dumps({"method": "Debugger.paused", "params": {}}),
    })
    trace.close()
    entries = _lines(tmp_path / "t.jsonl")
    assert [(e["dir"], e["session"]) for e in entries] == [
        (BRIDGE_TO_DEVICE, "SESSION"),
        (DEVICE_TO_BRIDGE, "SESSION"),
        (DEVICE_TO_BRIDGE, "SESSION"),
    ]
    assert entries[0]["msg"]["method"] == "Runtime.enable"
    assert entries[2]["msg"]["method"] == "Debugger.paused"
    assert sent, "the message must still reach the device"


def test_device_hook_unwraps_target_envelopes(tmp_path: Path) -> None:
    """A page target's messages travel inside Target.* envelopes; the trace records the real
    message, naming the envelope and the target it was for."""
    trace = ProtocolTrace(tmp_path / "t.jsonl")
    trace.device_hook(
        BRIDGE_TO_DEVICE,
        "S",
        {
            "method": "Target.sendMessageToTarget",
            "params": {"targetId": "page-7", "message": json.dumps({"id": 3, "method": "Runtime.evaluate"})},
        },
    )
    trace.device_hook(
        DEVICE_TO_BRIDGE,
        "S",
        {
            "method": "Target.dispatchMessageFromTarget",
            "params": {"targetId": "page-7", "message": json.dumps({"id": 3, "result": {}})},
        },
    )
    trace.device_hook(DEVICE_TO_BRIDGE, "S", {"method": "Target.targetCreated", "params": {}})  # not an envelope
    trace.close()
    entries = _lines(tmp_path / "t.jsonl")
    assert entries[0]["msg"] == {"id": 3, "method": "Runtime.evaluate", "_wrapper": "Target.sendMessageToTarget"}
    assert entries[0]["page"] == "page-7"
    assert entries[1]["msg"] == {"id": 3, "result": {}, "_wrapper": "Target.dispatchMessageFromTarget"}
    assert entries[2]["msg"]["method"] == "Target.targetCreated" and entries[2]["page"] == ""


async def test_page_endpoint_records_both_editor_directions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The page websocket pump records what the editor sent and what the bridge answered."""
    trace = ProtocolTrace(tmp_path / "t.jsonl")
    monkeypatch.setattr(cdp_server.app.state, "trace", trace, raising=False)
    inbound = [{"id": 1, "method": "Runtime.enable"}]
    outbound = [{"id": 1, "result": {}}]
    received: list[dict[str, Any]] = []
    delivered: list[dict[str, Any]] = []

    class FakeTarget:
        session_id = "S"
        page_id = "P:1"

        async def send(self, message: dict[str, Any]) -> None:
            received.append(message)

        async def receive(self) -> dict[str, Any]:
            if outbound:
                return outbound.pop(0)
            await asyncio.sleep(3600)
            raise AssertionError

    class FakeWebsocket:
        async def iter_json(self) -> AsyncIterator[dict[str, Any]]:
            for message in inbound:
                yield message

        async def send_json(self, message: dict[str, Any]) -> None:
            delivered.append(message)
            raise asyncio.CancelledError  # one message is enough

    target = cast(Any, FakeTarget())
    websocket = cast(Any, FakeWebsocket())
    await cdp_server.from_cdp(target, websocket)
    with pytest.raises(asyncio.CancelledError):
        await cdp_server.to_cdp(target, websocket)
    trace.close()
    monkeypatch.delattr(cdp_server.app.state, "trace", raising=False)
    entries = _lines(tmp_path / "t.jsonl")
    assert [(e["dir"], e["session"], e["page"]) for e in entries] == [
        (EDITOR_TO_BRIDGE, "S", "P:1"),
        (BRIDGE_TO_EDITOR, "S", "P:1"),
    ]
    assert received == [{"id": 1, "method": "Runtime.enable"}] and delivered == [{"id": 1, "result": {}}]


def test_no_trace_means_no_recording(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(cdp_server.app.state, "trace", raising=False)
    assert cdp_server._trace() is None
    _ = SimpleNamespace  # keep the import honest for future fakes
