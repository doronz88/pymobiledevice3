"""Replay a recorded editor session through the current bridge, for golden-flow regression tests.

A golden fixture is a JSON-lines trace (as `webinspector cdp --trace` records, trimmed of the
watchdog's setBreakpointsActive nudges) of a real editor - WebStorm, VS Code - talking to the
bridge. `replay_flat_session` feeds the fixture's editor commands and device responses through a
real `CdpTarget` and returns what the bridge emitted to the editor, so a test can assert the
editor-visible behavior a past bug broke. The device inputs are authentic; the assertions are the
current, correct output (the recorded bridge->editor side is the old output and is not compared).

Only the un-multiplexed (JSContext) path is modelled here - the flow the WebStorm stepping bug was
in. The device speaks straight, with no Target envelope.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Optional, cast

from pymobiledevice3.services.web_protocol.cdp_target import CdpTarget
from pymobiledevice3.services.webinspector import (
    Application,
    AutomationAvailability,
    Page,
    SessionProtocol,
    WebinspectorService,
)

# Requests the bridge issues on its own (setup replay and the withheld-reply watchdog) that the
# fixture does not script: acknowledge them without consuming a scripted device turn.
AUTO_ACKNOWLEDGED = frozenset({"Debugger.setBreakpointsActive"})

FIXTURES = Path(__file__).resolve().parent / "golden"


def load_fixture(name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (FIXTURES / f"{name}.jsonl").read_text().splitlines() if line.strip()]


class _Turn:
    """A device request the fixture scripts, with the reply and events that followed it."""

    def __init__(self, method: str) -> None:
        self.method = method
        self.reply: Optional[dict[str, Any]] = None
        self.events: list[dict[str, Any]] = []


def _device_turns(fixture: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[_Turn]]:
    """Split a fixture into (editor commands, initial device events, scripted device turns).

    A turn begins at each `bridge->device` request and gathers the `device->bridge` messages up to
    the next request: the one reply (it carries the request's id) and any events. Device events
    before the first request are the initial batch.
    """
    editor: list[dict[str, Any]] = []
    initial_events: list[dict[str, Any]] = []
    turns: list[_Turn] = []
    request_ids: dict[int, _Turn] = {}
    current: Optional[_Turn] = None
    for entry in fixture:
        direction, message = entry["dir"], entry["msg"]
        if direction == "editor->bridge":
            editor.append(message)
        elif direction == "bridge->device":
            current = _Turn(message.get("method", ""))
            if isinstance(message.get("id"), int):
                request_ids[message["id"]] = current
            turns.append(current)
        elif direction == "device->bridge":
            if "id" in message and "method" not in message:
                owner = request_ids.get(message["id"])
                if owner is not None:
                    owner.reply = message
            elif current is not None:
                current.events.append(message)
            else:
                initial_events.append(message)
    return editor, initial_events, turns


async def replay_flat_session(fixture: list[dict[str, Any]], settle: float = 0.4) -> list[dict[str, Any]]:
    """Drive a flat CdpTarget with the fixture and return the messages it emitted to the editor."""
    editor, initial_events, turns = _device_turns(fixture)
    scripted = [turn for turn in turns if turn.method not in AUTO_ACKNOWLEDGED]
    turn_iter = iter(scripted)

    inspector = WebinspectorService.__new__(WebinspectorService)
    inspector.wir_events = {}
    inspector.wir_message_results = {}
    # The bridge keys replies by their integer wire id (see WebinspectorService.send_socket_data);
    # the attribute's annotation is looser than that runtime shape.
    results = cast(dict[Any, Any], inspector.wir_message_results)
    session_id = "GOLDEN"

    def deliver_events(events: list[dict[str, Any]]) -> None:
        queue = inspector.session_events(session_id)
        for event in events:
            queue.append(dict(event))

    async def send_socket_data(session: str, app_id: str, page_id: int, data: dict[str, Any]) -> None:
        method = data.get("method", "")
        wire_id = data.get("id")
        if method in AUTO_ACKNOWLEDGED:
            if isinstance(wire_id, int):
                results[wire_id] = {"id": wire_id, "result": {}}
            return
        turn = next(turn_iter, None)
        if turn is None:
            return
        if turn.events:
            deliver_events(turn.events)
        if isinstance(wire_id, int) and turn.reply is not None:
            reply = {key: value for key, value in turn.reply.items() if key != "id"}
            results[wire_id] = {"id": wire_id, **reply}

    inspector.send_socket_data = send_socket_data  # type: ignore[method-assign]

    page = Page.from_page_dictionary({
        "WIRPageIdentifierKey": 1,
        "WIRTypeKey": "WIRTypeJavaScript",
        "WIRTitleKey": "JSContext",
        "WIRURLKey": "",
    })
    application = Application(
        "PID:1", "com.example.app", 1, "App", AutomationAvailability.NOT_AVAILABLE, 1, False, True
    )
    target = CdpTarget(SessionProtocol(inspector, session_id, application, page, method_prefix=""), "jscontext")
    assert target._flat, "the golden replay models the un-multiplexed JSContext path"

    emitted: list[dict[str, Any]] = []

    async def drain() -> None:
        while True:
            emitted.append(await target.receive())

    drain_task = asyncio.ensure_future(drain())
    try:
        if initial_events:
            deliver_events(initial_events)
        for command in editor:
            await target.send(dict(command))
            await asyncio.sleep(0.02)
        await asyncio.sleep(settle)
    finally:
        drain_task.cancel()
        for task in (target._input_task, target._receiving_task):
            task.cancel()
    return emitted
