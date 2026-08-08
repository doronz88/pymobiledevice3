import asyncio
import json
import logging
from types import SimpleNamespace
from typing import Any, Optional

import pytest

from pymobiledevice3.services.web_protocol.inspector_session import InspectorSession


@pytest.fixture()
async def session():
    protocol = SimpleNamespace(inspector=SimpleNamespace(wir_events=[]))
    session = InspectorSession(protocol, target_id="page-1")  # pyright: ignore[reportArgumentType]
    yield session
    session._receive_task.cancel()


def _wrap_target_event(inner: dict[str, Any]) -> dict[str, Any]:
    # events pushed by the page arrive wrapped in Target.dispatchMessageFromTarget,
    # with the inner message JSON-encoded and carrying no 'id'
    return {
        "method": "Target.dispatchMessageFromTarget",
        "params": {"targetId": "page-1", "message": json.dumps(inner)},
    }


async def test_runtime_execution_context_created_is_not_logged_as_unhandled(
    session: InspectorSession, caplog: pytest.LogCaptureFixture
) -> None:
    # observed live: WebKit pushes this right after Runtime.enable
    event = {
        "method": "Runtime.executionContextCreated",
        "params": {"context": {"id": 2, "type": "normal", "name": "", "frameId": "0.1"}},
    }
    with caplog.at_level(logging.DEBUG, logger="pymobiledevice3.services.web_protocol.inspector_session"):
        session._target_dispatch_message_from_target(_wrap_target_event(event))
    assert not [record for record in caplog.records if record.levelno >= logging.CRITICAL]


async def test_truly_unknown_event_still_logged(session: InspectorSession, caplog: pytest.LogCaptureFixture) -> None:
    event = {"method": "Bogus.event", "params": {}}
    with caplog.at_level(logging.DEBUG, logger="pymobiledevice3.services.web_protocol.inspector_session"):
        session._target_dispatch_message_from_target(_wrap_target_event(event))
    assert [record for record in caplog.records if record.levelno >= logging.CRITICAL]


def _console_message_added(text: str, parameters: Optional[list[dict[str, Any]]]) -> dict[str, Any]:
    message: dict[str, Any] = {"source": "console-api", "level": "log", "type": "log", "text": text}
    if parameters is not None:
        message["parameters"] = parameters
    return {"method": "Console.messageAdded", "params": {"message": message}}


def _console_record(
    session: InspectorSession, caplog: pytest.LogCaptureFixture, event: dict[str, Any], force_live: bool = True
) -> logging.LogRecord:
    if force_live:
        # formatting tests represent messages logged after Console.enable completed
        session._console_replay = False
    with caplog.at_level(logging.DEBUG, logger="webinspector.console"):
        session._target_dispatch_message_from_target(_wrap_target_event(event))
    assert len(caplog.records) == 1
    return caplog.records[0]


def _console_output(session: InspectorSession, caplog: pytest.LogCaptureFixture, event: dict[str, Any]) -> str:
    return _console_record(session, caplog, event).getMessage()


async def test_console_log_multiple_arguments(session: InspectorSession, caplog: pytest.LogCaptureFixture) -> None:
    # captured live from console.log(4,4): 'text' carries only the first argument,
    # 'parameters' carries all of them
    event = _console_message_added(
        "4",
        [
            {"type": "number", "value": 4, "description": "4"},
            {"type": "number", "value": 4, "description": "4"},
        ],
    )
    assert _console_output(session, caplog, event) == "4 4"


async def test_console_log_mixed_arguments(session: InspectorSession, caplog: pytest.LogCaptureFixture) -> None:
    event = _console_message_added(
        "hello",
        [
            {"type": "string", "value": "hello"},
            {"type": "boolean", "value": True},
            {"type": "undefined"},
            {"type": "object", "className": "Object", "description": "Object", "objectId": "obj-1"},
        ],
    )
    assert _console_output(session, caplog, event) == "hello true undefined Object"


async def test_console_message_without_parameters_uses_text(
    session: InspectorSession, caplog: pytest.LogCaptureFixture
) -> None:
    # page-originated messages (e.g. resource errors) carry no 'parameters'
    event = _console_message_added("Failed to load resource", None)
    assert _console_output(session, caplog, event) == "Failed to load resource"


async def test_console_history_replayed_before_enable_completes_is_marked(
    session: InspectorSession, caplog: pytest.LogCaptureFixture
) -> None:
    # WebKit replays the page's buffered console history while Console.enable is being
    # processed; those messages are distinguishable (and silenceable) by logger name
    event = _console_message_added("4", [{"type": "number", "value": 4, "description": "4"}])
    record = _console_record(session, caplog, event, force_live=False)
    assert record.name == "webinspector.console.replay"
    assert record.getMessage() == "4"


async def test_console_enable_completion_switches_to_live_output(
    session: InspectorSession, caplog: pytest.LogCaptureFixture
) -> None:
    async def send_command(method: str, **kwargs: Any) -> None:
        pass

    session.protocol.send_command = send_command  # pyright: ignore[reportAttributeAccessIssue]
    task = asyncio.create_task(session.console_enable())
    # deliver the Console.enable response (inner id 1) so console_enable completes
    session.protocol.inspector.wir_events.append(_wrap_target_event({"id": 1, "result": {}}))
    await asyncio.wait_for(task, timeout=5)
    event = _console_message_added("4", [{"type": "number", "value": 4, "description": "4"}])
    # console_enable itself must have switched the session out of replay state
    record = _console_record(session, caplog, event, force_live=False)
    assert record.name == "webinspector.console"
    assert record.getMessage() == "4"


async def test_get_properties_raw_returns_descriptors(session: InspectorSession) -> None:
    async def send_command(method: str, **kwargs: Any) -> dict[str, Any]:
        assert method == "Runtime.getProperties"
        assert kwargs == {"objectId": "obj-1", "ownProperties": True, "generatePreview": True}
        inner = {"result": {"properties": [{"name": "a", "value": {"type": "number", "value": 1}}]}}
        return {"params": {"message": json.dumps(inner)}}

    session.send_command = send_command  # pyright: ignore[reportAttributeAccessIssue]
    properties = await session.get_properties_raw("obj-1")
    assert properties == [{"name": "a", "value": {"type": "number", "value": 1}}]
