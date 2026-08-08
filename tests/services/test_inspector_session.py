import json
import logging
from types import SimpleNamespace
from typing import Any

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


async def test_truly_unknown_event_still_logged(
    session: InspectorSession, caplog: pytest.LogCaptureFixture
) -> None:
    event = {"method": "Bogus.event", "params": {}}
    with caplog.at_level(logging.DEBUG, logger="pymobiledevice3.services.web_protocol.inspector_session"):
        session._target_dispatch_message_from_target(_wrap_target_event(event))
    assert [record for record in caplog.records if record.levelno >= logging.CRITICAL]
