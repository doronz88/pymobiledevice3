from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import CoreDeviceError
from pymobiledevice3.remote.core_device.display_service import (
    MEDIA_IN_USE_ERROR_CODE,
    DisplayService,
    is_media_in_use_error,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.remote.xpc_message import XpcUInt64Type

DISPLAY_SERVICE = "com.apple.coredevice.displayservice"
STOP_FEATURE = "com.apple.coredevice.feature.stopmediastream"


class FakeConnection:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []
        self.closed = False

    async def connect(self) -> None:
        pass

    async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(request)
        return {"CoreDevice.output": {"stoppedStreams": [], "serverInfo": {"running": False}}}

    async def close(self) -> None:
        self.closed = True


def _make_rsd() -> RemoteServiceDiscoveryService:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {
        "Properties": {"OSVersion": "26.0"},
        "Services": {DISPLAY_SERVICE: {"Port": "1024", "Properties": {"Features": [STOP_FEATURE]}}},
    }
    rsd.udid = "udid"
    return rsd


def _make_display_service() -> tuple[DisplayService, FakeConnection]:
    rsd = _make_rsd()
    service = DisplayService(rsd)
    connection = FakeConnection()
    service._service = cast(RemoteXPCConnection, connection)
    return service, connection


@pytest.mark.asyncio
async def test_stop_media_stream_sends_stopall_request() -> None:
    # The daemon decodes StopRequest(stopAll: Bool, identifiers: [UInt32]?). The default
    # stop targets the whole media-stream server; nothing else is in the payload.
    service, connection = _make_display_service()
    await service.stop_media_stream()
    assert len(connection.sent) == 1
    payload = connection.sent[0]["CoreDevice.input"]
    assert payload == {"stopAll": True}
    assert isinstance(payload["stopAll"], bool)


@pytest.mark.asyncio
async def test_stop_media_stream_with_identifiers() -> None:
    service, connection = _make_display_service()
    await service.stop_media_stream(stop_all=False, identifiers=[7, 9])
    payload = connection.sent[0]["CoreDevice.input"]
    assert payload["stopAll"] is False
    assert payload["identifiers"] == [7, 9]
    # Identifiers must be typed UInt32/64 so they encode as XPC integers, not a nested dict.
    assert all(isinstance(i, XpcUInt64Type) for i in payload["identifiers"])


@pytest.mark.asyncio
async def test_stop_all_streams_uses_a_fresh_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    # The stop MUST be the sole reply-bearing request on its RemoteXPC connection, so
    # stop_all_streams opens a brand-new connection and closes it — it never reuses one.
    rsd = _make_rsd()
    connection = FakeConnection()
    monkeypatch.setattr(rsd, "start_remote_service", lambda name: cast(RemoteXPCConnection, connection))

    result = await DisplayService.stop_all_streams(rsd)

    assert result == {"stoppedStreams": [], "serverInfo": {"running": False}}
    assert len(connection.sent) == 1
    assert connection.sent[0]["CoreDevice.input"] == {"stopAll": True}
    assert connection.closed is True


def test_is_media_in_use_error_matches_code_9022() -> None:
    assert is_media_in_use_error(CoreDeviceError("in use", code=MEDIA_IN_USE_ERROR_CODE))
    assert not is_media_in_use_error(CoreDeviceError("other", code=1))
    assert not is_media_in_use_error(CoreDeviceError("no code"))
    assert not is_media_in_use_error(ValueError("unrelated"))
