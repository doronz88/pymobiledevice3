import asyncio
import socket
import struct
from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import CoreDeviceError, DeviceVersionNotSupportedError
from pymobiledevice3.remote.core_device.display_service import (
    MEDIA_IN_USE_ERROR_CODE,
    DisplayService,
    is_media_in_use_error,
)
from pymobiledevice3.remote.core_device.screen_stream import ScreenStreamServer
from pymobiledevice3.remote.core_device.vnc_server import VncStreamServer
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


def _make_rsd(os_version: str = "26.0") -> RemoteServiceDiscoveryService:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {
        "Properties": {"OSVersion": os_version},
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
@pytest.mark.parametrize("reset", [False, True], ids=["close", "reset"])
async def test_stop_media_stream_counts_a_dropped_connection_as_stopped(reset: bool) -> None:
    # A device tearing the tunnel down can drop the channel after taking the request, before it replies.
    with socket.create_server(("127.0.0.1", 0)) as server:
        host = socket.create_connection(server.getsockname())
        device, _ = server.accept()
    device.setblocking(False)
    connection = RemoteXPCConnection(("127.0.0.1", 0))
    connection._reader, connection._writer = await asyncio.open_connection(sock=host)
    service = DisplayService(_make_rsd())
    service._service = connection

    async def drop_after_request() -> None:
        await asyncio.get_running_loop().sock_recv(device, 65536)
        if reset:
            device.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        device.close()

    try:
        dropper = asyncio.create_task(drop_after_request())
        assert await service.stop_media_stream() == {"stopped": True}
        await dropper
    finally:
        device.close()
        await connection.close()


@pytest.mark.asyncio
async def test_stop_all_streams_uses_a_connection_of_its_own(monkeypatch: pytest.MonkeyPatch) -> None:
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


@pytest.mark.asyncio
async def test_start_video_stream_refuses_devices_before_ios_27() -> None:
    # iOS 26 accepts the start request but never sends a frame (#2151), so it is not sent at all
    service, connection = _make_display_service()
    with pytest.raises(DeviceVersionNotSupportedError, match=r"iOS 27\.0 or later"):
        await service.start_video_stream(receiver_ip="::1", receiver_port=1, sender_ip="::2")
    assert connection.sent == []


async def _never_called(*args: Any, **kwargs: Any) -> None:
    raise AssertionError("reached the device")


@pytest.mark.asyncio
async def test_serve_web_refuses_devices_before_ios_27(monkeypatch: pytest.MonkeyPatch) -> None:
    # Its eager stream start swallows failures, so the version is checked before it
    monkeypatch.setattr(ScreenStreamServer, "_eager_stream_start", _never_called)
    server = ScreenStreamServer(_make_rsd("26.5.2"), http_port=0)
    with pytest.raises(DeviceVersionNotSupportedError):
        await server.serve()


@pytest.mark.asyncio
async def test_serve_vnc_refuses_devices_before_ios_27(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(DisplayService, "connect", _never_called)
    server = VncStreamServer(_make_rsd("26.5.2"), port=0)
    with pytest.raises(DeviceVersionNotSupportedError):
        await server.serve()
