import asyncio
from typing import Optional

import pytest

from pymobiledevice3.exceptions import FileRelayError
from pymobiledevice3.services.file_relay import (
    DEFAULT_SOURCE,
    FileRelayService,
    file_relay_unsupported_message,
    is_file_relay_likely_supported,
)


class _FakeFileRelayConnection:
    def __init__(self, response: dict, chunks: Optional[list[bytes]] = None) -> None:
        self.response = response
        self.chunks = list(chunks or [])
        self.sent_plists = []

    async def send_plist(self, request: dict) -> None:
        self.sent_plists.append(request)

    async def recv_plist(self) -> dict:
        return self.response

    async def recv_any(self, _chunk_size: int) -> bytes:
        if not self.chunks:
            return b""
        return self.chunks.pop(0)


def _file_relay_service(connection: _FakeFileRelayConnection) -> FileRelayService:
    service = FileRelayService(object())
    service._service = connection
    return service


@pytest.mark.parametrize(
    ("product_version", "expected"),
    [
        ("7.1.2", True),
        ("8.0", False),
        ("17.5", False),
        ("invalid", True),
    ],
)
def test_is_file_relay_likely_supported(product_version: str, expected: bool) -> None:
    assert is_file_relay_likely_supported(product_version) is expected


def test_file_relay_unsupported_message_points_to_override() -> None:
    message = file_relay_unsupported_message("17.5")

    assert "legacy service" in message
    assert "iOS 17.5" in message
    assert "--allow-unsupported" in message


@pytest.mark.asyncio
async def test_request_sources_uses_default_source() -> None:
    connection = _FakeFileRelayConnection({"Status": "Acknowledged"}, [b"archive", b""])
    service = _file_relay_service(connection)

    archive = await service.request_sources()

    assert archive == b"archive"
    assert connection.sent_plists == [{"Sources": [DEFAULT_SOURCE]}]


@pytest.mark.asyncio
async def test_iter_sources_streams_requested_sources() -> None:
    connection = _FakeFileRelayConnection({"Status": "Acknowledged"}, [b"part-1", b"part-2", b""])
    service = _file_relay_service(connection)

    chunks = [chunk async for chunk in service.iter_sources(["CrashReporter", "WiFi"], chunk_size=7)]

    assert chunks == [b"part-1", b"part-2"]
    assert connection.sent_plists == [{"Sources": ["CrashReporter", "WiFi"]}]


@pytest.mark.asyncio
async def test_iter_sources_raises_file_relay_error() -> None:
    response = {"Error": "InvalidSource"}
    connection = _FakeFileRelayConnection(response)
    service = _file_relay_service(connection)

    with pytest.raises(FileRelayError, match="InvalidSource") as exc:
        _ = [chunk async for chunk in service.iter_sources(["Invalid"])]

    assert exc.value.response == response


@pytest.mark.asyncio
async def test_iter_sources_raises_when_request_is_not_acknowledged() -> None:
    response = {"Status": "Unexpected"}
    connection = _FakeFileRelayConnection(response)
    service = _file_relay_service(connection)

    with pytest.raises(FileRelayError, match="not acknowledged") as exc:
        _ = [chunk async for chunk in service.iter_sources(["CrashReporter"])]

    assert exc.value.response == response


@pytest.mark.asyncio
async def test_iter_sources_raises_when_acknowledgement_times_out() -> None:
    class SlowConnection(_FakeFileRelayConnection):
        async def recv_plist(self) -> dict:
            await asyncio.Future()
            return {}

    connection = SlowConnection({"Status": "Acknowledged"})
    service = _file_relay_service(connection)

    with pytest.raises(FileRelayError, match="timed out"):
        _ = [chunk async for chunk in service.iter_sources(["CrashReporter"], timeout=0.01)]
