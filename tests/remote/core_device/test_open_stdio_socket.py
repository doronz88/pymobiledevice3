import uuid
from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import NotConnectedError
from pymobiledevice3.remote.core_device.app_service import AppServiceService
from pymobiledevice3.remote.core_device.open_stdio_socket import OpenStdioSocketService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

IDENTIFIER = uuid.UUID("e8708c6e-cf44-4f1b-8a71-bbb238d22e66")


class FakeConnection:
    def __init__(self, inbound: bytes) -> None:
        self._inbound = inbound
        self.sent = b""
        self.closed = False

    async def recvall(self, size: int) -> bytes:
        data, self._inbound = self._inbound[:size], self._inbound[size:]
        return data

    async def recv_any(self, size: int) -> bytes:
        return await self.recvall(size)

    async def sendall(self, data: bytes) -> None:
        self.sent += data

    async def close(self) -> None:
        self.closed = True


class FakeRsd:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.ports: list[int] = []

    def get_service_port(self, name: str) -> int:
        assert name == "com.apple.coredevice.openstdiosocket"
        return 1234

    async def create_service_connection(self, port: int) -> FakeConnection:
        self.ports.append(port)
        return self.connection


@pytest.mark.asyncio
async def test_connect_reads_the_identifier_then_relays_bytes() -> None:
    connection = FakeConnection(IDENTIFIER.bytes + b"hello\r\n")
    rsd = FakeRsd(connection)

    async with OpenStdioSocketService(cast(RemoteServiceDiscoveryService, rsd)) as stdio:
        assert stdio.identifier == IDENTIFIER
        assert await stdio.read() == b"hello\r\n"
        assert await stdio.read() == b""
        await stdio.write(b"input\n")

    assert rsd.ports == [1234] and connection.sent == b"input\n" and connection.closed


def test_identifier_requires_a_connection() -> None:
    with pytest.raises(NotConnectedError):
        _ = OpenStdioSocketService(cast(RemoteServiceDiscoveryService, object())).identifier


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        (None, {}),
        (IDENTIFIER, {"standardInput": IDENTIFIER, "standardOutput": IDENTIFIER, "standardError": IDENTIFIER}),
    ],
)
async def test_launch_application_attaches_the_stdio_socket(
    monkeypatch: pytest.MonkeyPatch, identifier: Any, expected: dict[str, Any]
) -> None:
    service = AppServiceService(cast(RemoteServiceDiscoveryService, object()))
    requests: list[dict[str, Any]] = []

    async def invoke(feature: str, request: dict[str, Any]) -> dict[str, Any]:
        requests.append(request)
        return {}

    monkeypatch.setattr(service, "invoke", invoke)

    await service.launch_application("com.example.app", stdio_identifier=identifier)

    assert requests[0]["standardIOIdentifiers"] == expected
