import contextlib
import socket
from collections.abc import Generator, Iterator
from typing import Any, cast

import pytest

from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.exceptions import ConnectionTerminatedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.service_connection import ServiceConnection


class _Lockdown:
    """Starts every service with SSL on a connection whose handshake fails."""

    def __init__(self) -> None:
        self.sock, self.peer = socket.socketpair()
        self.connection = ServiceConnection(self.sock)

        def failing_handshake(*args: Any, **kwargs: Any) -> None:
            raise ConnectionTerminatedError()

        async def failing_async_handshake(*args: Any, **kwargs: Any) -> None:
            failing_handshake()

        self.connection.ssl_start = failing_async_handshake  # type: ignore[method-assign]
        self.connection.ssl_start_sync = failing_handshake  # type: ignore[method-assign]

    async def get_service_connection_attributes(self, name: str, include_escrow_bag: bool = False) -> dict[str, Any]:
        return {"Port": 1, "EnableServiceSSL": True}

    async def create_service_connection(self, port: int) -> ServiceConnection:
        return self.connection

    @contextlib.contextmanager
    def ssl_file(self) -> Generator[str, None, None]:
        yield "unused-certfile"


@pytest.fixture
def lockdown() -> Iterator[_Lockdown]:
    lockdown = _Lockdown()
    yield lockdown
    lockdown.peer.close()
    lockdown.sock.close()


@pytest.mark.asyncio
async def test_start_lockdown_service_closes_the_connection_when_ssl_fails(lockdown: _Lockdown) -> None:
    with pytest.raises(ConnectionTerminatedError):
        await LockdownClient.start_lockdown_service(cast(Any, lockdown), "com.example.service")
    assert lockdown.connection.socket is None
    assert lockdown.sock.fileno() == -1


@pytest.mark.asyncio
@pytest.mark.parametrize("strip_ssl", [False, True])
async def test_dtx_open_closes_the_connection_when_ssl_fails(lockdown: _Lockdown, strip_ssl: bool) -> None:
    provider = cast(Any, type("Provider", (), {"lockdown": lockdown})())
    with pytest.raises(ConnectionTerminatedError):
        await DtxServiceProvider._open_dtx_connection(provider, "com.example.service", strip_ssl=strip_ssl)
    assert lockdown.connection.socket is None
    assert lockdown.sock.fileno() == -1
