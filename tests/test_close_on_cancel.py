"""A connection opened by a connect/create helper must be closed when the helper is cancelled midway.

`except Exception` does not catch `asyncio.CancelledError`, so a `wait_for()` timeout or a Ctrl-C during a
handshake used to leave the just-opened connection registered with the event loop and unreachable.
"""

import asyncio
import contextlib
import socket
from typing import Any, cast

import pytest

from pymobiledevice3 import usbmux
from pymobiledevice3.lockdown import RemoteLockdownClient, create_using_remote
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.service_connection import ServiceConnection


async def _cancel_once_blocked(task: "asyncio.Task[Any]", blocked: asyncio.Event) -> None:
    await asyncio.wait_for(blocked.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


class IdleService:
    """A lockdownd connection that only records whether it was closed."""

    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_create_using_remote_closes_the_connection_when_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    # A cancellation inside a lockdown request is cleaned up by `_request()` itself; block between
    # requests instead, where only the creation helper can close the connection.
    blocked = asyncio.Event()

    async def hanging_initialize(self: RemoteLockdownClient) -> None:
        blocked.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(RemoteLockdownClient, "_initialize", hanging_initialize)
    service = IdleService()
    task = asyncio.create_task(create_using_remote(cast(ServiceConnection, service), identifier="udid"))

    await _cancel_once_blocked(task, blocked)

    assert service.closed


@pytest.mark.asyncio
async def test_remotexpc_connect_closes_the_connection_when_cancelled() -> None:
    accepted = asyncio.Event()
    peer_closed = asyncio.Event()

    async def silent_peer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Never answer the handshake; report when the client side goes away.
        accepted.set()
        with contextlib.suppress(ConnectionError):
            while await reader.read(4096):
                pass
        peer_closed.set()
        writer.close()

    server = await asyncio.start_server(silent_peer, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    connection = RemoteXPCConnection(("127.0.0.1", port))
    try:
        task = asyncio.create_task(connection.connect())

        await _cancel_once_blocked(task, accepted)

        assert connection._writer is None
        await asyncio.wait_for(peer_closed.wait(), 5)
    finally:
        # Server.wait_closed() waits for live connections on Python 3.12.1+, so drop ours first.
        await connection.close()
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_create_usbmux_socket_closes_the_socket_when_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    blocked = asyncio.Event()
    sockets: list[socket.socket] = []

    async def hanging_sock_connect(sock: socket.socket, address: Any) -> None:
        sockets.append(sock)
        blocked.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(asyncio.get_running_loop(), "sock_connect", hanging_sock_connect)
    task = asyncio.create_task(usbmux.MuxConnection.create_usbmux_socket("127.0.0.1:1"))

    await _cancel_once_blocked(task, blocked)

    assert sockets[0].fileno() == -1
