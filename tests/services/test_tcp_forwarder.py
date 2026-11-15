import asyncio
import socket
import struct
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest

from pymobiledevice3.lockdown import SERVICE_PORT, LockdownClient
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.tcp_forwarder import TcpForwarderBase, UsbmuxTcpForwarder

FREE_PORT = 3582


class DummyForwarder(TcpForwarderBase):
    async def _establish_remote_connection(self) -> ServiceConnection:
        raise NotImplementedError


async def attempt_local_connection(port: int) -> None:
    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.close()
    await writer.wait_closed()


@pytest.mark.parametrize("dst_port", [FREE_PORT, SERVICE_PORT])
@pytest.mark.asyncio
async def test_tcp_forwarder_bad_port(lockdown: LockdownClient, dst_port: int) -> None:
    # start forwarder
    assert lockdown.udid is not None
    forwarder = UsbmuxTcpForwarder(lockdown.udid, dst_port, FREE_PORT)
    task = asyncio.create_task(forwarder.start())

    try:
        # wait for it to actually start listening
        for _ in range(100):
            if forwarder.server is not None:
                break
            await asyncio.sleep(0.01)
        assert forwarder.server is not None
        await attempt_local_connection(FREE_PORT)

    finally:
        # tell it to stop
        forwarder.stop()
        # make sure it stops
        await asyncio.wait_for(task, timeout=5)


@pytest.mark.asyncio
async def test_tcp_forwarder_ephemeral_port_and_asyncio_event() -> None:
    listening_event = asyncio.Event()
    forwarder = DummyForwarder(0, listening_event=listening_event)
    task = asyncio.create_task(forwarder.start())

    try:
        await asyncio.wait_for(listening_event.wait(), timeout=5)
        assert forwarder.server is not None
        assert forwarder.listening_port is not None
        assert forwarder.listening_port > 0
    finally:
        forwarder.stop()
        await asyncio.wait_for(task, timeout=5)


class LoopbackConnection:
    """Stands in for the device side of a forwarded connection: a stream to a local TCP server."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()


class LoopbackForwarder(TcpForwarderBase):
    def __init__(self, remote_port: int) -> None:
        super().__init__(0, listening_event=asyncio.Event())
        self.remote_port = remote_port

    async def _establish_remote_connection(self) -> ServiceConnection:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.remote_port)
        return cast(ServiceConnection, LoopbackConnection(reader, writer))


@asynccontextmanager
async def running_loopback_forwarder() -> AsyncGenerator[tuple[LoopbackForwarder, "asyncio.Task[None]"], None]:
    """Run a forwarder whose remote end is a local server that holds every connection open."""
    remote_handlers: set[asyncio.Task[None]] = set()

    async def hold_open(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        remote_handlers.add(task)
        try:
            while await reader.read(4096):
                pass
        finally:
            writer.close()

    remote = await asyncio.start_server(hold_open, "127.0.0.1", 0)
    forwarder = LoopbackForwarder(remote.sockets[0].getsockname()[1])
    task = asyncio.create_task(forwarder.start())
    try:
        assert forwarder.listening_event is not None
        await asyncio.wait_for(forwarder.listening_event.wait(), timeout=5)
        yield forwarder, task
    finally:
        forwarder.stop()
        task.cancel()
        for handler in remote_handlers:
            handler.cancel()
        await asyncio.gather(task, *remote_handlers, return_exceptions=True)
        remote.close()
        await remote.wait_closed()


async def wait_for_connection_tasks(forwarder: TcpForwarderBase, count: int) -> None:
    for _ in range(500):
        if len(forwarder._connection_tasks) == count:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"expected {count} forwarded connections, have {len(forwarder._connection_tasks)}")


@pytest.mark.asyncio
async def test_tcp_forwarder_stops_while_a_connection_is_being_forwarded() -> None:
    # Server.wait_closed() waits for every accepted connection since Python 3.12.1, so the forwarder
    # has to end its connections before waiting for the listener.
    async with running_loopback_forwarder() as (forwarder, task):
        assert forwarder.listening_port is not None
        _reader, writer = await asyncio.open_connection("127.0.0.1", forwarder.listening_port)
        try:
            await wait_for_connection_tasks(forwarder, 1)

            forwarder.stop()
            await asyncio.wait_for(asyncio.shield(task), timeout=5)

            assert not forwarder._connection_tasks
        finally:
            writer.close()


@pytest.mark.asyncio
async def test_tcp_forwarder_forgets_a_connection_the_client_reset() -> None:
    async with running_loopback_forwarder() as (forwarder, _task):
        assert forwarder.listening_port is not None
        client = socket.create_connection(("127.0.0.1", forwarder.listening_port))
        try:
            await wait_for_connection_tasks(forwarder, 1)
            # SO_LINGER with a zero timeout turns close() into a reset.
            client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        finally:
            client.close()

        await wait_for_connection_tasks(forwarder, 0)


@pytest.mark.asyncio
async def test_tcp_forwarder_drops_a_connection_accepted_just_before_stop() -> None:
    # A connection is accepted a few event loop iterations before its handler first runs. A stop()
    # landing in between finds no handler to cancel, so the handler has to end the connection itself:
    # start() waits for it.
    forwarder = LoopbackForwarder(0)
    establish = AsyncMock()
    forwarder._establish_remote_connection = establish
    local_writer = Mock(wait_closed=AsyncMock())
    forwarder.stop()

    await forwarder._handle_server_connection(Mock(), local_writer)

    local_writer.close.assert_called_once_with()
    establish.assert_not_awaited()
    assert not forwarder._connection_tasks
