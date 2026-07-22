import asyncio
import socket
from typing import cast

import pytest

from pymobiledevice3.service_connection import ServiceConnection


class _FakeTransport:
    def __init__(self) -> None:
        self.aborted = False

    def abort(self) -> None:
        self.aborted = True


class _FakeWriter:
    def __init__(self) -> None:
        self.transport = _FakeTransport()
        self.closed = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.Future()


@pytest.mark.asyncio
async def test_service_connection_close_aborts_when_wait_closed_hangs(monkeypatch):
    sock = socket.socket()
    conn = ServiceConnection(sock)
    writer = _FakeWriter()
    conn.writer = cast(asyncio.StreamWriter, writer)

    await conn.close()

    assert writer.closed is True
    assert writer.transport.aborted is True
    assert conn.writer is None
    assert conn.reader is None
    assert conn.socket is None
    assert sock.fileno() == -1
