import asyncio
import socket
import ssl
from typing import cast

import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError
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


def test_ssl_start_sync_failure_raises_connection_terminated(monkeypatch):
    # A failed handshake leaves the original socket detached by wrap_socket(); the error
    # path must not touch it again (used to raise EBADF/WinError 10038, masking the error).
    client, server = socket.socketpair()
    server.close()
    conn = ServiceConnection(client)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    monkeypatch.setattr(ServiceConnection, "create_ssl_context", lambda self, certfile, keyfile=None: context)

    with pytest.raises(ConnectionTerminatedError):
        conn.ssl_start_sync("unused-certfile")
