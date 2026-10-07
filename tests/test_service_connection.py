import asyncio
import socket
import ssl
import struct
from typing import cast

import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError, DeviceNotFoundError
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
async def test_create_using_usbmux_missing_device_explains_the_failed_lookup(monkeypatch):
    """DeviceNotFoundError must carry a message naming the lookup that failed, on top of the
    machine-readable `udid` member."""

    async def no_device(udid, connection_type=None, usbmux_address=None):
        return None

    monkeypatch.setattr("pymobiledevice3.service_connection.select_device", no_device)

    with pytest.raises(DeviceNotFoundError) as exc_info:
        await ServiceConnection.create_using_usbmux("TARGET-UDID", 62078, connection_type="USB")

    assert exc_info.value.udid == "TARGET-UDID"
    assert str(exc_info.value) == "Device not found: usbmux has no device matching udid TARGET-UDID over USB"


def test_device_not_found_error_defaults_to_a_message() -> None:
    """A raise site that passes only the udid still yields a self-explanatory `str(exc)`."""
    error = DeviceNotFoundError("TARGET-UDID")
    assert str(error) == "Device not found: TARGET-UDID"
    assert error.udid == "TARGET-UDID"


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


# CPython <= 3.10 leaves the half-built SSLSocket unclosed when the handshake fails inside
# wrap_socket(), so it emits a ResourceWarning when collected. Reproducible with plain CPython and
# no pymobiledevice3 involved, and the socket is never ours to close -- wrap_socket() owns it.
@pytest.mark.filterwarnings("ignore::ResourceWarning")
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


@pytest.mark.asyncio
async def test_sendall_after_peer_closed_raises_connection_terminated():
    # Once the peer is gone asyncio fails a send with ConnectionResetError("Connection lost"), then with
    # the stored socket error (BrokenPipeError). Both mean the device dropped us. On Windows socketpair()
    # is TCP, so sends are still accepted until the peer's RST comes back; keep sending until one fails.
    host, device = socket.socketpair()
    connection = ServiceConnection(host)
    try:
        await connection.start()
        device.close()
        for _ in range(2):
            with pytest.raises(ConnectionTerminatedError):
                for _ in range(200):
                    await connection.sendall(b"\x00" * 1024)
                    await asyncio.sleep(0.01)
    finally:
        device.close()
        await connection.close()


@pytest.mark.asyncio
async def test_recvall_after_peer_reset_raises_connection_terminated():
    with socket.create_server(("127.0.0.1", 0)) as server:
        host = socket.create_connection(server.getsockname())
        device, _ = server.accept()
    connection = ServiceConnection(host)
    try:
        await connection.start()
        # Linger 0 makes close() send RST instead of FIN, like a device dropping off the bus.
        device.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        device.close()
        with pytest.raises(ConnectionTerminatedError):
            await connection.recvall(4)
    finally:
        device.close()
        await connection.close()
