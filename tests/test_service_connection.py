import asyncio
import errno
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


@pytest.mark.asyncio
async def test_recv_any_after_peer_reset_raises_connection_terminated():
    with socket.create_server(("127.0.0.1", 0)) as server:
        host = socket.create_connection(server.getsockname())
        device, _ = server.accept()
    connection = ServiceConnection(host)
    try:
        await connection.start()
        device.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        device.close()
        with pytest.raises(ConnectionTerminatedError):
            await connection.recv_any()
    finally:
        device.close()
        await connection.close()


@pytest.mark.asyncio
async def test_socket_error_other_than_reset_raises_connection_terminated(monkeypatch):
    # A link that goes silent (Wi-Fi, keep-alive expiry) fails with ETIMEDOUT, an unreachable one with
    # EHOSTUNREACH. Neither is a ConnectionError, yet both mean the device is gone.
    host, device = socket.socketpair()
    connection = ServiceConnection(host)
    error = TimeoutError(errno.ETIMEDOUT, "Operation timed out")

    async def failing_drain() -> None:
        raise error

    try:
        await connection.start()
        assert connection.reader is not None and connection.writer is not None
        monkeypatch.setattr(connection.writer, "drain", failing_drain)
        with pytest.raises(ConnectionTerminatedError):
            await connection.sendall(b"\x00")
        # what asyncio does to the reader once the transport fails
        connection.reader.set_exception(error)
        with pytest.raises(ConnectionTerminatedError):
            await connection.recvall(4)
        with pytest.raises(ConnectionTerminatedError):
            await connection.recv_any()
    finally:
        device.close()
        await connection.close()


def _live_transport(fd: int) -> object:
    transport = getattr(asyncio.get_running_loop(), "_transports", {}).get(fd)
    return transport if transport is not None and not transport.is_closing() else None


@pytest.mark.asyncio
async def test_close_during_start_leaves_no_transport_on_the_fd():
    """A close() that lands while start() is still binding the socket must win: the fd must not be
    left owned by a live transport (the OS reuses the number for the next socket, which asyncio
    then refuses to touch), and the closed connection must not come back to life."""
    sock, peer = socket.socketpair()
    fd = sock.fileno()
    connection = ServiceConnection(sock)
    try:
        start = asyncio.ensure_future(connection.start())
        await asyncio.sleep(0)  # start() is inside open_connection(), its transport registered
        await connection.close()
        with pytest.raises(ConnectionTerminatedError):
            await start
        assert connection.reader is None and connection.writer is None
        await asyncio.sleep(0)
        assert _live_transport(fd) is None
        with pytest.raises(ConnectionTerminatedError):
            await connection.start()
    finally:
        peer.close()


@pytest.mark.asyncio
async def test_close_after_the_open_finishes_but_before_start_resumes():
    """The open can complete before close() runs while start() has yet to take its streams: close()
    must close those streams instead of the bare socket under them."""
    sock, peer = socket.socketpair()
    fd = sock.fileno()
    connection = ServiceConnection(sock)
    try:
        start = asyncio.ensure_future(connection.start())
        while connection._open_task is None or not connection._open_task.done():
            await asyncio.sleep(0)
        assert connection.writer is None, "start() resumed before close() could run"
        await connection.close()
        with pytest.raises(ConnectionTerminatedError):
            await start
        assert connection.reader is None and connection.writer is None
        await asyncio.sleep(0)
        assert _live_transport(fd) is None
    finally:
        peer.close()


@pytest.mark.asyncio
async def test_close_during_ssl_start_leaves_no_transport_on_the_fd(monkeypatch):
    """Same race as above for the TLS handshake that binds a not-yet-started socket."""
    sock, peer = socket.socketpair()  # the peer never answers the ClientHello
    fd = sock.fileno()
    connection = ServiceConnection(sock)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    monkeypatch.setattr(connection, "create_ssl_context", lambda certfile, keyfile=None: context)
    try:
        handshake = asyncio.ensure_future(connection.ssl_start("unused"))
        await asyncio.sleep(0.1)  # waiting for the ServerHello
        await connection.close()
        with pytest.raises(ConnectionTerminatedError):
            await asyncio.wait_for(handshake, timeout=5)
        assert connection.reader is None and connection.writer is None
        await asyncio.sleep(0)
        assert _live_transport(fd) is None
    finally:
        peer.close()
