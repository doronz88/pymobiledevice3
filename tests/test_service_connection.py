import asyncio
import errno
import socket
import ssl
import struct
import sys
from typing import cast

import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError, DeviceNotFoundError
from pymobiledevice3.service_connection import ServiceConnection

pytestmark = pytest.mark.usefixtures("socket_hygiene")


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
async def test_service_connection_close_aborts_when_wait_closed_hangs():
    writer = _FakeWriter()
    conn = ServiceConnection(asyncio.StreamReader(), cast(asyncio.StreamWriter, writer))

    await conn.close()

    assert writer.closed is True
    assert writer.transport.aborted is True
    with pytest.raises(ConnectionTerminatedError):
        await conn.sendall(b"\x00")


def _client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


# CPython <= 3.10 leaves the half-built SSLSocket unclosed when the handshake fails inside
# wrap_socket(), so it emits a ResourceWarning when collected. Reproducible with plain CPython and
# no pymobiledevice3 involved, and the socket is never ours to close -- wrap_socket() owns it.
@pytest.mark.filterwarnings("ignore::ResourceWarning")
@pytest.mark.asyncio
async def test_strip_ssl_handshake_failure_raises_connection_terminated():
    # A failed handshake leaves the original socket detached by wrap_socket(); the error
    # path must not touch it again (used to raise EBADF/WinError 10038, masking the error).
    client, server = socket.socketpair()
    server.close()
    with pytest.raises(ConnectionTerminatedError):
        await ServiceConnection.from_socket(client, ssl_context=_client_context(), strip_ssl=True)
    assert client.fileno() == -1


@pytest.mark.asyncio
async def test_sendall_after_peer_closed_raises_connection_terminated():
    # Once the peer is gone asyncio fails a send with ConnectionResetError("Connection lost"), then with
    # the stored socket error (BrokenPipeError). Both mean the device dropped us. On Windows socketpair()
    # is TCP, so sends are still accepted until the peer's RST comes back; keep sending until one fails.
    host, device = socket.socketpair()
    connection = await ServiceConnection.from_socket(host)
    try:
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
    connection = await ServiceConnection.from_socket(host)
    try:
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
    connection = await ServiceConnection.from_socket(host)
    try:
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
    connection = await ServiceConnection.from_socket(host)
    error = TimeoutError(errno.ETIMEDOUT, "Operation timed out")

    async def failing_drain() -> None:
        raise error

    try:
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
async def test_failed_tls_bind_leaves_no_transport_on_the_fd():
    """A handshake the peer refuses must close the socket through its transport: a transport left
    live on the fd would claim the number the OS hands to the next socket, and asyncio then refuses
    every sock_* call on it ("File descriptor N is used by transport")."""
    sock, peer = socket.socketpair()
    fd = sock.fileno()
    peer.close()
    with pytest.raises(ConnectionTerminatedError):
        await ServiceConnection.from_socket(sock, ssl_context=_client_context())
    await asyncio.sleep(0)
    assert _live_transport(fd) is None
    assert sock.fileno() == -1


@pytest.mark.asyncio
async def test_cancelled_tls_bind_leaves_no_transport_on_the_fd():
    """Cancelling the bind mid-handshake (a timeout, a closing caller) must not leave the fd owned
    by a live transport either."""
    sock, peer = socket.socketpair()  # the peer never answers the ClientHello
    fd = sock.fileno()
    try:
        bind = asyncio.create_task(ServiceConnection.from_socket(sock, ssl_context=_client_context()))
        await asyncio.sleep(0.1)  # waiting for the ServerHello
        bind.cancel()
        with pytest.raises(asyncio.CancelledError):
            await bind
        await asyncio.sleep(0)
        assert _live_transport(fd) is None
        assert sock.fileno() == -1
    finally:
        peer.close()


@pytest.mark.asyncio
async def test_close_releases_the_fd():
    sock, peer = socket.socketpair()
    fd = sock.fileno()
    try:
        connection = await ServiceConnection.from_socket(sock)
        await connection.close()
        await asyncio.sleep(0)
        assert _live_transport(fd) is None
        assert sock.fileno() == -1
        with pytest.raises(ConnectionTerminatedError):
            await connection.recv_any()
    finally:
        peer.close()


@pytest.mark.asyncio
async def test_tcp_tls_failure_raises_connection_terminated():
    """A peer that drops the handshake ends it as ConnectionTerminatedError, as over usbmux."""

    async def refuse(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(1)  # the ClientHello
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(refuse, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(ConnectionTerminatedError):
            await ServiceConnection.create_using_tcp("127.0.0.1", port, keep_alive=False, ssl_context=_client_context())
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_tcp_rejects_stripped_tls():
    with pytest.raises(ValueError):
        await ServiceConnection.create_using_tcp("127.0.0.1", 1, ssl_context=_client_context(), strip_ssl=True)


@pytest.mark.asyncio
async def test_close_wakes_a_task_blocked_in_recv():
    sock, peer = socket.socketpair()
    connection = await ServiceConnection.from_socket(sock)
    try:
        blocked = asyncio.create_task(connection.recvall(4))
        await asyncio.sleep(0.01)
        await connection.close()
        with pytest.raises(ConnectionTerminatedError):
            await asyncio.wait_for(blocked, timeout=2)
    finally:
        peer.close()


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "win32", reason="a socketpair send there completes though the peer never reads")
async def test_close_wakes_a_task_blocked_in_send():
    sock, peer = socket.socketpair()  # the peer never reads, so the send buffers fill up
    # Small kernel buffers and no transport buffering make the send block at once.
    for end, option in ((sock, socket.SO_SNDBUF), (peer, socket.SO_RCVBUF)):
        end.setsockopt(socket.SOL_SOCKET, option, 4096)
    connection = await ServiceConnection.from_socket(sock)
    connection.writer.transport.set_write_buffer_limits(high=0)
    try:
        blocked = asyncio.create_task(connection.sendall(b"\x00" * (64 * 1024 * 1024)))
        await asyncio.sleep(0.05)
        assert not blocked.done()
        await connection.close()
        with pytest.raises(ConnectionTerminatedError):
            await asyncio.wait_for(blocked, timeout=2)
    finally:
        peer.close()


@pytest.mark.asyncio
async def test_concurrent_closes_release_the_fd_once():
    sock, peer = socket.socketpair()
    connection = await ServiceConnection.from_socket(sock)
    try:
        await asyncio.wait_for(asyncio.gather(connection.close(), connection.close(), connection.close()), timeout=5)
        assert sock.fileno() == -1
    finally:
        peer.close()


@pytest.mark.asyncio
async def test_close_during_start_tls_does_not_install_the_tls_writer():
    sock, peer = socket.socketpair()  # the peer never answers the ClientHello
    connection = await ServiceConnection.from_socket(sock)
    plain_writer = connection.writer
    try:
        upgrade = asyncio.create_task(connection.start_tls(_client_context()))
        await asyncio.sleep(0.05)
        await connection.close()
        with pytest.raises(ConnectionTerminatedError):
            await asyncio.wait_for(upgrade, timeout=5)
        assert connection.writer is plain_writer
    finally:
        peer.close()
