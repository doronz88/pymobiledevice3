import asyncio
import errno
import socket
import ssl
import struct
import sys
import threading
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from pymobiledevice3.ca import dump_cert, make_cert, serialize_private_key_pkcs8_pem
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


@pytest.mark.asyncio
async def test_strip_ssl_handshake_failure_raises_connection_terminated():
    client, server = socket.socketpair()
    server.close()
    with pytest.raises(ConnectionTerminatedError):
        await ServiceConnection.from_socket(client, ssl_context=_client_context(), strip_ssl=True)
    await asyncio.sleep(0)
    assert client.fileno() == -1


@pytest.mark.asyncio
async def test_strip_ssl_fails_fast_on_a_peer_that_is_not_speaking_tls():
    client, server = socket.socketpair()
    try:
        server.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        with pytest.raises(ConnectionTerminatedError):
            await asyncio.wait_for(
                ServiceConnection.from_socket(client, ssl_context=_client_context(), strip_ssl=True), timeout=2
            )
    finally:
        server.close()


@pytest.fixture(scope="module")
def server_certfile(tmp_path_factory: pytest.TempPathFactory) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path_factory.mktemp("tls") / "server.pem"
    path.write_bytes(
        dump_cert(make_cert(key, key.public_key(), common_name="test")) + serialize_private_key_pkcs8_pem(key)
    )
    return str(path)


def _stripping_server(sock: socket.socket, certfile: str, version: ssl.TLSVersion, received: list[bytes]) -> None:
    """The device side of a stripped-TLS service: a TLS handshake, then plaintext both ways."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = version
    # A TLS 1.3 session ticket is an encrypted record sent after the handshake: a service that
    # switches to plaintext cannot send one (with tickets, both the old blocking strip and this one
    # would hand the record to the plaintext stream).
    context.num_tickets = 0
    context.load_cert_chain(certfile)
    with context.wrap_socket(sock, server_side=True) as tls:
        plain = socket.socket(fileno=tls.detach())
    with plain:
        plain.sendall(b"hello")
        received.append(plain.recv(4))


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
@pytest.mark.parametrize("over", ["usbmux", "tcp"])
async def test_strip_ssl_carries_plaintext_after_the_handshake(
    server_certfile: str, version: ssl.TLSVersion, over: str
) -> None:
    received: list[bytes] = []
    if over == "usbmux":
        client, device = socket.socketpair()
        thread = threading.Thread(target=_stripping_server, args=(device, server_certfile, version, received))
        thread.start()
        connection = await ServiceConnection.from_socket(client, ssl_context=_client_context(), strip_ssl=True)
    else:
        listener = socket.create_server(("127.0.0.1", 0))

        def accept_and_serve() -> None:
            with listener:
                device, _ = listener.accept()
            _stripping_server(device, server_certfile, version, received)

        thread = threading.Thread(target=accept_and_serve)
        thread.start()
        connection = await ServiceConnection.create_using_tcp(
            "127.0.0.1", listener.getsockname()[1], keep_alive=False, ssl_context=_client_context(), strip_ssl=True
        )
    try:
        assert await connection.recvall(5) == b"hello"
        await connection.sendall(b"ping")
        await asyncio.get_running_loop().run_in_executor(None, thread.join, 5)
        assert received == [b"ping"]
    finally:
        await connection.close()


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


@pytest.mark.asyncio
async def test_cancel_as_the_dial_completes_closes_what_it_dialed():
    """A caller cancelled in the same loop iteration its dial completes (a timeout, a shutdown)
    must not leave the dialed connection open: wait_for drops that result on the floor."""
    sock, peer = socket.socketpair()
    dialed = asyncio.get_running_loop().create_future()
    gate = asyncio.get_running_loop().create_future()

    async def dialer(hostname: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        streams = await asyncio.open_connection(sock=sock)
        dialed.set_result(None)
        await gate
        return streams

    try:
        creating = asyncio.create_task(ServiceConnection.create_using_tcp("device", 1, open_connection=dialer))
        await dialed
        gate.set_result(None)  # the dial completes on the next iteration...
        creating.cancel()  # ...the iteration its caller is cancelled in
        try:
            connection = await creating
        except asyncio.CancelledError:
            pass
        else:  # Python <= 3.11's wait_for can drop the cancellation instead of the result
            await connection.close()
        for _ in range(5):
            await asyncio.sleep(0)
        assert sock.fileno() == -1
    finally:
        peer.close()
