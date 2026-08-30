import socket
import socketserver
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Iterator
from typing import Optional, Union

import pytest
from wsproto import ConnectionType, WSConnection
from wsproto.events import AcceptConnection, BytesMessage, CloseConnection, Event, Ping, Pong, Request

from pymobiledevice3.tunneld.server import WS_CLOSE_CONNECT_FAILED, WS_CLOSE_NO_TUNNEL

UDID = "00008120-0000000000000000"

# Runs a tunneld server with all monitors disabled and a single fake established tunnel whose
# address points at localhost instead of a device, so /connect proxies into local TCP servers.
TUNNELD_SCRIPT = (
    "import sys\n"
    "from typing import Any, cast\n"
    "from pymobiledevice3.remote.common import TunnelProtocol\n"
    "from pymobiledevice3.remote.tunnel_service import TunnelResult\n"
    "from pymobiledevice3.tunneld.server import TunneldRunner, TunnelTask\n"
    "runner = TunneldRunner('127.0.0.1', int(sys.argv[1]), usb_monitor=False, wifi_monitor=False, "
    "usbmux_monitor=False, mobdev2_monitor=False)\n"
    "runner._tunneld_core.tunnel_tasks['fake-interface'] = TunnelTask(\n"
    "    task=cast(Any, None), udid=sys.argv[3],\n"
    "    tunnel=TunnelResult(interface='fake-interface', address='127.0.0.1', port=int(sys.argv[2]),\n"
    "                        protocol=TunnelProtocol.TCP, client=cast(Any, None)))\n"
    "runner._run_app()\n"
)


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(65536)
            if not data:
                break
            self.request.sendall(data)


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def echo_port() -> Iterator[int]:
    """A TCP echo server on 127.0.0.1, standing in for a service on the device tunnel address."""
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), _EchoHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=10)


@pytest.fixture(scope="module")
def tunneld_port(echo_port: int) -> Iterator[int]:
    """A real tunneld server (uvicorn) whose fake tunnel RSD port is the echo server's port."""
    port = _unused_port()
    proc = subprocess.Popen(
        [sys.executable, "-c", TUNNELD_SCRIPT, str(port), str(echo_port), UDID],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                assert proc.poll() is None, "tunneld server exited prematurely"
                assert time.monotonic() < deadline, "tunneld server did not come up"
                time.sleep(0.1)
        yield port
    finally:
        # the injected fake TunnelTask has no real asyncio task, so skip graceful shutdown
        proc.kill()
        proc.wait(timeout=10)


class _WebsocketClient:
    """Minimal wsproto-based websocket client for exercising the /connect endpoint."""

    def __init__(self, port: int, target: str) -> None:
        self._sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self._ws = WSConnection(ConnectionType.CLIENT)
        self._events: deque[Event] = deque()
        self._send(Request(host=f"127.0.0.1:{port}", target=target))
        event = self.next_event()
        assert isinstance(event, AcceptConnection), f"websocket handshake failed: {event}"

    def __enter__(self) -> "_WebsocketClient":
        return self

    def __exit__(self, *args: object) -> None:
        self._sock.close()

    def _send(self, event: Event) -> None:
        self._sock.sendall(self._ws.send(event))

    def next_event(self) -> Event:
        while not self._events:
            data = self._sock.recv(65536)
            self._ws.receive_data(data if data else None)
            for event in self._ws.events():
                if isinstance(event, Ping):
                    self._send(Pong(payload=event.payload))
                    continue
                self._events.append(event)
        return self._events.popleft()

    def send_bytes(self, data: bytes) -> None:
        self._send(BytesMessage(data=data))

    def recv_bytes(self, count: int) -> bytes:
        """Receive exactly ``count`` payload bytes, reassembling message fragments."""
        received = b""
        while len(received) < count:
            event = self.next_event()
            assert isinstance(event, BytesMessage), f"expected a bytes message, got: {event}"
            received += event.data
        return received

    def recv_close(self) -> CloseConnection:
        event = self.next_event()
        assert isinstance(event, CloseConnection), f"expected a close, got: {event}"
        return event


def _connect(tunneld_port: int, udid: str = UDID, port: Optional[Union[int, str]] = None) -> _WebsocketClient:
    target = f"/connect?udid={udid}"
    if port is not None:
        target += f"&port={port}"
    return _WebsocketClient(tunneld_port, target)


def test_connect_no_tunnel_for_udid(tunneld_port: int) -> None:
    with _connect(tunneld_port, udid="non-existing-udid") as websocket:
        assert websocket.recv_close().code == WS_CLOSE_NO_TUNNEL


def test_connect_tcp_connection_refused(tunneld_port: int) -> None:
    with _connect(tunneld_port, port=_unused_port()) as websocket:
        assert websocket.recv_close().code == WS_CLOSE_CONNECT_FAILED


def test_connect_forwards_traffic_to_default_rsd_port(tunneld_port: int) -> None:
    with _connect(tunneld_port) as websocket:
        for payload in (b"hello over the tunnel", b"\x00\x01\x02\xff" * 25000):
            websocket.send_bytes(payload)
            assert websocket.recv_bytes(len(payload)) == payload


def test_connect_forwards_traffic_to_explicit_port(tunneld_port: int, echo_port: int) -> None:
    with _connect(tunneld_port, port=echo_port) as websocket:
        websocket.send_bytes(b"ping")
        assert websocket.recv_bytes(4) == b"ping"


def test_connect_parallel_connections(tunneld_port: int) -> None:
    with _connect(tunneld_port) as first, _connect(tunneld_port) as second:
        first.send_bytes(b"first")
        second.send_bytes(b"second")
        assert second.recv_bytes(6) == b"second"
        assert first.recv_bytes(5) == b"first"
