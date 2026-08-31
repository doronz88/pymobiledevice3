import asyncio
import http.server
import socket
import socketserver
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from typing import Optional

import pytest
import typer

from pymobiledevice3.cli.cli_common import _parse_tunnel_spec
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.tunneld.api import (
    TUNNELD_DEFAULT_ADDRESS,
    TunneldAddress,
    TunneldConnectDialer,
    _bridge_by_default,
)

UDID = "00008120-0000000000000000"

# The fake tunnel's address: what the RSD would dial, and what the tunneld server connects to
TUNNEL_ADDRESS = "127.0.0.1"

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


@pytest.fixture(scope="module")
def http_404_port() -> Iterator[int]:
    """A plain HTTP server rejecting every request, standing in for a tunneld without /connect."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_error(404)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
            pass

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=10)


def _dialer(tunneld_port: int, udid: str = UDID) -> TunneldConnectDialer:
    return TunneldConnectDialer(("127.0.0.1", tunneld_port), udid, TUNNEL_ADDRESS)


async def _wait_bridges_closed(dialer: TunneldConnectDialer) -> None:
    """Wait for every pump task to finish, so no bridge outlives its test's event loop."""
    deadline = time.monotonic() + 10
    while dialer._pumps:
        assert time.monotonic() < deadline, "bridge pump did not finish"
        await asyncio.sleep(0.01)


async def test_dial_roundtrip(tunneld_port: int, echo_port: int) -> None:
    dialer = _dialer(tunneld_port)
    reader, writer = await dialer.dial(TUNNEL_ADDRESS, echo_port)
    try:
        # the create_using_tcp contract: the returned writer carries a real socket
        assert writer.get_extra_info("socket") is not None
        for payload in (b"hello over the bridge", b"\x00\x01\x02\xff" * 25000):
            writer.write(payload)
            await writer.drain()
            assert await reader.readexactly(len(payload)) == payload
    finally:
        writer.close()
    await _wait_bridges_closed(dialer)


async def test_dial_via_service_connection(tunneld_port: int, echo_port: int) -> None:
    dialer = _dialer(tunneld_port)
    conn = await ServiceConnection.create_using_tcp(TUNNEL_ADDRESS, echo_port, open_connection=dialer.dial)
    try:
        await conn.sendall(b"service payload")
        assert await conn.recvall(15) == b"service payload"
    finally:
        await conn.aclose()
    await _wait_bridges_closed(dialer)


async def test_dial_unknown_udid_yields_eof(tunneld_port: int) -> None:
    dialer = _dialer(tunneld_port, udid="non-existing-udid")
    reader, writer = await dialer.dial(TUNNEL_ADDRESS, 12345)
    try:
        assert await reader.read(1) == b""
    finally:
        writer.close()
    await _wait_bridges_closed(dialer)


async def test_dial_rejected_by_server_without_connect(http_404_port: int) -> None:
    dialer = TunneldConnectDialer(("127.0.0.1", http_404_port), UDID, TUNNEL_ADDRESS)
    with pytest.raises(ConnectionError, match="rejected /connect"):
        await dialer.dial(TUNNEL_ADDRESS, 12345)


async def test_dial_invalid_handshake_from_non_http_server(echo_port: int) -> None:
    # an echo server reflects the websocket request back, which is not a valid handshake response
    dialer = TunneldConnectDialer(("127.0.0.1", echo_port), UDID, TUNNEL_ADDRESS)
    with pytest.raises(ConnectionError, match="invalid websocket handshake"):
        await dialer.dial(TUNNEL_ADDRESS, 12345)


async def test_dial_falls_through_for_other_hosts(tunneld_port: int, echo_port: int) -> None:
    # dials to anything but the tunnel address must use the stdlib dialer, not the bridge
    dialer = TunneldConnectDialer(("127.0.0.1", tunneld_port), UDID, "fdaa:1:2:3::1")
    reader, writer = await dialer.dial("127.0.0.1", echo_port)
    try:
        writer.write(b"direct")
        await writer.drain()
        assert await reader.readexactly(6) == b"direct"
        assert not dialer._pumps
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.parametrize(
    "spec,expected_udid,expected_address,expected_bridge",
    [
        (UDID, UDID, TUNNELD_DEFAULT_ADDRESS, None),
        (f"{UDID}:50000", UDID, ("127.0.0.1", 50000), None),
        ("", "", TUNNELD_DEFAULT_ADDRESS, None),
        (f"{UDID}@lab-mac", UDID, ("lab-mac", 49151), True),
        (f"{UDID}@lab-mac:8080", UDID, ("lab-mac", 8080), True),
        (f"{UDID}@192.168.0.7:8080", UDID, ("192.168.0.7", 8080), True),
        (f"{UDID}@[fd00::1]:8080", UDID, ("fd00::1", 8080), True),
        (f"{UDID}@[fd00::1]", UDID, ("fd00::1", 49151), True),
        (f"{UDID}@fd00::1", UDID, ("fd00::1", 49151), True),
        ("@lab-mac:8080", "", ("lab-mac", 8080), True),
        ("@lab-mac", "", ("lab-mac", 49151), True),
    ],
)
def test_parse_tunnel_spec(
    spec: str, expected_udid: str, expected_address: TunneldAddress, expected_bridge: Optional[bool]
) -> None:
    assert _parse_tunnel_spec(spec) == (expected_udid, expected_address, expected_bridge)


@pytest.mark.parametrize("spec", [f"{UDID}:/var/run/tunneld.sock", ":/tmp/user@host.sock"])
def test_parse_tunnel_spec_rejects_uds_path(spec: str) -> None:
    with pytest.raises(typer.BadParameter, match="unix-socket tunneld support was removed"):
        _parse_tunnel_spec(spec)


@pytest.mark.parametrize(
    "address,expected",
    [
        (("127.0.0.1", 49151), False),
        (("localhost", 49151), False),
        (("::1", 49151), False),
        (("192.168.0.7", 49151), True),
        (("lab-mac", 49151), True),
    ],
)
def test_bridge_by_default(address: TunneldAddress, expected: bool) -> None:
    assert _bridge_by_default(address) is expected


# Dials a bridge, exchanges traffic, then exits WITHOUT closing anything - like Ctrl+C on a
# live stream. The abandoned pump coroutines are closed by GC with GeneratorExit; any await in
# their finally blocks would surface as "coroutine ignored GeneratorExit" on stderr.
ABANDON_SCRIPT = (
    "import asyncio, sys\n"
    "from pymobiledevice3.tunneld.api import TunneldConnectDialer\n"
    "async def main():\n"
    "    dialer = TunneldConnectDialer(('127.0.0.1', int(sys.argv[1])), sys.argv[2], '127.0.0.1')\n"
    "    reader, writer = await dialer.dial('127.0.0.1', int(sys.argv[3]))\n"
    "    writer.write(b'x' * 1024)\n"
    "    await writer.drain()\n"
    "    await reader.readexactly(1024)\n"
    "loop = asyncio.new_event_loop()\n"
    "loop.run_until_complete(main())\n"
    "# exit with the bridge still open and the loop never cleaned up\n"
)


def test_abandoned_bridge_exits_cleanly(tunneld_port: int, echo_port: int) -> None:
    """Exiting mid-bridge (e.g. Ctrl+C on a live stream) must not spew coroutine teardown errors."""
    result = subprocess.run(
        [sys.executable, "-c", ABANDON_SCRIPT, str(tunneld_port), UDID, str(echo_port)],
        capture_output=True,
        timeout=30,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "GeneratorExit" not in result.stderr, result.stderr
    assert "was never awaited" not in result.stderr, result.stderr
