import socket
import socketserver
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Sequence
from typing import Any, Optional

import pytest
import requests

from pymobiledevice3.tunneld.api import TunneldConnectDialer
from pymobiledevice3.tunneld.server import WS_CLOSE_CONNECT_FAILED, WS_CLOSE_NO_TUNNEL, normalize_upstream_url
from pymobiledevice3.tunneld.ws_bridge import connect as ws_connect

UDID_A = "00008120-000000000000000A"
UDID_B = "00008120-000000000000000B"

# A tunneld with all monitors disabled and a single fake established tunnel, so a federation
# topology can be built out of device-less servers.
TUNNELD_SCRIPT = (
    "import sys\n"
    "from typing import Any, cast\n"
    "from pymobiledevice3.remote.common import TunnelProtocol\n"
    "from pymobiledevice3.remote.tunnel_service import TunnelResult\n"
    "from pymobiledevice3.tunneld.server import TunneldRunner, TunnelTask\n"
    "port, udid, tunnel_port, upstreams = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]\n"
    "tunnel_address = sys.argv[5]\n"
    "runner = TunneldRunner('127.0.0.1', port, usb_monitor=False, wifi_monitor=False, "
    "usbmux_monitor=False, mobdev2_monitor=False, upstreams=[u for u in upstreams.split(',') if u])\n"
    "if udid:\n"
    "    runner._tunneld_core.tunnel_tasks[f'fake-{udid}'] = TunnelTask(\n"
    "        task=cast(Any, None), udid=udid,\n"
    "        tunnel=TunnelResult(interface=f'fake-{udid}', address=tunnel_address, port=tunnel_port,\n"
    "                            protocol=TunnelProtocol.TCP, client=cast(Any, None)))\n"
    "runner._run_app()\n"
)

# The fake tunnel's address: what an RSD would dial, and what tunneld connects to
TUNNEL_ADDRESS = "127.0.0.1"


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(65536)
            if not data:
                break
            self.request.sendall(data)


@pytest.fixture(scope="module")
def echo_port() -> Iterator[int]:
    """A TCP echo server standing in for a service on a device's tunnel address."""
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), _EchoHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=10)


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _spawn_tunneld(
    udid: str = "",
    tunnel_port: Optional[int] = None,
    upstreams: Sequence[str] = (),
    tunnel_address: str = TUNNEL_ADDRESS,
) -> tuple[subprocess.Popen[bytes], int]:
    port = _unused_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            TUNNELD_SCRIPT,
            str(port),
            udid,
            str(tunnel_port if tunnel_port is not None else _unused_port()),
            ",".join(upstreams),
            tunnel_address,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 30
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return proc, port
        except OSError:
            assert proc.poll() is None, "tunneld server exited prematurely"
            assert time.monotonic() < deadline, "tunneld server did not come up"
            time.sleep(0.1)


@pytest.fixture
def federated_pair() -> Iterator[tuple[int, int]]:
    """Two tunnelds, each holding one fake tunnel and registering the other as an upstream."""
    procs = []
    try:
        proc_a, port_a = _spawn_tunneld(UDID_A)
        procs.append(proc_a)
        proc_b, port_b = _spawn_tunneld(UDID_B)
        procs.append(proc_b)
        requests.post(f"http://127.0.0.1:{port_a}/upstream", json={"url": f"http://127.0.0.1:{port_b}"}, timeout=10)
        requests.post(f"http://127.0.0.1:{port_b}/upstream", json={"url": f"http://127.0.0.1:{port_a}"}, timeout=10)
        yield port_a, port_b
    finally:
        for proc in procs:
            # the injected fake TunnelTask has no real asyncio task, so skip graceful shutdown
            proc.kill()
            proc.wait(timeout=10)


def _list_tunnels(port: int) -> dict[str, list[dict[str, Any]]]:
    resp = requests.get(f"http://127.0.0.1:{port}", timeout=30)
    resp.raise_for_status()
    return resp.json()


def test_mutual_upstreams_merge_both_listings(federated_pair: tuple[int, int]) -> None:
    """A cycle must still federate: without a hop budget the nested fetch loses the race against
    its parent's timeout, so the upstream's own device goes missing from the merged listing."""
    port_a, port_b = federated_pair
    for port, own_udid, peer_udid in ((port_a, UDID_A, UDID_B), (port_b, UDID_B, UDID_A)):
        tunnels = _list_tunnels(port)
        assert set(tunnels) == {own_udid, peer_udid}, tunnels


def test_mutual_upstreams_report_each_tunnel_once(federated_pair: tuple[int, int]) -> None:
    """A tunnel reachable through several federation paths is listed once, not once per path."""
    tunnels = _list_tunnels(federated_pair[0])
    for udid, entries in tunnels.items():
        assert len(entries) == 1, f"{udid} duplicated across federation paths: {entries}"


def test_federation_terminates_promptly(federated_pair: tuple[int, int]) -> None:
    """The hop budget bounds a cycle, so a listing never waits out cascading fetch timeouts."""
    started = time.monotonic()
    _list_tunnels(federated_pair[0])
    assert time.monotonic() - started < 10


@pytest.fixture
def aggregator(echo_port: int) -> Iterator[tuple[int, int]]:
    """An aggregator holding no devices, fronting a downstream tunneld whose fake tunnel points at
    the echo server — the lab topology: only the aggregator is reachable from the client."""
    procs = []
    try:
        proc_b, port_b = _spawn_tunneld(UDID_B, tunnel_port=echo_port)
        procs.append(proc_b)
        proc_a, port_a = _spawn_tunneld(upstreams=[f"http://127.0.0.1:{port_b}"])
        procs.append(proc_a)
        yield port_a, port_b
    finally:
        for proc in procs:
            proc.kill()
            proc.wait(timeout=10)


def test_aggregator_lists_upstream_device_with_origin(aggregator: tuple[int, int]) -> None:
    """A federated entry names the hop that reported it, so a client can act on the listing."""
    port_a, port_b = aggregator
    tunnels = _list_tunnels(port_a)
    assert set(tunnels) == {UDID_B}
    assert tunnels[UDID_B][0]["origin"] == f"http://127.0.0.1:{port_b}"


def test_local_entries_report_no_origin(federated_pair: tuple[int, int]) -> None:
    """An instance's own tunnels carry a null origin: its /connect reaches them directly."""
    port_a, _ = federated_pair
    assert _list_tunnels(port_a)[UDID_A][0]["origin"] is None


async def test_connect_relays_through_aggregator(aggregator: tuple[int, int], echo_port: int) -> None:
    """The headline capability: a client with a route only to the aggregator reaches a device
    attached to the downstream host, with no VPN and no route to that host's tunnel interface."""
    port_a, _ = aggregator
    dialer = TunneldConnectDialer(("127.0.0.1", port_a), UDID_B, TUNNEL_ADDRESS)
    reader, writer = await dialer.dial(TUNNEL_ADDRESS, echo_port)
    try:
        for payload in (b"through two hops", b"\x00\xff" * 40000):
            writer.write(payload)
            await writer.drain()
            assert await reader.readexactly(len(payload)) == payload
    finally:
        writer.close()


async def test_connect_reports_no_tunnel_when_no_upstream_owns_it(aggregator: tuple[int, int]) -> None:
    """A UDID served by neither the aggregator nor its upstreams still closes with 4404."""
    port_a, _ = aggregator
    upstream = await ws_connect("127.0.0.1", port_a, "non-existing-udid")
    try:
        assert await upstream.recv_bytes() is None
        assert upstream.close_code == WS_CLOSE_NO_TUNNEL
    finally:
        upstream.close()


async def test_relayed_close_code_is_preserved(aggregator: tuple[int, int]) -> None:
    """A failure at the far end keeps its own close code, so a two-hop topology stays debuggable."""
    port_a, _ = aggregator
    # a released port, not one held bound-but-unlistening: macOS answers the latter with silence
    # rather than an RST, so the far end would burn its full connect timeout before refusing.
    # A port stolen in the gap makes this assert fail loudly rather than pass silently.
    upstream = await ws_connect("127.0.0.1", port_a, UDID_B, _unused_port())
    try:
        assert await upstream.recv_bytes() is None
        assert upstream.close_code == WS_CLOSE_CONNECT_FAILED
    finally:
        upstream.close()


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("lab-1", "http://lab-1:49151"),
        ("lab-1:8080", "http://lab-1:8080"),
        ("http://lab-1", "http://lab-1:49151"),
        ("http://lab-1:8080", "http://lab-1:8080"),
        ("http://lab-1:8080/", "http://lab-1:8080"),
        ("  http://lab-1:8080  ", "http://lab-1:8080"),
        ("[fd00::1]:49151", "http://[fd00::1]:49151"),
        ("http://[fd00::1]", "http://[fd00::1]:49151"),
        ("192.168.0.7:49151", "http://192.168.0.7:49151"),
    ],
)
def test_normalize_upstream_url(spec: str, expected: str) -> None:
    assert normalize_upstream_url(spec) == expected


@pytest.mark.parametrize(
    "spec,message",
    [
        # the relay dials plaintext, so a TLS upstream would be silently mis-dialed
        ("https://lab-1", "only http:// upstreams"),
        ("http://lab-1/tunneld", "bare host"),
        ("http://lab-1?x=1", "bare host"),
        ("http://", "names no host"),
        ("http://lab-1:portly", "invalid port"),
    ],
)
def test_normalize_upstream_url_rejects(spec: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        normalize_upstream_url(spec)


def test_add_upstream_stores_the_canonical_form(federated_pair: tuple[int, int]) -> None:
    """A schemeless registration is accepted and canonicalized, so both federation paths agree."""
    port_a, _ = federated_pair
    resp = requests.post(f"http://127.0.0.1:{port_a}/upstream", json={"url": "lab-9:1234"}, timeout=10)
    assert resp.status_code == 200
    assert "http://lab-9:1234" in requests.get(f"http://127.0.0.1:{port_a}/upstream", timeout=10).json()
    # and it can be removed by the spelling it was added with
    requests.delete(f"http://127.0.0.1:{port_a}/upstream", json={"url": "lab-9:1234"}, timeout=10)
    assert "http://lab-9:1234" not in requests.get(f"http://127.0.0.1:{port_a}/upstream", timeout=10).json()


def test_add_upstream_rejects_unusable_url(federated_pair: tuple[int, int]) -> None:
    """An upstream neither federation path could act on fails loudly at registration."""
    port_a, _ = federated_pair
    resp = requests.post(f"http://127.0.0.1:{port_a}/upstream", json={"url": "https://lab-9"}, timeout=10)
    assert resp.status_code == 400
    assert "only http:// upstreams" in resp.json()["error"]


async def test_schemeless_upstream_relays(echo_port: int) -> None:
    """The friendly 'HOST:PORT' spelling works through the whole stack, not just the parser."""
    procs = []
    try:
        proc_b, port_b = _spawn_tunneld(UDID_B, tunnel_port=echo_port)
        procs.append(proc_b)
        proc_a, port_a = _spawn_tunneld(upstreams=[f"127.0.0.1:{port_b}"])
        procs.append(proc_a)
        dialer = TunneldConnectDialer(("127.0.0.1", port_a), UDID_B, TUNNEL_ADDRESS)
        reader, writer = await dialer.dial(TUNNEL_ADDRESS, echo_port)
        try:
            writer.write(b"schemeless")
            await writer.drain()
            assert await reader.readexactly(10) == b"schemeless"
        finally:
            writer.close()
    finally:
        for proc in procs:
            proc.kill()
            proc.wait(timeout=10)


# TEST-NET-1: routable nowhere, so a bridge that picks this tunnel cannot succeed by accident
UNREACHABLE_TUNNEL_ADDRESS = "192.0.2.1"


async def test_connect_picks_the_tunnel_the_client_named(echo_port: int) -> None:
    """A device can have two tunnels — one held here, one on an upstream — when both tunnelds
    monitor the same host. Keying only on the UDID paired this instance's tunnel address with the
    caller's port, dialing an endpoint that exists nowhere; the address names which tunnel to use.
    """
    procs = []
    try:
        proc_b, port_b = _spawn_tunneld(UDID_B, tunnel_port=echo_port, tunnel_address=TUNNEL_ADDRESS)
        procs.append(proc_b)
        proc_a, port_a = _spawn_tunneld(
            UDID_B,  # same device, its own tunnel, as a monitoring aggregator would have
            tunnel_port=echo_port,
            tunnel_address=UNREACHABLE_TUNNEL_ADDRESS,
            upstreams=[f"http://127.0.0.1:{port_b}"],
        )
        procs.append(proc_a)
        # the client asks the aggregator for the upstream's tunnel, by address
        dialer = TunneldConnectDialer(("127.0.0.1", port_a), UDID_B, TUNNEL_ADDRESS)
        reader, writer = await dialer.dial(TUNNEL_ADDRESS, echo_port)
        try:
            writer.write(b"named tunnel")
            await writer.drain()
            assert await reader.readexactly(12) == b"named tunnel"
        finally:
            writer.close()
    finally:
        for proc in procs:
            proc.kill()
            proc.wait(timeout=10)


async def test_connect_still_serves_its_own_tunnel_by_address(echo_port: int) -> None:
    """The instance's own tunnel is still served directly when the client names that one."""
    procs = []
    try:
        proc, port = _spawn_tunneld(UDID_B, tunnel_port=echo_port, tunnel_address=TUNNEL_ADDRESS)
        procs.append(proc)
        dialer = TunneldConnectDialer(("127.0.0.1", port), UDID_B, TUNNEL_ADDRESS)
        reader, writer = await dialer.dial(TUNNEL_ADDRESS, echo_port)
        try:
            writer.write(b"own tunnel")
            await writer.drain()
            assert await reader.readexactly(10) == b"own tunnel"
        finally:
            writer.close()
    finally:
        for proc in procs:
            proc.kill()
            proc.wait(timeout=10)
