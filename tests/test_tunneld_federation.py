import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from typing import Any

import pytest
import requests

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
    "port, udid, tunnel_port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])\n"
    "runner = TunneldRunner('127.0.0.1', port, usb_monitor=False, wifi_monitor=False, "
    "usbmux_monitor=False, mobdev2_monitor=False)\n"
    "runner._tunneld_core.tunnel_tasks[f'fake-{udid}'] = TunnelTask(\n"
    "    task=cast(Any, None), udid=udid,\n"
    "    tunnel=TunnelResult(interface=f'fake-{udid}', address='127.0.0.1', port=tunnel_port,\n"
    "                        protocol=TunnelProtocol.TCP, client=cast(Any, None)))\n"
    "runner._run_app()\n"
)


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _spawn_tunneld(udid: str) -> tuple[subprocess.Popen[bytes], int]:
    port = _unused_port()
    proc = subprocess.Popen(
        [sys.executable, "-c", TUNNELD_SCRIPT, str(port), udid, str(_unused_port())],
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
