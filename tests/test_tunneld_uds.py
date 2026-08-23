import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from pymobiledevice3.cli.cli_common import _parse_tunnel_spec
from pymobiledevice3.exceptions import TunneldConnectionError
from pymobiledevice3.tunneld.api import TUNNELD_DEFAULT_ADDRESS, _list_tunnels, get_tunneld_devices

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="unix domain sockets are not supported on Windows")


def test_parse_tunnel_spec_bare_udid() -> None:
    assert _parse_tunnel_spec("abc123") == ("abc123", TUNNELD_DEFAULT_ADDRESS)


def test_parse_tunnel_spec_empty() -> None:
    assert _parse_tunnel_spec("") == ("", TUNNELD_DEFAULT_ADDRESS)


def test_parse_tunnel_spec_port() -> None:
    assert _parse_tunnel_spec("abc123:1234") == ("abc123", (TUNNELD_DEFAULT_ADDRESS[0], 1234))


def test_parse_tunnel_spec_uds_path() -> None:
    assert _parse_tunnel_spec("abc123:/tmp/tunneld.sock") == ("abc123", "/tmp/tunneld.sock")


def test_parse_tunnel_spec_uds_path_no_udid() -> None:
    assert _parse_tunnel_spec(":/tmp/tunneld.sock") == ("", "/tmp/tunneld.sock")


def test_list_tunnels_missing_socket_raises_tunneld_connection_error() -> None:
    with pytest.raises(TunneldConnectionError):
        _list_tunnels(str(Path(tempfile.mkdtemp()) / "missing.sock"))


async def test_tunneld_server_over_unix_socket() -> None:
    """End-to-end: TunneldRunner bound to a unix socket, queried through the UDS client path."""
    uds = str(Path(tempfile.mkdtemp()) / "tunneld.sock")
    script = (
        "import sys\n"
        "from pymobiledevice3.tunneld.server import TunneldRunner\n"
        "TunneldRunner.create('127.0.0.1', 0, uds=sys.argv[1], usb_monitor=False, wifi_monitor=False, "
        "usbmux_monitor=False, mobdev2_monitor=False)\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", script, uds], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.connect(uds)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                assert proc.poll() is None, "tunneld server exited prematurely"
                assert time.monotonic() < deadline, "tunneld server did not come up on the unix socket"
                time.sleep(0.1)

        assert _list_tunnels(uds) == {}
        assert await get_tunneld_devices(uds) == []
    finally:
        proc.terminate()
        proc.wait(timeout=10)
