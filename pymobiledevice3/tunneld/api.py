import json
import socket
from http.client import HTTPConnection
from typing import Any, Optional, Union

import requests

from pymobiledevice3.exceptions import TunneldConnectionError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

TUNNELD_DEFAULT_ADDRESS = ("127.0.0.1", 49151)

# Address of a running ``tunneld`` HTTP server: either a ``(host, port)`` TCP address
# or a ``str`` path to a unix domain socket.
TunneldAddress = Union[tuple[str, int], str]


class _UnixHTTPConnection(HTTPConnection):
    """HTTPConnection over a unix domain socket."""

    def __init__(self, path: str) -> None:
        super().__init__("localhost")
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self._path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


async def get_tunneld_devices(
    tunneld_address: TunneldAddress = TUNNELD_DEFAULT_ADDRESS,
) -> list[RemoteServiceDiscoveryService]:
    """
    Query a running ``tunneld`` instance over HTTP for all active tunnels and connect to each.

    :param tunneld_address: ``(host, port)`` of the ``tunneld`` HTTP server, or a unix domain socket path.
    :returns: a connected `RemoteServiceDiscoveryService`
        for every tunnel that could be reached; tunnels that fail to connect are skipped.
    :raises TunneldConnectionError: if the ``tunneld`` instance cannot be reached.
    """
    tunnels = _list_tunnels(tunneld_address)
    return await _create_rsds_from_tunnels(tunnels)


async def get_tunneld_device_by_udid(
    udid: str, tunneld_address: TunneldAddress = TUNNELD_DEFAULT_ADDRESS
) -> Optional[RemoteServiceDiscoveryService]:
    """
    Query a running ``tunneld`` instance over HTTP for the tunnel matching a given UDID and connect.

    :param udid: UDID of the target device.
    :param tunneld_address: ``(host, port)`` of the ``tunneld`` HTTP server, or a unix domain socket path.
    :returns: a connected
        `RemoteServiceDiscoveryService` for
        the device, or ``None`` if ``tunneld`` reports no tunnel for the UDID.
    :raises TunneldConnectionError: if the ``tunneld`` instance cannot be reached.
    """
    tunnels = _list_tunnels(tunneld_address)
    if udid not in tunnels:
        return None
    rsds = await _create_rsds_from_tunnels({udid: tunnels[udid]})
    return rsds[0]


def _list_tunnels(tunneld_address: TunneldAddress = TUNNELD_DEFAULT_ADDRESS) -> dict[str, list[dict[str, Any]]]:
    try:
        if isinstance(tunneld_address, str):
            # Get the list of tunnels over a unix domain socket
            conn = _UnixHTTPConnection(tunneld_address)
            try:
                conn.request("GET", "/")
                tunnels = json.loads(conn.getresponse().read())
            finally:
                conn.close()
        else:
            # Get the list of tunnels from the specified address
            resp = requests.get(f"http://{tunneld_address[0]}:{tunneld_address[1]}")
            tunnels = resp.json()
    except (requests.exceptions.ConnectionError, OSError) as e:
        raise TunneldConnectionError() from e
    return tunnels


async def _create_rsds_from_tunnels(tunnels: dict[str, list[dict[str, Any]]]) -> list[RemoteServiceDiscoveryService]:
    rsds: list[RemoteServiceDiscoveryService] = []
    for _udid, details in tunnels.items():
        for tunnel_details in details:
            rsd = RemoteServiceDiscoveryService(
                (tunnel_details["tunnel-address"], tunnel_details["tunnel-port"]),
                name=tunnel_details["interface"],
                auxiliary_metadata=tunnel_details.get("auxiliary-metadata"),
            )
            try:
                await rsd.connect()
                rsds.append(rsd)
            except (TimeoutError, ConnectionError):
                continue
    return rsds
