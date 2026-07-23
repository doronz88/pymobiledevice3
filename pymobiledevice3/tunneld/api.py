from typing import Any, Optional

import requests

from pymobiledevice3.exceptions import TunneldConnectionError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

TUNNELD_DEFAULT_ADDRESS = ("127.0.0.1", 49151)


async def get_tunneld_devices(
    tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS,
) -> list[RemoteServiceDiscoveryService]:
    """
    Query a running ``tunneld`` instance over HTTP for all active tunnels and connect to each.

    :param tunneld_address: ``(host, port)`` of the ``tunneld`` HTTP server.
    :returns: a connected `RemoteServiceDiscoveryService`
        for every tunnel that could be reached; tunnels that fail to connect are skipped.
    :raises TunneldConnectionError: if the ``tunneld`` instance cannot be reached.
    """
    tunnels = _list_tunnels(tunneld_address)
    return await _create_rsds_from_tunnels(tunnels)


async def get_tunneld_device_by_udid(
    udid: str, tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS
) -> Optional[RemoteServiceDiscoveryService]:
    """
    Query a running ``tunneld`` instance over HTTP for the tunnel matching a given UDID and connect.

    :param udid: UDID of the target device.
    :param tunneld_address: ``(host, port)`` of the ``tunneld`` HTTP server.
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


def _list_tunnels(tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS) -> dict[str, list[dict[str, Any]]]:
    try:
        # Get the list of tunnels from the specified address
        resp = requests.get(f"http://{tunneld_address[0]}:{tunneld_address[1]}")
        tunnels = resp.json()
    except requests.exceptions.ConnectionError as e:
        raise TunneldConnectionError() from e
    return tunnels


async def _create_rsds_from_tunnels(tunnels: dict[str, list[dict[str, Any]]]) -> list[RemoteServiceDiscoveryService]:
    rsds = []
    for _udid, details in tunnels.items():
        for tunnel_details in details:
            rsd = RemoteServiceDiscoveryService(
                (tunnel_details["tunnel-address"], tunnel_details["tunnel-port"]), name=tunnel_details["interface"]
            )
            try:
                await rsd.connect()
                rsds.append(rsd)
            except (TimeoutError, ConnectionError):
                continue
    return rsds
