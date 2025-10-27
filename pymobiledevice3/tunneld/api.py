from typing import Optional

import requests

from pymobiledevice3.exceptions import TunneldConnectionError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.utils import get_asyncio_loop

TUNNELD_DEFAULT_ADDRESS = ("127.0.0.1", 49151)


async def async_get_tunneld_devices(
    tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS,
) -> list[RemoteServiceDiscoveryService]:
    tunnels = _list_tunnels(tunneld_address)
    return await _create_rsds_from_tunnels(tunnels)


def get_tunneld_devices(
    tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS,
) -> list[RemoteServiceDiscoveryService]:
    return get_asyncio_loop().run_until_complete(async_get_tunneld_devices(tunneld_address))


async def async_get_tunneld_device_by_udid(
    udid: str, tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS
) -> Optional[RemoteServiceDiscoveryService]:
    tunnels = _list_tunnels(tunneld_address)
    if udid not in tunnels:
        return None
    rsds = await _create_rsds_from_tunnels({udid: tunnels[udid]})
    return rsds[0]


def get_tunneld_device_by_udid(
    udid: str, tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS
) -> Optional[RemoteServiceDiscoveryService]:
    return get_asyncio_loop().run_until_complete(async_get_tunneld_device_by_udid(udid, tunneld_address))


def _list_tunnels(tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS) -> dict[str, list[dict]]:
    try:
        # Get the list of tunnels from the specified address
        resp = requests.get(f"http://{tunneld_address[0]}:{tunneld_address[1]}")
        tunnels = resp.json()
    except requests.exceptions.ConnectionError as e:
        raise TunneldConnectionError() from e
    return tunnels


async def _create_rsds_from_tunnels(tunnels: dict[str, list[dict]]) -> list[RemoteServiceDiscoveryService]:
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
