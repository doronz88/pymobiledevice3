import asyncio

import pytest

from pymobiledevice3.remote.common import ConnectionType
from pymobiledevice3.remote.tunnel_service import (
    get_core_device_tunnel_services,
    get_remote_pairing_tunnel_services,
    start_tunnel,
)


@pytest.mark.parametrize("connection_type", [ConnectionType.USB, ConnectionType.WIFI])
@pytest.mark.asyncio
async def test_start_tunnel(connection_type: ConnectionType):
    get_tunnel_services = {
        connection_type.USB: get_core_device_tunnel_services,
        connection_type.WIFI: get_remote_pairing_tunnel_services,
    }
    tunnel_services = await get_tunnel_services[connection_type]()
    async with start_tunnel(tunnel_services[0]):
        await asyncio.sleep(1)
    for tunnel_service in tunnel_services:
        await tunnel_service.close()
