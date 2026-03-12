import asyncio

import pytest

from pymobiledevice3.exceptions import AccessDeniedError, QuicProtocolNotSupportedError
from pymobiledevice3.remote.common import ConnectionType
from pymobiledevice3.remote.tunnel_service import (
    get_core_device_tunnel_services,
    get_remote_pairing_tunnel_services,
    start_tunnel,
)


@pytest.mark.parametrize("connection_type", [ConnectionType.USB, ConnectionType.WIFI])
@pytest.mark.asyncio
async def test_start_tunnel(connection_type: ConnectionType) -> None:
    get_tunnel_services = {
        connection_type.USB: get_core_device_tunnel_services,
        connection_type.WIFI: get_remote_pairing_tunnel_services,
    }
    try:
        tunnel_services = await get_tunnel_services[connection_type]()
    except AccessDeniedError:
        pytest.skip("Skipping tunnel test: insufficient permissions to manage remoted on this host")
    except asyncio.TimeoutError:
        pytest.skip("Skipping tunnel test: timed out discovering tunnel services")
    if not tunnel_services:
        pytest.skip(f"No {connection_type.value} tunnel services available")

    try:
        try:
            async with start_tunnel(tunnel_services[0]):
                await asyncio.sleep(1)
        except QuicProtocolNotSupportedError:
            pytest.skip("Skipping tunnel test: QUIC is not supported on this device/runtime")
        except asyncio.TimeoutError:
            pytest.skip("Skipping tunnel test: timed out connecting to available tunnel service")
        except Exception as e:
            if "Failed to create any utun interface" in str(e):
                pytest.skip("Skipping tunnel test: unable to create utun interface on this host")
            raise
    finally:
        for tunnel_service in tunnel_services:
            await tunnel_service.close()
