import logging
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio

from pymobiledevice3.exceptions import DeviceNotFoundError, InvalidServiceError
from pymobiledevice3.lockdown import UsbmuxLockdownClient, create_using_usbmux
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.tunneld.api import get_tunneld_devices

logging.getLogger("quic").disabled = True
logging.getLogger("asyncio").disabled = True
logging.getLogger("parso.cache").disabled = True
logging.getLogger("parso.cache.pickle").disabled = True
logging.getLogger("parso.python.diff").disabled = True
logging.getLogger("humanfriendly.prompts").disabled = True
logging.getLogger("blib2to3.pgen2.driver").disabled = True
logging.getLogger("urllib3.connectionpool").disabled = True


def pytest_addoption(parser):
    parser.addoption("--rsd", default=None, type=str, nargs=2, action="store")
    parser.addoption("--tunnel", default=None, type=str, action="store")


@pytest.fixture(scope="function")
def rsd_option(request):
    """
    Get --rsd option
    """
    return request.config.getoption("--rsd")


@pytest.fixture(scope="function")
def tunnel_option(request):
    """
    Get --tunnel option
    """
    return request.config.getoption("--tunnel")


@pytest_asyncio.fixture(scope="function")
async def service_provider(
    rsd_option, tunnel_option
) -> AsyncGenerator[RemoteServiceDiscoveryService | UsbmuxLockdownClient, Any]:
    """
    Creates a new LockdownServiceProvider client for each test.
    """
    if rsd_option is not None:
        async with RemoteServiceDiscoveryService(rsd_option) as rsd:
            yield rsd
    elif tunnel_option is not None:
        rsds = await get_tunneld_devices()
        try:
            if tunnel_option == "":
                yield rsds[0]
            else:
                yield next(rsd for rsd in rsds if rsd.udid == tunnel_option)
            for rsd in rsds:
                await rsd.close()
        except IndexError as e:
            raise DeviceNotFoundError(tunnel_option) from e
    else:
        async with await create_using_usbmux() as client:
            yield client


@pytest_asyncio.fixture(scope="function")
async def dvt(service_provider) -> AsyncGenerator[DvtSecureSocketProxyService, Any]:
    """
    Creates a new DvtSecureSocketProxyService client for each test.
    """
    try:
        async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
            yield dvt
    except InvalidServiceError:
        pytest.skip("Skipping DVT-based test since the service isn't accessible")


@pytest_asyncio.fixture(scope="function")
async def lockdown() -> AsyncGenerator[UsbmuxLockdownClient, Any]:
    """
    Creates a new lockdown client for each test.
    """
    async with await create_using_usbmux() as client:
        yield client
