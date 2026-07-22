import logging
from collections.abc import AsyncGenerator
from typing import Any, Union

import pytest
import pytest_asyncio

from pymobiledevice3.exceptions import (
    ConnectionFailedToUsbmuxdError,
    DeviceNotFoundError,
    InvalidServiceError,
    NoDeviceConnectedError,
)
from pymobiledevice3.lockdown import UsbmuxLockdownClient, create_using_usbmux
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.testmanaged.xcuitest import XCUITestService
from pymobiledevice3.tunneld.api import get_tunneld_devices

logging.getLogger("quic").setLevel(logging.CRITICAL + 1)
logging.getLogger("asyncio").setLevel(logging.CRITICAL + 1)
logging.getLogger("parso").setLevel(logging.CRITICAL + 1)
logging.getLogger("humanfriendly").setLevel(logging.CRITICAL + 1)
logging.getLogger("blib2to3").setLevel(logging.CRITICAL + 1)
logging.getLogger("urllib3").setLevel(logging.CRITICAL + 1)


def pytest_addoption(parser):
    parser.addoption("--rsd", default=None, type=str, nargs=2, action="store")
    parser.addoption("--tunnel", default=None, type=str, action="store")
    parser.addoption(
        "--xcuitest-config",
        default=None,
        metavar="PATH",
        help="Path to xcuitest JSON config file",
    )


NO_DEVICE_SKIP_REASON = "No test device is available through usbmuxd"


async def _create_usbmux_client() -> UsbmuxLockdownClient:
    try:
        return await create_using_usbmux()
    except (ConnectionFailedToUsbmuxdError, DeviceNotFoundError, NoDeviceConnectedError):
        pytest.skip(NO_DEVICE_SKIP_REASON)


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
) -> AsyncGenerator[Union[RemoteServiceDiscoveryService, UsbmuxLockdownClient, Any]]:
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
                try:
                    selected_rsd = rsds[0]
                except IndexError as e:
                    raise DeviceNotFoundError(tunnel_option) from e
            else:
                selected_rsd = next((rsd for rsd in rsds if rsd.udid == tunnel_option), None)
                if selected_rsd is None:
                    raise DeviceNotFoundError(tunnel_option)

            yield selected_rsd
        finally:
            for rsd in rsds:
                await rsd.close()
    else:
        async with await _create_usbmux_client() as client:
            yield client


@pytest_asyncio.fixture(scope="function")
async def dvt(service_provider) -> AsyncGenerator[DvtProvider, Any]:
    """
    Creates a new DVT provider for each test.
    """
    try:
        async with DvtProvider(service_provider) as dvt:
            yield dvt
    except InvalidServiceError:
        pytest.skip("Skipping DVT-based test since the DVT provider service isn't accessible")


@pytest_asyncio.fixture(scope="function")
async def lockdown() -> AsyncGenerator[UsbmuxLockdownClient, Any]:
    """
    Creates a new lockdown client for each test.
    """
    client = await _create_usbmux_client()
    async with client:
        yield client


@pytest_asyncio.fixture(scope="function")
async def xcuitest_service(service_provider) -> XCUITestService:
    """
    Creates a new XCUITestService client for each test.
    """
    try:
        # check manually, as the XCUITestService currently connect to the needed services
        # only when starting the test ( shall we change this? )
        async with DvtProvider(service_provider):
            pass
        return XCUITestService(service_provider)
    except InvalidServiceError:
        pytest.skip("Skipping XCUITest-based test since the service isn't accessible")
