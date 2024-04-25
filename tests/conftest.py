import logging

import pytest
import pytest_asyncio

from pymobiledevice3.exceptions import DeviceNotFoundError, InvalidServiceError
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.tunneld import async_get_tunneld_devices

logging.getLogger('quic').disabled = True
logging.getLogger('asyncio').disabled = True
logging.getLogger('zeroconf').disabled = True
logging.getLogger('parso.cache').disabled = True
logging.getLogger('parso.cache.pickle').disabled = True
logging.getLogger('parso.python.diff').disabled = True
logging.getLogger('humanfriendly.prompts').disabled = True
logging.getLogger('blib2to3.pgen2.driver').disabled = True
logging.getLogger('urllib3.connectionpool').disabled = True


def pytest_addoption(parser):
    parser.addoption('--rsd', default=None, type=str, nargs=2, action='store')
    parser.addoption('--tunnel', default=None, type=str, action='store')


@pytest.fixture(scope='function')
def rsd_option(request):
    """
    Get --rsd option
    """
    return request.config.getoption('--rsd')


@pytest.fixture(scope='function')
def tunnel_option(request):
    """
    Get --tunnel option
    """
    return request.config.getoption('--tunnel')


@pytest_asyncio.fixture(scope='function')
async def service_provider(rsd_option, tunnel_option) -> LockdownServiceProvider:
    """
    Creates a new LockdownServiceProvider client for each test.
    """
    if rsd_option is not None:
        async with RemoteServiceDiscoveryService(rsd_option) as rsd:
            yield rsd
    elif tunnel_option is not None:
        rsds = await async_get_tunneld_devices()
        try:
            if tunnel_option == '':
                yield rsds[0]
            else:
                yield [rsd for rsd in rsds if rsd.udid == tunnel_option][0]
            for rsd in rsds:
                await rsd.close()
        except IndexError:
            raise DeviceNotFoundError(tunnel_option)
    else:
        with create_using_usbmux() as client:
            yield client


@pytest.fixture(scope='function')
def dvt(service_provider) -> DvtSecureSocketProxyService:
    """
    Creates a new DvtSecureSocketProxyService client for each test.
    """
    try:
        with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
            yield dvt
    except InvalidServiceError:
        pytest.skip('Skipping DVT-based test since the service isn\'t accessible')


@pytest.fixture(scope='function')
def lockdown(request) -> LockdownClient:
    """
    Creates a new lockdown client for each test.
    """
    with create_using_usbmux() as client:
        yield client
