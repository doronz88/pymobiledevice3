import pytest

from pymobiledevice3.exceptions import InvalidServiceError
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService


def pytest_addoption(parser):
    parser.addoption('--rsd', default=None, type=str, nargs=2, action='store')


@pytest.fixture(scope='function')
def service_provider(request) -> LockdownServiceProvider:
    """
    Creates a new LockdownServiceProvider client for each test.
    """
    rsd = request.config.getoption('--rsd')

    if rsd is not None:
        with RemoteServiceDiscoveryService(rsd) as rsd:
            yield rsd
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
