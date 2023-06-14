import pytest

from pymobiledevice3.lockdown import create_using_usbmux


@pytest.fixture(scope='function')
def lockdown():
    """
    Creates a new lockdown client for each test.
    """
    with create_using_usbmux() as client:
        yield client
