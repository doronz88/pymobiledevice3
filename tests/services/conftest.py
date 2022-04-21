import pytest

from pymobiledevice3.lockdown import LockdownClient


@pytest.fixture(scope='function')
def lockdown():
    """
    Creates a new lockdown client for each test.
    """
    with LockdownClient() as client:
        yield client
