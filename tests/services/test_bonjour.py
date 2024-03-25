import pytest
from packaging.version import Version

from pymobiledevice3.bonjour import browse_mobdev2, browse_remoted, browse_remotepairing


@pytest.mark.asyncio
async def test_mobdev2(lockdown):
    lockdown.enable_wifi_connections = True
    assert len(await browse_mobdev2()) >= 1


@pytest.mark.asyncio
async def test_remoted(lockdown):
    if Version(lockdown.product_version) < Version('16.0'):
        pytest.skip('iOS < 16.0')
    assert len(await browse_remoted()) >= 1


@pytest.mark.asyncio
async def test_remotepairing(lockdown):
    if Version(lockdown.product_version) < Version('17.0'):
        pytest.skip('iOS < 17.0')
    assert len(await browse_remotepairing()) >= 1
