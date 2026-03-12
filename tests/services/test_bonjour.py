import pytest
from packaging.version import Version

from pymobiledevice3.bonjour import browse_mobdev2, browse_remoted, browse_remotepairing
from pymobiledevice3.lockdown import LockdownClient


@pytest.mark.asyncio
async def test_mobdev2(lockdown: LockdownClient) -> None:
    await lockdown.set_enable_wifi_connections(True)
    results = await browse_mobdev2()
    if not results:
        pytest.skip("No mobdev2 Bonjour services discovered on this host/network")
    assert len(results) >= 1


@pytest.mark.asyncio
async def test_remoted(lockdown: LockdownClient) -> None:
    if Version(lockdown.product_version) < Version("16.0"):
        pytest.skip("iOS < 16.0")
    results = await browse_remoted()
    if not results:
        pytest.skip("No remoted Bonjour services discovered on this host/network")
    assert len(results) >= 1


@pytest.mark.asyncio
async def test_remotepairing(lockdown: LockdownClient) -> None:
    if Version(lockdown.product_version) < Version("17.0"):
        pytest.skip("iOS < 17.0")
    results = await browse_remotepairing()
    if not results:
        pytest.skip("No remotepairing Bonjour services discovered on this host/network")
    assert len(results) >= 1
