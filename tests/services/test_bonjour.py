import base64

import pytest
from packaging.version import Version

from pymobiledevice3.bonjour import ServiceInstance, browse_mobdev2, browse_remoted, browse_remotepairing
from pymobiledevice3.lockdown import LockdownClient, compute_mobdev2_auth_tag, get_mobdev2_lockdowns
from pymobiledevice3.pair_records import iter_remote_pair_records_by_identifier
from pymobiledevice3.remote.tunnel_service import PEER_ALT_IRK_KEY, _match_remote_pair_record


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


def _mobdev2_auth_tags(answer: ServiceInstance) -> set[bytes]:
    return {
        base64.b64decode(value)
        for key, value in answer.properties.items()
        if key == "authTag" or key.startswith("authTag#")
    }


# The tests below hold the matching against what a real device advertises. Mocked adverts only repeat
# our own assumptions -- that is how matching on the advertised MAC (a private Wi-Fi address in
# practice) once shipped.


@pytest.mark.asyncio
async def test_mobdev2_advert_names_our_host(lockdown: LockdownClient) -> None:
    await lockdown.set_enable_wifi_connections(True)
    assert lockdown.pair_record is not None
    tagged = [answer for answer in await browse_mobdev2() if _mobdev2_auth_tags(answer)]
    if not tagged:
        pytest.skip("No mobdev2 advert carrying an authTag was discovered on this host/network")
    host_id = lockdown.pair_record["HostID"]
    assert any(
        compute_mobdev2_auth_tag(host_id, answer.properties["identifier"]) in _mobdev2_auth_tags(answer)
        for answer in tagged
    )


@pytest.mark.asyncio
async def test_mobdev2_lockdown_by_udid(lockdown: LockdownClient) -> None:
    await lockdown.set_enable_wifi_connections(True)
    if not await browse_mobdev2():
        pytest.skip("No mobdev2 Bonjour services discovered on this host/network")
    found = [client async for _, client in get_mobdev2_lockdowns(udid=lockdown.udid, only_paired=True)]
    try:
        assert found
        assert all(client.paired and client.udid == lockdown.udid for client in found)
    finally:
        for client in found:
            await client.close()


@pytest.mark.asyncio
async def test_remotepairing_advert_matches_pair_record(lockdown: LockdownClient) -> None:
    if Version(lockdown.product_version) < Version("17.0"):
        pytest.skip("iOS < 17.0")
    alt_irks = {
        identifier: pair_record[PEER_ALT_IRK_KEY]
        for identifier, _, pair_record in iter_remote_pair_records_by_identifier()
        if identifier == lockdown.udid and PEER_ALT_IRK_KEY in pair_record
    }
    if not alt_irks:
        pytest.skip("No RemotePairing record holding the device altIRK (`lockdown remotepairing --pair`)")
    answers = await browse_remotepairing()
    if not answers:
        pytest.skip("No remotepairing Bonjour services discovered on this host/network")
    assert any(_match_remote_pair_record(answer, alt_irks) == lockdown.udid for answer in answers)
