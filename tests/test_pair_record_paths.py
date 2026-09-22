from unittest.mock import Mock

import pytest

from pymobiledevice3 import pair_records
from pymobiledevice3.exceptions import DevicePathError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.remote import tunnel_service


@pytest.mark.parametrize("identifier", ["../victim", "/victim", r"C:\victim", r"..\victim", "nested/file", "x\0y"])
def test_pair_record_reads_reject_identifiers(tmp_path, identifier):
    with pytest.raises(DevicePathError):
        pair_records.get_local_pairing_record(identifier, tmp_path)
    with pytest.raises(DevicePathError):
        pair_records.get_itunes_pairing_record(identifier)
    with pytest.raises(DevicePathError):
        pair_records.get_remote_pairing_record_filename(identifier)


@pytest.mark.parametrize("identifier", ["00008110-001234567890001E", "fe80::1c2b:3aff:fe4d:5e6f%en0"])
def test_pair_record_reads_accept_udids_and_hostnames(tmp_path, identifier):
    # a TCP lockdown client is keyed by its hostname, an IPv6 address for a device found over Wi-Fi
    assert pair_records.get_local_pairing_record(identifier, tmp_path) is None
    assert pair_records.get_remote_pairing_record_filename(identifier) == f"remote_{identifier}"


@pytest.mark.asyncio
async def test_classic_save_rejects_identifier(tmp_path):
    client = Mock()
    client.identifier = "../victim"
    client.pair_record = {"test": "value"}
    client.pairing_records_cache_folder = tmp_path
    with pytest.raises(DevicePathError):
        await LockdownClient.save_pair_record(client)
    assert not (tmp_path.parent / "victim.plist").exists()


@pytest.mark.parametrize("host", [False, True])
def test_remote_pairing_rejects_identifier(tmp_path, monkeypatch, host):
    monkeypatch.setattr(tunnel_service, "create_pairing_records_cache_folder", lambda: tmp_path)
    if host:
        instance = Mock(peer_device=Mock(udid="../victim"))
        prop = tunnel_service.PairableHost.pair_record_path
    else:
        instance = Mock(remote_identifier="../victim")
        prop = tunnel_service.RemotePairingProtocol.pair_record_path
    assert prop.fget is not None
    with pytest.raises(DevicePathError):
        prop.fget(instance)
