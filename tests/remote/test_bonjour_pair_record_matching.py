"""Bonjour answers are matched to their pair record offline, never by trying records against devices."""

import base64
import dataclasses
import logging
import plistlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from opack2 import dumps

import pymobiledevice3.lockdown as lockdown_module
import pymobiledevice3.remote.tunnel_service as tunnel_service
from pymobiledevice3.bonjour import Address, ServiceInstance
from pymobiledevice3.exceptions import ConnectionTerminatedError
from pymobiledevice3.lockdown import compute_mobdev2_auth_tag
from pymobiledevice3.remote.siphash import compute_auth_tag
from pymobiledevice3.remote.tunnel_service import (
    PEER_ALT_IRK_KEY,
    PairingDataComponentTLVBuf,
    PairingDataComponentType,
    RemotePairingTunnelService,
    get_remote_pairing_tunnel_services,
)

ALT_IRK = bytes(range(16))
OTHER_ALT_IRK = bytes(range(16, 32))
SERVICE_IDENTIFIER = "2BE6E510-0325-4365-923E-B14C6F57DB3A"


def _answer(alt_irk: Optional[bytes], addresses: tuple[str, ...] = ("10.0.0.1",), port: int = 49152) -> ServiceInstance:
    properties = {"identifier": SERVICE_IDENTIFIER}
    if alt_irk is not None:
        properties["authTag"] = base64.b64encode(compute_auth_tag(alt_irk, SERVICE_IDENTIFIER)).decode()
    return ServiceInstance(
        instance="x._remotepairing._tcp.local.",
        host="device.local",
        port=port,
        addresses=[Address(ip=ip, iface="en0") for ip in addresses],
        properties=properties,
    )


@pytest.fixture
def remotepairing(monkeypatch, tmp_path):
    """Fake the pair records on disk, the bonjour browse and the connection; expose what was attempted."""

    @dataclasses.dataclass
    class State:
        records: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
        answers: list[ServiceInstance] = dataclasses.field(default_factory=list)
        unreachable: set[str] = dataclasses.field(default_factory=set)
        attempts: list[tuple[str, str, int]] = dataclasses.field(default_factory=list)
        browses: int = 0

    state = State()

    def iter_records():
        for identifier, record in state.records.items():
            yield identifier, tmp_path / f"remote_{identifier}.plist", record

    async def browse(timeout):
        state.browses += 1
        return state.answers

    async def connect(identifier, hostname, port, autopair=True):
        state.attempts.append((identifier, hostname, port))
        if hostname in state.unreachable:
            raise ConnectionTerminatedError()
        return (identifier, hostname)

    monkeypatch.setattr(tunnel_service, "iter_remote_pair_records_by_identifier", iter_records)
    monkeypatch.setattr(tunnel_service, "browse_remotepairing", browse)
    monkeypatch.setattr(tunnel_service, "create_core_device_tunnel_service_using_remotepairing", connect)
    monkeypatch.setattr(tunnel_service, "_warned_stale_pair_records", set())
    return state


async def test_only_the_matching_record_is_used(remotepairing):
    remotepairing.records = {"OTHER": {PEER_ALT_IRK_KEY: OTHER_ALT_IRK}, "MINE": {PEER_ALT_IRK_KEY: ALT_IRK}}
    remotepairing.answers = [_answer(ALT_IRK)]

    assert await get_remote_pairing_tunnel_services() == [("MINE", "10.0.0.1")]
    assert remotepairing.attempts == [("MINE", "10.0.0.1", 49152)]


@pytest.mark.parametrize("stranger", [_answer(OTHER_ALT_IRK), _answer(None)])
async def test_unmatched_answers_are_never_contacted(remotepairing, stranger):
    remotepairing.records = {"MINE": {PEER_ALT_IRK_KEY: ALT_IRK}}
    remotepairing.answers = [stranger]

    assert await get_remote_pairing_tunnel_services() == []
    assert remotepairing.attempts == []


async def test_udid_and_excluded_identifiers_filter_before_connecting(remotepairing):
    remotepairing.records = {"MINE": {PEER_ALT_IRK_KEY: ALT_IRK}}
    remotepairing.answers = [_answer(ALT_IRK)]

    assert await get_remote_pairing_tunnel_services(udid="SOMEONE-ELSE") == []
    assert await get_remote_pairing_tunnel_services(excluded_identifiers={"MINE"}) == []
    assert remotepairing.attempts == []
    # With no candidate record left there is nothing to wait for.
    assert remotepairing.browses == 0


async def test_every_reachable_address_of_a_matched_device_is_returned(remotepairing):
    remotepairing.records = {"MINE": {PEER_ALT_IRK_KEY: ALT_IRK}}
    remotepairing.answers = [_answer(ALT_IRK, addresses=("10.0.0.1", "10.0.0.2"))]
    remotepairing.unreachable = {"10.0.0.1"}

    assert await get_remote_pairing_tunnel_services() == [("MINE", "10.0.0.2")]


async def test_record_without_alt_irk_is_skipped_with_a_single_warning(remotepairing, caplog):
    remotepairing.records = {"STALE": {"private_key": b"\x00" * 32}}
    remotepairing.answers = [_answer(ALT_IRK)]

    with caplog.at_level(logging.WARNING, logger=tunnel_service.__name__):
        assert await get_remote_pairing_tunnel_services() == []
        assert await get_remote_pairing_tunnel_services() == []

    assert remotepairing.attempts == []
    warnings = [r for r in caplog.records if "remote_STALE.plist" in r.getMessage()]
    assert len(warnings) == 1


def test_pair_setup_records_the_device_alt_irk(monkeypatch, tmp_path):
    monkeypatch.setattr(tunnel_service, "create_pairing_records_cache_folder", lambda: tmp_path)
    service = RemotePairingTunnelService("MINE", "10.0.0.1", 49152)
    service.remote_unlock_host_key = ""

    service.peer_alt_irk = service._parse_peer_alt_irk({
        PairingDataComponentType.INFO: dumps({"altIRK": ALT_IRK, "model": "iPhone12,1"})
    })
    service.save_pair_record()

    assert plistlib.loads(service.pair_record_path.read_bytes())[PEER_ALT_IRK_KEY] == ALT_IRK


@pytest.mark.parametrize(
    "device_tlv",
    [{}, {PairingDataComponentType.INFO: b"\xff"}, {PairingDataComponentType.INFO: dumps({"altIRK": b"short"})}],
)
def test_pair_setup_tolerates_a_missing_alt_irk(monkeypatch, tmp_path, device_tlv):
    monkeypatch.setattr(tunnel_service, "create_pairing_records_cache_folder", lambda: tmp_path)
    service = RemotePairingTunnelService("MINE", "10.0.0.1", 49152)
    service.remote_unlock_host_key = ""

    service.peer_alt_irk = service._parse_peer_alt_irk(device_tlv)
    service.save_pair_record()

    assert PEER_ALT_IRK_KEY not in plistlib.loads(service.pair_record_path.read_bytes())


async def test_record_without_alt_irk_still_pair_verifies(monkeypatch, tmp_path):
    # The altIRK only serves recognizing a Wi-Fi advert. Pair-verify -- all USB/RSD needs -- must keep
    # working with a record written before it was stored.
    monkeypatch.setattr(tunnel_service, "create_pairing_records_cache_folder", lambda: tmp_path)
    (tmp_path / "remote_MINE.plist").write_bytes(
        plistlib.dumps({"private_key": b"\x01" * 32, "public_key": b"\x02" * 32, "remote_unlock_host_key": ""})
    )
    service = RemotePairingTunnelService("MINE", "10.0.0.1", 49152)
    device_key = X25519PrivateKey.generate().public_key().public_bytes_raw()
    replies = [
        PairingDataComponentTLVBuf.build([
            {"type": PairingDataComponentType.STATE, "data": b"\x02"},
            {"type": PairingDataComponentType.PUBLIC_KEY, "data": device_key},
        ]),
        PairingDataComponentTLVBuf.build([{"type": PairingDataComponentType.STATE, "data": b"\x04"}]),
    ]

    async def send_receive_pairing_data(pairing_data):
        return replies.pop(0)

    monkeypatch.setattr(service, "_send_receive_pairing_data", send_receive_pairing_data)

    assert await service._validate_pairing() is True
    assert replies == []


# --- mobdev2 ---------------------------------------------------------------------------------------

MAC = "aa:bb:cc:dd:ee:ff"
OTHER_MAC = "11:22:33:44:55:66"


HOST_ID = "11111111-2222-3333-4444-555555555555"
OTHER_HOST_ID = "99999999-8888-7777-6666-555555555555"


def _mobdev2_answer(mac: str, ip: str, paired_host_ids: Optional[tuple[str, ...]] = None) -> ServiceInstance:
    """A mobdev2 advert; ``paired_host_ids`` adds the tags of the hosts the device is paired with (iOS 17+)."""
    properties = {}
    if paired_host_ids is not None:
        properties["identifier"] = SERVICE_IDENTIFIER
        for index, host_id in enumerate(paired_host_ids):
            tag = base64.b64encode(compute_mobdev2_auth_tag(host_id, SERVICE_IDENTIFIER)).decode()
            properties["authTag" if index == 0 else f"authTag#{index}"] = tag
    return ServiceInstance(
        instance=f"{mac}@fe80::1._apple-mobdev2._tcp.local.",
        host="device.local",
        port=62078,
        addresses=[Address(ip=ip, iface="en0")],
        properties=properties,
    )


@dataclasses.dataclass
class _FakeLockdown:
    hostname: str
    udid: Optional[str]
    paired: bool
    closed: bool = False

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def mobdev2(monkeypatch):
    @dataclasses.dataclass
    class State:
        answers: list[ServiceInstance] = dataclasses.field(default_factory=list)
        usbmux_record: Optional[dict[str, Any]] = None
        # hostname -> udid of the device living there; it only accepts its own record
        devices: dict[str, str] = dataclasses.field(default_factory=dict)
        lockdowns: list[_FakeLockdown] = dataclasses.field(default_factory=list)
        browses: int = 0

    state = State()

    async def browse(timeout):
        state.browses += 1
        return state.answers

    async def create_using_tcp(hostname, autopair, pair_record):
        device_udid = state.devices[hostname]
        accepted = pair_record is not None and pair_record["UDID"] == device_udid
        lockdown = _FakeLockdown(hostname, device_udid if accepted else None, accepted)
        state.lockdowns.append(lockdown)
        return lockdown

    async def preferred_record(identifier, pairing_records_cache_folder):
        return state.usbmux_record

    monkeypatch.setattr(lockdown_module, "browse_mobdev2", browse)
    monkeypatch.setattr(lockdown_module, "create_using_tcp", create_using_tcp)
    monkeypatch.setattr(lockdown_module, "get_preferred_pair_record", preferred_record)
    return state


async def _mobdev2_hostnames(**kwargs) -> list[str]:
    return [lockdown.hostname async for _, lockdown in lockdown_module.get_mobdev2_lockdowns(**kwargs)]


# "UDID" is not a real pair record key; the fake device uses it to decide whether the record is its own.
RECORD = {"WiFiMACAddress": MAC, "UDID": "UDID", "HostID": HOST_ID}


async def test_mobdev2_udid_yields_only_the_requested_device(mobdev2, tmp_path):
    (tmp_path / "UDID.plist").write_bytes(plistlib.dumps(RECORD))
    mobdev2.answers = [_mobdev2_answer(OTHER_MAC, "10.0.0.9"), _mobdev2_answer(MAC, "10.0.0.1")]
    mobdev2.devices = {"10.0.0.9": "STRANGER", "10.0.0.1": "UDID"}

    assert await _mobdev2_hostnames(udid="UDID", pair_records=tmp_path) == ["10.0.0.1"]
    assert [lockdown.closed for lockdown in mobdev2.lockdowns] == [True, False]


async def test_mobdev2_udid_is_found_behind_a_private_wifi_address(mobdev2, tmp_path):
    # The advertised MAC is the randomized one, not the record's WiFiMACAddress.
    mobdev2.usbmux_record = RECORD
    mobdev2.answers = [_mobdev2_answer(OTHER_MAC, "10.0.0.9"), _mobdev2_answer("ca:11:22:33:44:55", "10.0.0.1")]
    mobdev2.devices = {"10.0.0.9": "STRANGER", "10.0.0.1": "UDID"}

    assert await _mobdev2_hostnames(udid="UDID", pair_records=tmp_path) == ["10.0.0.1"]


async def test_mobdev2_paired_devices_are_found_behind_private_wifi_addresses(mobdev2, tmp_path):
    # tunneld's monitor: no udid, several records, and no advert names its device -- each device is
    # offered the records until it accepts one; a stranger accepts none and is dropped.
    (tmp_path / "FIRST.plist").write_bytes(plistlib.dumps({"WiFiMACAddress": MAC, "UDID": "FIRST", "HostID": HOST_ID}))
    (tmp_path / "SECOND.plist").write_bytes(
        plistlib.dumps({"WiFiMACAddress": OTHER_MAC, "UDID": "SECOND", "HostID": HOST_ID})
    )
    mobdev2.answers = [
        _mobdev2_answer("ca:00:00:00:00:01", "10.0.0.1"),
        _mobdev2_answer("ca:00:00:00:00:02", "10.0.0.2"),
        _mobdev2_answer("ca:00:00:00:00:03", "10.0.0.3"),
    ]
    mobdev2.devices = {"10.0.0.1": "SECOND", "10.0.0.2": "STRANGER", "10.0.0.3": "FIRST"}

    assert await _mobdev2_hostnames(pair_records=tmp_path, only_paired=True) == ["10.0.0.1", "10.0.0.3"]
    assert all(lockdown.closed for lockdown in mobdev2.lockdowns if not lockdown.paired)


async def test_mobdev2_advert_naming_its_record_is_offered_only_that_record(mobdev2, tmp_path):
    (tmp_path / "FIRST.plist").write_bytes(plistlib.dumps({"WiFiMACAddress": MAC, "UDID": "FIRST", "HostID": HOST_ID}))
    (tmp_path / "SECOND.plist").write_bytes(
        plistlib.dumps({"WiFiMACAddress": OTHER_MAC, "UDID": "SECOND", "HostID": HOST_ID})
    )
    mobdev2.answers = [_mobdev2_answer(MAC, "10.0.0.1")]
    mobdev2.devices = {"10.0.0.1": "FIRST"}

    assert await _mobdev2_hostnames(pair_records=tmp_path, only_paired=True) == ["10.0.0.1"]
    assert len(mobdev2.lockdowns) == 1


def test_mobdev2_auth_tag_known_answer():
    # HMAC-SHA256(HKDF-SHA512(HostID), identifier)[:8], as MobileDevice's AMDIsTXTRecordForUDID computes it.
    assert base64.b64encode(compute_mobdev2_auth_tag(HOST_ID, SERVICE_IDENTIFIER)) == b"DNKInlok1wk="


async def test_mobdev2_device_not_paired_with_our_host_is_never_contacted(mobdev2, tmp_path):
    (tmp_path / "UDID.plist").write_bytes(plistlib.dumps({**RECORD, "HostID": HOST_ID}))
    mobdev2.answers = [
        _mobdev2_answer("ca:00:00:00:00:01", "10.0.0.9", paired_host_ids=(OTHER_HOST_ID,)),
        _mobdev2_answer("ca:00:00:00:00:02", "10.0.0.1", paired_host_ids=(OTHER_HOST_ID, HOST_ID)),
    ]
    mobdev2.devices = {"10.0.0.9": "STRANGER", "10.0.0.1": "UDID"}

    assert await _mobdev2_hostnames(pair_records=tmp_path, only_paired=True) == ["10.0.0.1"]
    assert [lockdown.hostname for lockdown in mobdev2.lockdowns] == ["10.0.0.1"]


async def test_mobdev2_device_is_offered_only_the_records_of_hosts_it_names(mobdev2, tmp_path):
    (tmp_path / "FIRST.plist").write_bytes(
        plistlib.dumps({"WiFiMACAddress": MAC, "UDID": "FIRST", "HostID": OTHER_HOST_ID})
    )
    (tmp_path / "SECOND.plist").write_bytes(
        plistlib.dumps({"WiFiMACAddress": OTHER_MAC, "UDID": "SECOND", "HostID": HOST_ID})
    )
    mobdev2.answers = [_mobdev2_answer("ca:00:00:00:00:01", "10.0.0.1", paired_host_ids=(HOST_ID,))]
    mobdev2.devices = {"10.0.0.1": "SECOND"}

    assert await _mobdev2_hostnames(pair_records=tmp_path, only_paired=True) == ["10.0.0.1"]
    assert len(mobdev2.lockdowns) == 1


async def test_mobdev2_yields_one_client_per_device(mobdev2, tmp_path):
    # A device advertises every address it has; they all lead to the same place, and a chooser listing
    # the same device several times is no use to anyone.
    (tmp_path / "UDID.plist").write_bytes(plistlib.dumps(RECORD))
    answer = _mobdev2_answer("ca:00:00:00:00:01", "10.0.0.1")
    answer.addresses.append(Address(ip="10.0.0.2", iface="en0"))
    mobdev2.answers = [answer]
    mobdev2.devices = {"10.0.0.1": "UDID", "10.0.0.2": "UDID"}

    assert await _mobdev2_hostnames(pair_records=tmp_path) == ["10.0.0.1"]


async def test_mobdev2_without_udid_uses_the_records_usbmuxd_holds(mobdev2, monkeypatch):
    # macOS/Windows keep lockdown records with usbmuxd, out of our folder and impossible to enumerate:
    # without a udid the records of the devices usbmuxd lists are what lets the device come up paired.
    async def list_devices():
        return [SimpleNamespace(serial="UDID")]

    async def usbmux_record(serial):
        return RECORD if serial == "UDID" else None

    monkeypatch.setattr(lockdown_module, "get_home_folder", lambda: Path("/nonexistent"))
    monkeypatch.setattr(lockdown_module, "OSUTIL", SimpleNamespace(pair_record_path=Path("/nonexistent")))
    monkeypatch.setattr(lockdown_module.usbmux, "list_devices", list_devices)
    monkeypatch.setattr(lockdown_module, "get_usbmux_pairing_record", usbmux_record)
    mobdev2.answers = [_mobdev2_answer("ca:00:00:00:00:01", "10.0.0.1", paired_host_ids=(HOST_ID,))]
    mobdev2.devices = {"10.0.0.1": "UDID"}

    assert await _mobdev2_hostnames(only_paired=True) == ["10.0.0.1"]


async def test_mobdev2_udid_without_a_record_neither_browses_nor_connects(mobdev2, tmp_path):
    mobdev2.answers = [_mobdev2_answer(MAC, "10.0.0.1")]

    assert await _mobdev2_hostnames(udid="UDID", pair_records=tmp_path) == []
    assert mobdev2.browses == 0
    assert mobdev2.lockdowns == []
