"""Bonjour answers are matched to their pair record offline, never by trying records against devices."""

import base64
import dataclasses
import logging
import plistlib
from typing import Any, Optional

import pytest
from opack2 import dumps

import pymobiledevice3.lockdown as lockdown_module
import pymobiledevice3.remote.tunnel_service as tunnel_service
from pymobiledevice3.bonjour import Address, ServiceInstance
from pymobiledevice3.exceptions import ConnectionTerminatedError
from pymobiledevice3.remote.siphash import compute_auth_tag
from pymobiledevice3.remote.tunnel_service import (
    PEER_ALT_IRK_KEY,
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


# --- mobdev2 ---------------------------------------------------------------------------------------

MAC = "aa:bb:cc:dd:ee:ff"
OTHER_MAC = "11:22:33:44:55:66"


def _mobdev2_answer(mac: str, ip: str) -> ServiceInstance:
    return ServiceInstance(
        instance=f"{mac}@fe80::1._apple-mobdev2._tcp.local.",
        host="device.local",
        port=62078,
        addresses=[Address(ip=ip, iface="en0")],
    )


@pytest.fixture
def mobdev2(monkeypatch):
    @dataclasses.dataclass
    class State:
        answers: list[ServiceInstance] = dataclasses.field(default_factory=list)
        usbmux_record: Optional[dict[str, Any]] = None
        attempts: list[tuple[str, Optional[dict[str, Any]]]] = dataclasses.field(default_factory=list)
        browses: int = 0

    state = State()

    async def browse(timeout):
        state.browses += 1
        return state.answers

    async def create_using_tcp(hostname, autopair, pair_record):
        state.attempts.append((hostname, pair_record))
        return hostname

    async def preferred_record(identifier, pairing_records_cache_folder):
        return state.usbmux_record

    monkeypatch.setattr(lockdown_module, "browse_mobdev2", browse)
    monkeypatch.setattr(lockdown_module, "create_using_tcp", create_using_tcp)
    monkeypatch.setattr(lockdown_module, "get_preferred_pair_record", preferred_record)
    return state


async def _mobdev2_lockdowns(**kwargs) -> list[Any]:
    return [lockdown async for _, lockdown in lockdown_module.get_mobdev2_lockdowns(**kwargs)]


async def test_mobdev2_udid_connects_only_to_the_device_of_its_record(mobdev2, tmp_path):
    record = {"WiFiMACAddress": MAC}
    (tmp_path / "UDID.plist").write_bytes(plistlib.dumps(record))
    mobdev2.answers = [_mobdev2_answer(OTHER_MAC, "10.0.0.9"), _mobdev2_answer(MAC, "10.0.0.1")]

    assert await _mobdev2_lockdowns(udid="UDID", pair_records=tmp_path) == ["10.0.0.1"]
    assert mobdev2.attempts == [("10.0.0.1", record)]


async def test_mobdev2_udid_record_may_come_from_usbmuxd(mobdev2, tmp_path):
    mobdev2.usbmux_record = {"WiFiMACAddress": MAC}
    mobdev2.answers = [_mobdev2_answer(OTHER_MAC, "10.0.0.9"), _mobdev2_answer(MAC, "10.0.0.1")]

    assert await _mobdev2_lockdowns(udid="UDID", pair_records=tmp_path) == ["10.0.0.1"]


async def test_mobdev2_udid_without_a_record_neither_browses_nor_connects(mobdev2, tmp_path):
    mobdev2.answers = [_mobdev2_answer(MAC, "10.0.0.1")]

    assert await _mobdev2_lockdowns(udid="UDID", pair_records=tmp_path) == []
    assert mobdev2.browses == 0
    assert mobdev2.attempts == []
