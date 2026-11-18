import asyncio
import os
import plistlib
from pathlib import Path
from typing import Any, Optional, cast

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pymobiledevice3 import lockdown as lockdown_module
from pymobiledevice3.cli import cli_common
from pymobiledevice3.exceptions import (
    DeviceNotFoundError,
    GetProhibitedError,
    LockdownError,
    MCProtectedError,
    NoDeviceConnectedError,
    NotPairedError,
    PairingDialogResponsePendingError,
    PairingError,
    PasscodeRequiredError,
    PasswordRequiredError,
    SessionActiveError,
    UserDeniedPairingError,
)
from pymobiledevice3.lockdown import LockdownClient, TcpLockdownClient, UsbmuxLockdownClient
from pymobiledevice3.remote.pair_setup import PairingDataComponentTLVBuf, build_pairing_tlv, opack_loads
from pymobiledevice3.remote.pair_setup import PairingDataComponentType as Component
from pymobiledevice3.remote.srp import SrpServer
from pymobiledevice3.service_connection import ServiceConnection

LOCKDOWND_SOCKET_SELECT_TIMEOUT = 60


@pytest.mark.parametrize(
    ("error", "exception_type"),
    [
        ("MCProtected", MCProtectedError),
        ("PasscodeRequired", PasscodeRequiredError),
        ("SessionActive", SessionActiveError),
    ],
)
def test_lockdown_error_mapping(error: str, exception_type: type[LockdownError]) -> None:
    lockdown = object.__new__(UsbmuxLockdownClient)
    lockdown.identifier = "test-device"
    lockdown.all_values = {"ProductVersion": "18.0"}

    with pytest.raises(exception_type) as exc_info:
        lockdown._verify_request_response("Test", {"Request": "Test", "Error": error})

    # lockdownd's code is kept apart from the message, which explains it
    assert exc_info.value.error == error
    assert str(exc_info.value) == exception_type.describe()
    assert exc_info.value.identifier == "test-device"
    assert exc_info.value.product_version == "18.0"


@pytest.mark.parametrize(
    ("error", "exception_type"),
    [
        ("PasswordProtected", PasswordRequiredError),
        ("UserDeniedPairing", UserDeniedPairingError),
        ("PairingDialogResponsePending", PairingDialogResponsePendingError),
    ],
)
def test_lockdown_pairing_errors_read_as_a_message(error: str, exception_type: type[PairingError]) -> None:
    # these were built with (code, identifier, version), so their message read as a tuple
    lockdown = object.__new__(UsbmuxLockdownClient)
    lockdown.identifier = "test-device"
    lockdown.all_values = {"ProductVersion": "18.0"}

    with pytest.raises(exception_type) as exc_info:
        lockdown._verify_request_response("Pair", {"Request": "Pair", "Error": error})

    assert str(exc_info.value) == exception_type.describe()


def test_lockdown_unmapped_error_names_the_request_and_code() -> None:
    lockdown = object.__new__(UsbmuxLockdownClient)
    lockdown.identifier = "test-device"
    lockdown.all_values = {"ProductVersion": "18.0"}

    with pytest.raises(LockdownError) as exc_info:
        lockdown._verify_request_response("StartSession", {"Request": "StartSession", "Error": "SessionInactive"})

    assert exc_info.value.error == "SessionInactive"
    assert str(exc_info.value) == "lockdownd failed StartSession: SessionInactive"


@pytest.mark.asyncio
async def test_lockdown_reconnect(lockdown: LockdownClient) -> None:
    d1 = await lockdown.get_date()

    # add some threshold to make sure lockdownd closed the connection on its end
    await asyncio.sleep(LOCKDOWND_SOCKET_SELECT_TIMEOUT + 5)

    d2 = await lockdown.get_date()

    assert d1 < d2


def _hkdf(key: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=32, salt=salt, info=info).derive(key)


class _CUPairingDevice:
    """The lockdownd side of a CU pairing, standing in for the lockdown connection."""

    PIN = "123456"
    UDID = "00008000-0000000000000000"

    def __init__(self) -> None:
        self.srp = SrpServer(self.PIN, os.urandom(16))
        self.pair_request: dict[str, Any] = {}
        self.public_key = rsa.generate_private_key(65537, 2048).public_key()

    def _cipher(self, direction: bytes) -> ChaCha20Poly1305:
        return ChaCha20Poly1305(_hkdf(self.srp.key, direction + b"KeySaltMDLD", direction + b"KeyInfoMDLD"))

    def _pair_setup(self, message: dict[str, Any]) -> dict[int, bytes]:
        tlv: dict[int, bytes] = {}
        for item in PairingDataComponentTLVBuf.parse(message["Payload"]):
            tlv[item.type] = tlv.get(item.type, b"") + item.data
        state = tlv[Component.STATE][0]
        assert message["Flags"] == (1 if state == 1 else 0)
        if state == 1:
            return {Component.SALT: self.srp._salt, Component.PUBLIC_KEY: self.srp.public}
        if state == 3:
            self.srp.process(tlv[Component.PUBLIC_KEY])
            if not self.srp.verify_client_proof(tlv[Component.PROOF]):
                return {Component.ERROR: b"\x02"}
            return {Component.PROOF: self.srp.proof}
        assert state == 5
        cipher = ChaCha20Poly1305(_hkdf(self.srp.key, b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info"))
        identity: dict[int, bytes] = {}
        for item in PairingDataComponentTLVBuf.parse(
            cipher.decrypt(b"\x00\x00\x00\x00PS-Msg05", tlv[Component.ENCRYPTED_DATA], b"")
        ):
            identity[item.type] = identity.get(item.type, b"") + item.data
        Ed25519PublicKey.from_public_bytes(identity[Component.PUBLIC_KEY]).verify(
            identity[Component.SIGNATURE],
            _hkdf(self.srp.key, b"Pair-Setup-Controller-Sign-Salt", b"Pair-Setup-Controller-Sign-Info")
            + identity[Component.IDENTIFIER]
            + identity[Component.PUBLIC_KEY],
        )
        assert opack_loads(identity[Component.INFO])["accountID"] == identity[Component.IDENTIFIER].decode()
        return {Component.ENCRYPTED_DATA: cipher.encrypt(b"\x00\x00\x00\x00PS-Msg06", b"", b"")}

    async def send_recv_plist(self, message: dict[str, Any]) -> dict[str, Any]:
        request = message["Request"]
        if request == "CUPairingCreate":
            answer = self._pair_setup(message)
            if Component.ERROR not in answer:
                state = PairingDataComponentTLVBuf.parse(message["Payload"])[-1].data[0]
                answer[Component.STATE] = bytes([state + 1])
            return {"Request": request, "ExtendedResponse": {"Payload": build_pairing_tlv(answer)}}

        payload = plistlib.loads(self._cipher(b"Write").decrypt(message["Nonce"], message["Payload"], b""))
        if request == "GetValueCU":
            pem = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
            reply: dict[str, Any] = {"Value": pem} if payload["Key"] == "DevicePublicKey" else {}
        else:
            assert request == "PairCU"
            self.pair_request = payload
            reply = {"UDID": self.UDID, "EscrowBag": b"escrow"}
        nonce = os.urandom(12)
        return {
            "Request": request,
            "Nonce": nonce,
            "Payload": self._cipher(b"Read").encrypt(nonce, plistlib.dumps(reply, fmt=plistlib.FMT_BINARY), b""),
        }


def _cu_lockdown(device: _CUPairingDevice, folder: Path) -> LockdownClient:
    lockdown = object.__new__(UsbmuxLockdownClient)
    lockdown.service = device  # pyright: ignore[reportAttributeAccessIssue]
    lockdown.label = "test"
    lockdown.identifier = "192.168.0.2"
    lockdown.host_id = "HOST-ID"
    lockdown.system_buid = "SYSTEM-BUID"
    lockdown.pairing_records_cache_folder = folder
    lockdown.all_values = {"ProductVersion": "18.0"}
    lockdown._reestablishing_connection = False
    lockdown._cu_key = None
    lockdown.paired = False
    return lockdown


@pytest.mark.asyncio
async def test_pair_cu_saves_the_pair_record_under_the_udid(tmp_path: Path) -> None:
    device = _CUPairingDevice()
    lockdown = _cu_lockdown(device, tmp_path)

    await lockdown.pair_cu(lambda: device.PIN)

    assert lockdown.paired
    # the private keys stay on the host, and a device without Wi-Fi reports no address to send back
    assert sorted(device.pair_request["PairRecord"]) == [
        "DeviceCertificate",
        "HostCertificate",
        "HostID",
        "RootCertificate",
        "SystemBUID",
    ]
    record = plistlib.loads((tmp_path / f"{device.UDID}.plist").read_bytes())
    assert record["EscrowBag"] == b"escrow"
    assert {"HostPrivateKey", "RootPrivateKey"} <= set(record)
    assert "WiFiMACAddress" not in record


@pytest.mark.asyncio
async def test_pair_cu_wrong_pin(tmp_path: Path) -> None:
    lockdown = _cu_lockdown(_CUPairingDevice(), tmp_path)

    with pytest.raises(PairingError, match="AUTHENTICATION"):
        await lockdown.pair_cu(lambda: "000000")

    assert not lockdown.paired
    assert list(tmp_path.iterdir()) == []


def testbuild_pairing_tlv_fragments_long_values() -> None:
    assert (
        build_pairing_tlv({3: b"a" * 300, 6: b"\x01"})
        == b"\x03\xff" + b"a" * 255 + b"\x03\x2d" + b"a" * 45 + b"\x06\x01\x01"
    )


class _Connection:
    """The device side of one connection; a heartbeat one when ``marcos`` is fed."""

    def __init__(self) -> None:
        #: What the device sends next; ``None`` stands for the connection breaking.
        self.marcos: asyncio.Queue[Optional[dict[str, Any]]] = asyncio.Queue()
        self.polos = 0
        self.closed = False

    async def recv_plist(self) -> dict[str, Any]:
        message = await self.marcos.get()
        if message is None:
            raise ConnectionAbortedError()
        return message

    async def send_plist(self, message: dict[str, Any]) -> None:
        assert message == {"Command": "Polo"}
        self.polos += 1

    async def close(self, timeout: float = 1) -> None:
        self.closed = True


class _NetworkLockdown(TcpLockdownClient):
    """A network lockdown client talking to a fake device."""

    HEARTBEAT_PORT = 1
    SERVICE_PORT = 2

    def __init__(
        self,
        service: Optional[ServiceConnection] = None,
        host_id: str = "HOST",
        hostname: str = "192.168.0.2",
        paired: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(service or cast(ServiceConnection, _Connection()), host_id, hostname, **kwargs)
        self._device_is_paired = paired
        self.paired = paired
        self.started: list[str] = []
        self.heartbeats: list[_Connection] = []

    async def _initialize(self) -> None:
        pass

    async def _handle_autopair(self, *args: Any, **kwargs: Any) -> None:
        self.paired = self._device_is_paired

    async def _request(
        self, request: str, options: Optional[dict[str, Any]] = None, verify_request: bool = True
    ) -> dict[str, Any]:
        assert request == "StartService" and options is not None
        self.started.append(options["Service"])
        is_heartbeat = options["Service"] == self.HEARTBEAT_SERVICE_NAME
        return {"Port": self.HEARTBEAT_PORT if is_heartbeat else self.SERVICE_PORT}

    async def create_service_connection(self, port: int, ssl_context: Any = None, strip_ssl: bool = False) -> Any:
        connection = _Connection()
        if port == self.HEARTBEAT_PORT:
            self.heartbeats.append(connection)
        return connection


async def _settle() -> None:
    for _ in range(3):
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_network_client_answers_the_heartbeat_from_its_first_service_until_closed() -> None:
    lockdown = await _NetworkLockdown.create(cast(ServiceConnection, _Connection()), hostname="192.168.0.2")
    # closing a heartbeat ends the services of every client of this host, so a client that starts none has none
    assert lockdown.started == []

    await lockdown.start_lockdown_service("com.apple.afc")
    assert lockdown.started == ["com.apple.mobile.heartbeat", "com.apple.afc"]
    [heartbeat] = lockdown.heartbeats

    for answered in (1, 2):
        heartbeat.marcos.put_nowait({"Command": "Marco"})
        await _settle()
        assert heartbeat.polos == answered

    # services ride on the one heartbeat, however they are started
    await lockdown.start_lockdown_service("com.apple.syslog_relay")
    await lockdown.get_service_connection_attributes("com.apple.instruments.remoteserver")
    assert len(lockdown.heartbeats) == 1
    assert not heartbeat.closed

    await lockdown.close()
    assert heartbeat.closed
    assert cast(_Connection, lockdown.service).closed


@pytest.mark.asyncio
async def test_network_client_that_started_no_service_has_no_heartbeat_to_close() -> None:
    async with await _NetworkLockdown.create(cast(ServiceConnection, _Connection())) as lockdown:
        pass
    assert lockdown.started == []
    assert cast(_Connection, lockdown.service).closed


@pytest.mark.asyncio
async def test_network_client_started_through_the_attributes_alone_has_a_heartbeat() -> None:
    # DTX opens its connection itself, from the attributes
    async with _NetworkLockdown() as lockdown:
        await lockdown.get_service_connection_attributes("com.apple.instruments.remoteserver")
        assert lockdown.started == ["com.apple.mobile.heartbeat", "com.apple.instruments.remoteserver"]
    assert [heartbeat.closed for heartbeat in lockdown.heartbeats] == [True]


@pytest.mark.asyncio
async def test_network_client_without_a_pairing_reports_the_service_error() -> None:
    async with _NetworkLockdown(paired=False) as lockdown:
        with pytest.raises(NotPairedError):
            await lockdown.start_lockdown_service("com.apple.afc")
        assert lockdown.started == []

        lockdown.paired = True
        await lockdown.start_lockdown_service("com.apple.afc")
        assert lockdown.started == ["com.apple.mobile.heartbeat", "com.apple.afc"]


@pytest.mark.asyncio
async def test_network_client_reopens_a_lost_heartbeat_with_the_next_service(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with _NetworkLockdown() as lockdown:
        await lockdown.start_lockdown_service("com.apple.afc")
        lockdown.heartbeats[0].marcos.put_nowait(None)
        await _settle()
        # the services are about to be dropped by the device, which is worth a word
        assert ["lost the heartbeat" in record.message for record in caplog.records] == [True]

        await lockdown.start_lockdown_service("com.apple.afc")
        assert len(lockdown.heartbeats) == 2
        assert lockdown.heartbeats[0].closed
        assert not lockdown.heartbeats[1].closed


@pytest.mark.asyncio
async def test_network_client_starts_one_heartbeat_for_concurrent_services() -> None:
    async with _NetworkLockdown() as lockdown:
        await asyncio.gather(*(lockdown.start_lockdown_service("com.apple.afc") for _ in range(3)))
        assert len(lockdown.heartbeats) == 1


@pytest.mark.asyncio
async def test_network_client_says_why_it_cannot_pair() -> None:
    lockdown = _NetworkLockdown(paired=False)

    async def get_value(domain: Optional[str] = None, key: Optional[str] = None) -> Any:
        assert key == "DevicePublicKey"
        raise GetProhibitedError("lockdownd does not allow reading this value.", None, "27.2")

    lockdown.get_value = get_value  # type: ignore[method-assign]
    with pytest.raises(PairingError, match="does not allow pairing over the network") as exc_info:
        await lockdown.pair()
    assert isinstance(exc_info.value.__cause__, GetProhibitedError)


def test_cli_closes_a_network_client_at_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(cli_common, "cli_loop", loop)
    try:
        lockdown = _NetworkLockdown()
        loop.run_until_complete(lockdown.start_lockdown_service("com.apple.afc"))

        cli_common._close_lockdown_at_exit(lockdown)
        assert lockdown.heartbeats[0].closed
        assert cast(_Connection, lockdown.service).closed
    finally:
        loop.close()


class _Mobdev2Device:
    def __init__(self, udid: str, closed: list[str], paired: bool = True) -> None:
        self.udid = udid
        self.paired = paired
        self._closed = closed

    async def close(self) -> None:
        self._closed.append(self.udid)


@pytest.mark.asyncio
async def test_create_using_mobdev2_connects_to_a_hostname(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "UDID-A.plist").write_bytes(plistlib.dumps({"HostID": "HOST"}))
    closed: list[str] = []
    offered: list[Any] = []

    async def create_using_tcp(hostname: str, autopair: bool, pair_record: Any) -> _Mobdev2Device:
        if hostname == "unreachable":
            raise ConnectionRefusedError()
        offered.append(pair_record)
        return _Mobdev2Device("UDID-A", closed, paired=hostname != "stranger")

    monkeypatch.setattr(lockdown_module, "create_using_tcp", create_using_tcp)

    assert (await lockdown_module.create_using_mobdev2("host", pair_records=tmp_path)).udid == "UDID-A"
    assert offered == [{"HostID": "HOST"}]

    # each way of not getting a paired client says which it was
    with pytest.raises(NoDeviceConnectedError, match="No device is answering at unreachable") as unreachable:
        await lockdown_module.create_using_mobdev2("unreachable", pair_records=tmp_path)
    assert isinstance(unreachable.value.__cause__, ConnectionRefusedError)

    with pytest.raises(NotPairedError):
        await lockdown_module.create_using_mobdev2("stranger", pair_records=tmp_path)
    # a device turning down the record of the one that was asked for may well be another device
    with pytest.raises(DeviceNotFoundError, match="does not accept the pair record of UDID-A"):
        await lockdown_module.create_using_mobdev2("stranger", udid="UDID-A", pair_records=tmp_path)
    assert closed == ["UDID-A", "UDID-A"]

    # another device answering at that address is not the one that was asked for
    (tmp_path / "UDID-B.plist").write_bytes(plistlib.dumps({"HostID": "HOST"}))
    with pytest.raises(DeviceNotFoundError) as other:
        await lockdown_module.create_using_mobdev2("host", udid="UDID-B", pair_records=tmp_path)
    assert other.value.udid == "UDID-B"
    assert closed == ["UDID-A", "UDID-A", "UDID-A"]


@pytest.mark.asyncio
async def test_create_using_mobdev2_without_a_hostname_takes_the_first_paired_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []
    devices = [_Mobdev2Device("UDID-A", closed), _Mobdev2Device("UDID-B", closed)]
    asked: list[dict[str, Any]] = []

    async def get_mobdev2_lockdowns(**kwargs: Any) -> Any:
        asked.append(kwargs)
        for device in devices:
            yield "host", device

    monkeypatch.setattr(lockdown_module, "get_mobdev2_lockdowns", get_mobdev2_lockdowns)

    assert await lockdown_module.create_using_mobdev2(udid="UDID", timeout=1) is devices[0]
    assert asked == [{"udid": "UDID", "pair_records": None, "only_paired": True, "timeout": 1}]

    devices.clear()
    with pytest.raises(NoDeviceConnectedError):
        await lockdown_module.create_using_mobdev2()
    with pytest.raises(DeviceNotFoundError):
        await lockdown_module.create_using_mobdev2(udid="UDID")
