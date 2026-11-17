import asyncio
import os
import plistlib
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pymobiledevice3.exceptions import (
    LockdownError,
    MCProtectedError,
    PairingDialogResponsePendingError,
    PairingError,
    PasscodeRequiredError,
    PasswordRequiredError,
    SessionActiveError,
    UserDeniedPairingError,
)
from pymobiledevice3.lockdown import LockdownClient, UsbmuxLockdownClient
from pymobiledevice3.remote.pair_setup import PairingDataComponentTLVBuf, build_pairing_tlv, opack_loads
from pymobiledevice3.remote.pair_setup import PairingDataComponentType as Component
from pymobiledevice3.remote.srp import SrpServer

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
