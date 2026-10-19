"""A restore must only ever touch its own device, so that several can run side by side."""

import asyncio
from typing import Any, Optional

import pytest
import typer

from pymobiledevice3 import irecv
from pymobiledevice3.cli import restore as restore_cli
from pymobiledevice3.exceptions import IRecvError
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.restore import fdr, restored_client
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.usbmux import MuxDevice

ECID_A = 0x001074523440401C
ECID_B = 0x000A1B2C3D4E5F60
UDID_A = f"00008150-{ECID_A:016X}"
UDID_B = f"00008120-{ECID_B:016X}"


@pytest.mark.parametrize(
    ("serial", "ecid"),
    [
        (UDID_A, ECID_A),
        (UDID_A.replace("-", ""), ECID_A),
        ("0123456789abcdef0123456789abcdef01234567", None),  # legacy UDID: no ECID in it
        ("not-a-udid", None),
    ],
)
def test_mux_device_ecid(serial: str, ecid: Optional[int]) -> None:
    assert MuxDevice(devid=1, serial=serial, connection_type="USB").ecid == ecid


class _FakeUsbDevice:
    idVendor = irecv.APPLE_VENDOR_ID
    idProduct = irecv.Mode.RECOVERY_MODE_2.value

    def __init__(self, ecid: int) -> None:
        self.serial_number = f"CPID:8150 CPRV:11 BDID:0C ECID:{ecid:016X} IBFL:3C SRNM:[ABCDEFGHIJ]"


def _find(monkeypatch: pytest.MonkeyPatch, devices: list[_FakeUsbDevice], ecid: Optional[int]) -> IRecv:
    monkeypatch.setattr(irecv, "find", lambda find_all=False, **kwargs: list(devices))
    client = IRecv.__new__(IRecv)
    client._device = None
    client._mode = None
    client._device_info = {}
    client._find(ecid=ecid, timeout=1)
    return client


@pytest.mark.parametrize("target", [ECID_A, ECID_B])
def test_irecv_finds_its_device_among_several_in_recovery(monkeypatch: pytest.MonkeyPatch, target: int) -> None:
    """Regression: a second device in Recovery made the lookup raise even when an ECID was given."""
    client = _find(monkeypatch, [_FakeUsbDevice(ECID_A), _FakeUsbDevice(ECID_B)], target)
    assert client.ecid == target


def test_irecv_without_ecid_refuses_to_guess(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(IRecvError, match="ECID"):
        _find(monkeypatch, [_FakeUsbDevice(ECID_A), _FakeUsbDevice(ECID_B)], None)


class _FakeService:
    async def start(self) -> None:
        pass

    async def send_recv_plist(self, request: dict[str, Any]) -> dict[str, Any]:
        return {"Type": "com.apple.mobile.restored", "RestoreProtocolVersion": 15}

    async def close(self) -> None:
        pass


async def test_restored_lookup_leaves_other_devices_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """Another device's restored must not even be connected to: it may be in the middle of a restore."""
    connected: list[str] = []

    async def list_usb(connection_type: str) -> list[MuxDevice]:
        return [MuxDevice(1, UDID_B, "USB"), MuxDevice(2, UDID_A, "USB")]

    async def create_using_usbmux(serial: str, port: int, connection_type: str = "USB") -> _FakeService:
        connected.append(serial)
        return _FakeService()

    async def fake_connect(self: RestoredClient) -> None:
        self.ecid = ECID_A
        self.hardware_info = {}
        self.saved_debug_info = {}

    monkeypatch.setattr(restored_client, "select_devices_by_connection_type", list_usb)
    monkeypatch.setattr(restored_client.ServiceConnection, "create_using_usbmux", create_using_usbmux)
    monkeypatch.setattr(RestoredClient, "_connect", fake_connect)

    client = await RestoredClient.create(ECID_A)

    assert client.udid == UDID_A
    assert connected == [UDID_A]


async def test_fdr_conn_listener_stays_on_the_ctrl_device(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: the FDR data connections went to whichever USB device usbmuxd listed first."""
    listened: list[Optional[str]] = []

    async def fake_listener(type_: fdr.fdr_type, udid: Optional[str] = None) -> None:
        listened.append(udid)

    class _SyncService:
        async def recvall(self, size: int) -> bytes:
            return b"\x00" * size

    monkeypatch.setattr(fdr, "run_fdr_listener", fake_listener)
    client = fdr.FDRClient(_SyncService(), UDID_A)  # pyright: ignore[reportArgumentType]
    await client.handle_sync_cmd()
    assert client._conn_listener_task is not None
    await asyncio.wait_for(client._conn_listener_task, 1)

    assert listened == [UDID_A]


class _FakeLockdown:
    def __init__(self, ecid: int) -> None:
        self.ecid = ecid


class _FakeDevice:
    def __init__(self, lockdown: Optional[_FakeLockdown] = None, irecv: Any = None) -> None:
        self.lockdown = lockdown

    async def get_is_image4_supported(self) -> bool:
        return True


async def test_cli_with_ecid_ignores_other_connected_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []

    async def list_devices() -> list[MuxDevice]:
        return [MuxDevice(1, UDID_B, "USB"), MuxDevice(2, UDID_A, "USB")]

    async def create_using_usbmux(serial: str, connection_type: str = "USB") -> _FakeLockdown:
        opened.append(serial)
        return _FakeLockdown(ECID_A if serial == UDID_A else ECID_B)

    monkeypatch.setattr(restore_cli, "is_invoked_for_completion", lambda: False)
    monkeypatch.setattr(restore_cli.usbmux, "list_devices", list_devices)
    monkeypatch.setattr(restore_cli, "create_using_usbmux", create_using_usbmux)
    monkeypatch.setattr(restore_cli, "Device", _FakeDevice)

    device = await restore_cli._device_dependency_async(hex(ECID_A))

    assert isinstance(device, _FakeDevice)
    assert device.lockdown is not None
    assert device.lockdown.ecid == ECID_A
    assert opened == [UDID_A]


async def test_cli_without_ecid_refuses_several_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    async def list_devices() -> list[MuxDevice]:
        return [MuxDevice(1, UDID_B, "USB"), MuxDevice(2, UDID_A, "USB")]

    monkeypatch.setattr(restore_cli, "is_invoked_for_completion", lambda: False)
    monkeypatch.setattr(restore_cli.usbmux, "list_devices", list_devices)

    with pytest.raises(typer.Exit):
        await restore_cli._device_dependency_async(None)
