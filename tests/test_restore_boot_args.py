import plistlib
from typing import Any, cast

import pytest
from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.ipsw import IPSW

from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.usb import UsbError

HARDWARE_MODEL = "vresearch101ap"
MANIFEST = {
    "ProductBuildVersion": "22B5054e",
    "ProductVersion": "18.1",
    "SupportedProductTypes": ["iProd99,1"],
    "BuildIdentities": [
        {
            "ApBoardID": "0x90",
            "ApChipID": "0xFE01",
            "Info": {
                "DeviceClass": HARDWARE_MODEL,
                "Variant": "Darwin Cloud Customer Erase Install (IPSW)",
                "RestoreBehavior": "Erase",
            },
            "Manifest": {},
        }
    ],
}


class _FakeIPSW:
    def __init__(self) -> None:
        self.build_manifest = BuildManifest(cast(IPSW, self), plistlib.dumps(MANIFEST))
        self.filelist: list[Any] = []


class _FakeIRecv:
    def getenv(self, name: str) -> str:
        return {"build-version": "iBoot-11881.40.153"}.get(name, "")


class _FakeDevice:
    irecv = _FakeIRecv()

    def get_hardware_model_value(self) -> str:
        return HARDWARE_MODEL


class _StopAfterBootArgs(Exception):
    pass


@pytest.mark.asyncio
async def test_ramdisk_boot_args_match_apples_default(monkeypatch: pytest.MonkeyPatch) -> None:
    recovery = Recovery(cast(IPSW, _FakeIPSW()), cast(Device, _FakeDevice()), behavior=Behavior.Erase)

    async def no_op(*args: Any, **kwargs: Any) -> None:
        pass

    async def stop(*args: Any, **kwargs: Any) -> None:
        raise _StopAfterBootArgs()

    monkeypatch.setattr("asyncio.sleep", no_op)
    monkeypatch.setattr(recovery, "reconnect_irecv", no_op)
    monkeypatch.setattr(recovery, "set_autoboot", lambda enable: None)
    monkeypatch.setattr(recovery, "send_applelogo", stop)

    with pytest.raises(_StopAfterBootArgs):
        await recovery.enter_restore()

    # MobileDevice's default RestoreBootArgs; without `-restore` a cloudOS research VM's restore ramdisk panics
    # in `seputil --gigalocker-shutdown` (REQUIRE fail: _gigalocker_state.available)
    assert recovery.restore_boot_args == "rd=md0 nand-enable-reformat=1 -progress -restore"


class _RecordingIRecv(_FakeIRecv):
    def __init__(self, unknown_commands: tuple[str, ...] = ()) -> None:
        self.unknown_commands = unknown_commands
        self.commands: list[str] = []

    def send_zero_length_download(self) -> None:
        pass

    def send_command(self, cmd: str, b_request: int = 0) -> None:
        self.commands.append(cmd)
        if cmd.split()[0] in self.unknown_commands:
            raise UsbError("the device stalled the request")


async def _boot_args_commands(monkeypatch: pytest.MonkeyPatch, irecv: _RecordingIRecv) -> list[str]:
    device = _FakeDevice()
    monkeypatch.setattr(device, "irecv", irecv, raising=False)
    recovery = Recovery(cast(IPSW, _FakeIPSW()), cast(Device, device), behavior=Behavior.Erase)
    recovery.restore_boot_args = "rd=md0 -restore"

    async def no_op(*args: Any, **kwargs: Any) -> None:
        pass

    monkeypatch.setattr(recovery, "send_component", no_op)
    await recovery.send_kernelcache()
    return [cmd for cmd in irecv.commands if "boot-args" in cmd]


@pytest.mark.asyncio
async def test_boot_args_are_set_without_persisting_them(monkeypatch: pytest.MonkeyPatch) -> None:
    assert await _boot_args_commands(monkeypatch, _RecordingIRecv()) == ["setenvnp boot-args rd=md0 -restore"]


@pytest.mark.asyncio
async def test_boot_args_fall_back_to_setenv_on_an_iboot_without_setenvnp(monkeypatch: pytest.MonkeyPatch) -> None:
    # an iBoot that doesn't know a command stalls the request
    assert await _boot_args_commands(monkeypatch, _RecordingIRecv(unknown_commands=("setenvnp",))) == [
        "setenvnp boot-args rd=md0 -restore",
        "setenv boot-args rd=md0 -restore",
    ]
