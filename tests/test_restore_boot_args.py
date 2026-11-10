import plistlib
from typing import Any, cast

import pytest
from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.ipsw import IPSW

from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Behavior, Recovery

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
