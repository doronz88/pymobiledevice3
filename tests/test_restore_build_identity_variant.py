import plistlib
from typing import Any, cast

import pytest
from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.exceptions import NoSuchBuildIdentityError
from ipsw_parser.ipsw import IPSW

from pymobiledevice3.restore.base_restore import BaseRestore, Behavior
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.restore import Restore

HARDWARE_MODEL = "vresearch101ap"
CUSTOMER = "Darwin Cloud Customer Erase Install (IPSW)"
RESEARCH = "Research Darwin Cloud Customer Erase Install (IPSW)"


def _identity(variant: str) -> dict[str, Any]:
    return {
        "ApBoardID": "0x90",
        "ApChipID": "0xFE01",
        "Info": {"DeviceClass": HARDWARE_MODEL, "Variant": variant, "RestoreBehavior": "Erase"},
        "Manifest": {},
    }


# order as in the cloudOS (PCC) research IPSW: the customer identity comes first
MANIFEST = {
    "ProductBuildVersion": "22B5054e",
    "ProductVersion": "18.1",
    "SupportedProductTypes": ["iProd99,1"],
    "BuildIdentities": [_identity(CUSTOMER), _identity(RESEARCH)],
}


class _FakeIPSW:
    def __init__(self) -> None:
        self.build_manifest = BuildManifest(cast(IPSW, self), plistlib.dumps(MANIFEST))
        self.filelist: list[Any] = []


class _FakeDevice:
    def get_hardware_model_value(self) -> str:
        return HARDWARE_MODEL


def _ipsw() -> IPSW:
    return cast(IPSW, _FakeIPSW())


def _device() -> Device:
    return cast(Device, _FakeDevice())


@pytest.mark.asyncio
async def test_erase_picks_the_first_matching_identity_by_default() -> None:
    assert BaseRestore(_ipsw(), _device(), behavior=Behavior.Erase).build_identity.variant == CUSTOMER


@pytest.mark.asyncio
async def test_variant_selects_the_identity_by_its_exact_name() -> None:
    restore = Restore(_ipsw(), _device(), behavior=Behavior.Erase, variant=RESEARCH)
    assert restore.build_identity.variant == RESEARCH
    # the recovery half (iBSS/iBEC/ramdisk and the AP ticket) must use the same identity
    assert restore.recovery.build_identity.variant == RESEARCH


@pytest.mark.asyncio
async def test_variant_is_not_matched_as_a_substring() -> None:
    with pytest.raises(NoSuchBuildIdentityError, match="available"):
        BaseRestore(_ipsw(), _device(), behavior=Behavior.Erase, variant="Erase Install (IPSW)")
