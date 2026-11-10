import plistlib
from typing import Any, Optional, cast

import pytest
from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.ipsw import IPSW

from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse

HARDWARE_MODEL = "vresearch101ap"


def _manifest(os_environment: Optional[str]) -> dict[str, Any]:
    # modeled on a cloudOS (PCC) BuildManifest: every identity carries Ap,OSEnvironment = 0x06
    identity: dict[str, Any] = {
        "ApBoardID": "0x90",
        "ApChipID": "0xFE01",
        "ApSecurityDomain": "0x01",
        "Info": {
            "DeviceClass": HARDWARE_MODEL,
            "Variant": "Research Darwin Cloud Customer Erase Install (IPSW)",
            "RestoreBehavior": "Erase",
        },
        "Manifest": {},
    }
    if os_environment is not None:
        identity["Ap,OSEnvironment"] = os_environment
    return {
        "ProductBuildVersion": "22B5054e",
        "ProductVersion": "18.1",
        "SupportedProductTypes": ["iProd99,1"],
        "BuildIdentities": [identity],
    }


class _FakeIPSW:
    def __init__(self, manifest: dict[str, Any]) -> None:
        self.build_manifest = BuildManifest(cast(IPSW, self), plistlib.dumps(manifest))
        self.filelist: list[Any] = []


class _FakeDevice:
    lockdown = None

    def get_hardware_model_value(self) -> str:
        return HARDWARE_MODEL

    async def get_ecid(self) -> int:
        return 0x1234

    async def get_ap_nonce(self) -> bytes:
        return b"nonce"

    async def get_sep_nonce(self) -> Optional[bytes]:
        return None

    async def get_is_image4_supported(self) -> bool:
        return True


async def _ap_tss_request(monkeypatch: pytest.MonkeyPatch, os_environment: Optional[str]) -> dict[str, Any]:
    recovery = Recovery(
        cast(IPSW, _FakeIPSW(_manifest(os_environment))), cast(Device, _FakeDevice()), behavior=Behavior.Erase
    )
    sent: list[dict[str, Any]] = []

    async def send_receive(self: TSSRequest) -> TSSResponse:
        sent.append(dict(self._request))
        return TSSResponse({"ApImg4Ticket": b"ticket"})

    monkeypatch.setattr(TSSRequest, "send_receive", send_receive)
    await recovery.get_tss_response()
    assert len(sent) == 1
    return sent[0]


@pytest.mark.asyncio
async def test_os_environment_is_copied_into_the_ap_ticket_request(monkeypatch: pytest.MonkeyPatch) -> None:
    # without it iBoot keeps the default DeviceTree environment instead of the trusted darwinOS one, so a cloudOS
    # research build boots without developer mode and its research cryptexes fail to mount (#1701)
    request = await _ap_tss_request(monkeypatch, "0x06")
    assert request["Ap,OSEnvironment"] == 6


@pytest.mark.asyncio
async def test_identities_without_os_environment_do_not_get_one(monkeypatch: pytest.MonkeyPatch) -> None:
    request = await _ap_tss_request(monkeypatch, None)
    assert "Ap,OSEnvironment" not in request
