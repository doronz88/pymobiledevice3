import plistlib
from typing import Any, Optional, cast

import pytest
from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.ipsw import IPSW

from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Recovery
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse

HARDWARE_MODEL = "d83ap"
RECOVERY_VARIANT = "Recovery Customer Install"


def _identity(variant: str, behavior: str, info: dict[str, Any], **properties: Any) -> dict[str, Any]:
    return {
        "ApBoardID": "0x04",
        "ApChipID": "0x8130",
        "ApSecurityDomain": "0x01",
        "Info": {"DeviceClass": HARDWARE_MODEL, "Variant": variant, "RestoreBehavior": behavior, **info},
        "Manifest": {},
        **properties,
    }


# as in an iPhone16,1 27.2.1 BuildManifest: the timestamp sits in Info, and no identity of a phone has Ap,VM
REQUESTED = {"RequestManifestProperties": ["Ap,Timestamp", "Ap,VM"], "Ap,Timestamp": 0}


class _FakeIPSW:
    def __init__(self, identities: list[dict[str, Any]]) -> None:
        manifest = {
            "ProductBuildVersion": "24B156",
            "ProductVersion": "27.2.1",
            "SupportedProductTypes": ["iPhone16,1"],
            "BuildIdentities": identities,
        }
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


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []

    async def send_receive(self: TSSRequest) -> TSSResponse:
        requests.append(dict(self._request))
        return TSSResponse({"ApImg4Ticket": b"ticket"})

    monkeypatch.setattr(TSSRequest, "send_receive", send_receive)
    return requests


def _recovery(*identities: dict[str, Any]) -> Recovery:
    return Recovery(cast(IPSW, _FakeIPSW(list(identities))), cast(Device, _FakeDevice()))


@pytest.mark.asyncio
async def test_requested_properties_are_read_from_the_info_and_skipped_when_absent(sent: list[dict[str, Any]]) -> None:
    await _recovery(_identity("Customer Upgrade Install (IPSW)", "Update", REQUESTED)).get_tss_response()
    (request,) = sent
    # with it TSS stamps the ticket (`tstp`), as it does for Apple's host
    assert request["Ap,Timestamp"] == 0
    assert "Ap,VM" not in request


@pytest.mark.asyncio
async def test_a_requested_property_of_the_identity_itself_wins_over_its_info(sent: list[dict[str, Any]]) -> None:
    identity = _identity("Customer Upgrade Install (IPSW)", "Update", {**REQUESTED, "Ap,VM": False}, **{"Ap,VM": True})
    await _recovery(identity).get_tss_response()
    assert sent[0]["Ap,VM"] is True


@pytest.mark.asyncio
async def test_identities_requesting_nothing_get_nothing(sent: list[dict[str, Any]]) -> None:
    await _recovery(_identity("Customer Upgrade Install (IPSW)", "Update", {"Ap,Timestamp": 0})).get_tss_response()
    assert "Ap,Timestamp" not in sent[0]


@pytest.mark.asyncio
async def test_the_recovery_os_ticket_request_follows_its_own_identity(sent: list[dict[str, Any]]) -> None:
    recovery = _recovery(
        _identity("Customer Upgrade Install (IPSW)", "Update", {"RecoveryVariant": RECOVERY_VARIANT}),
        _identity(RECOVERY_VARIANT, "Erase", REQUESTED),
    )
    assert recovery.recovery_variant is not None
    await recovery.get_tss_response()
    await recovery.get_tss_response(recovery.recovery_variant)
    main, recovery_os = sent
    assert "Ap,Timestamp" not in main
    assert recovery_os["Ap,Timestamp"] == 0
