import plistlib
from pathlib import Path
from typing import Any

import pytest

from pymobiledevice3.restore.tss import TSSRequest

XCODE_DDI = Path("/Library/Developer/DeveloperDiskImages/iOS_DDI/Restore/BuildManifest.plist")

# Values as reported by CryptexdService.read_personalization_identifiers on an iPhone12,1.
CHIP_INSTANCE: dict[str, Any] = {
    "img4_chip_chip": 32816,
    "img4_chip_bord": 4,
    "img4_chip_ecid": 586125774848046,
    "img4_chip_sdom": 1,
    "img4_chip_cpro": 1,
    "img4_chip_csec": 1,
    "img4_chip_cepo": 1,
    "img4_chip_clas": 242,
    "img4_chip_fchp": 65296,
    "img4_chip_type": 3,
}
NONCE = bytes(range(48))

CRYPTEX_IDENTITY: dict[str, Any] = {
    "Cryptex1,ChipID": "0xFF10",
    "Cryptex1,ProductClass": "0xF2",
    "Cryptex1,Type": 3,
    "Cryptex1,SubType": 2,
    "Cryptex1,NonceDomain": 4,
    "Cryptex1,UseProductClass": True,
    "Cryptex1,Version": "39.999.999.0.0,0",
    "Cryptex1,PreauthorizationVersion": "39.999.999.0.0,0",
    "Manifest": {
        # Personalize: False -- must be omitted; the signed manifest carries no dmg digest.
        "Cryptex1,GenericDmg": {"Digest": b"\x01", "Info": {"Personalize": False}},
        "Cryptex1,CryptexInfoPlist": {"Digest": b"\x02", "Info": {"Personalize": True}},
        "Cryptex1,GenericTrustCache": {"Digest": b"\x03", "Info": {"Personalize": True}},
        "Cryptex1,GenericVolume": {"Digest": b"\x04", "Info": {"Personalize": True}},
    },
}


def _request() -> dict[str, Any]:
    request = TSSRequest()
    request.add_cryptex1_tags(CRYPTEX_IDENTITY, CHIP_INSTANCE, NONCE)
    return request._request


def test_requests_a_cryptex1_ticket_not_an_ap_ticket() -> None:
    assert _request()["@Cryptex1,Ticket"] is True


def test_carries_the_cryptex1_chip_parameters() -> None:
    # These become the fchp/type/styp/clas/ndom/upcl/vnum/pave tags in the signed manifest.
    request = _request()
    assert request["Cryptex1,ChipID"] == 0xFF10
    assert request["Cryptex1,ProductClass"] == 0xF2
    assert request["Cryptex1,Type"] == 3
    assert request["Cryptex1,SubType"] == 2
    assert request["Cryptex1,NonceDomain"] == 4
    assert request["Cryptex1,UseProductClass"] is True
    assert request["Cryptex1,Version"] == "39.999.999.0.0,0"
    assert request["Cryptex1,PreauthorizationVersion"] == "39.999.999.0.0,0"


def test_nonce_is_sent_raw() -> None:
    # Verified on-device: the signed cnch tag equals the nonce byte-for-byte, unhashed.
    assert _request()["Cryptex1,Nonce"] == NONCE


def test_device_identity_comes_from_the_chip_instance() -> None:
    request = _request()
    assert request["ApECID"] == CHIP_INSTANCE["img4_chip_ecid"]
    assert request["ApChipID"] == CHIP_INSTANCE["img4_chip_chip"]
    assert request["ApProductionMode"] is True


def test_only_personalized_components_are_included() -> None:
    # Cryptex1,GenericDmg is Personalize: False; Xcode's ticket signs only ginf/gtcd/gtgv.
    request = _request()
    assert "Cryptex1,GenericDmg" not in request
    for key in ("Cryptex1,CryptexInfoPlist", "Cryptex1,GenericTrustCache", "Cryptex1,GenericVolume"):
        assert key in request
        assert "Info" not in request[key]


@pytest.mark.skipif(not XCODE_DDI.exists(), reason="Xcode DDI bundle not installed")
def test_against_the_real_build_manifest() -> None:
    """The one cryptex identity in Xcode's DDI must drive a complete request."""
    build_manifest = plistlib.loads(XCODE_DDI.read_bytes())
    identity = next(
        bi for bi in build_manifest["BuildIdentities"] if "Cryptex" in bi.get("Info", {}).get("Variant", "")
    )

    request = TSSRequest()
    request.add_cryptex1_tags(identity, CHIP_INSTANCE, NONCE)

    assert request._request["Cryptex1,NonceDomain"] == 4
    assert "Cryptex1,GenericDmg" not in request._request
    assert "Cryptex1,CryptexInfoPlist" in request._request
