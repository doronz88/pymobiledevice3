from typing import Any, cast

from ipsw_parser.ipsw import IPSW

from pymobiledevice3.remote.xpc_message import XpcInt64Type
from pymobiledevice3.restore.preflight import build_tethered_preflight_payload
from pymobiledevice3.services.restore_service import _xpc_encodable


class _FakeIPSW:
    def __init__(self) -> None:
        self.reads: list[str] = []

    def read(self, path: str) -> bytes:
        self.reads.append(path)
        return path.encode()


IDENTITY: dict[str, Any] = {
    "Rap,ChipID": 8228,
    "Manifest": {
        "Rap,RTKitOS": {"Digest": b"1", "Info": {"Path": "Firmware/Rose/ftab.bin"}},
        "Rap,SoftwareBinaryDsp1": {"Digest": b"2", "Info": {"Path": "Firmware/Rose/ftab.bin"}},
        "BMU,FirmwareMap": {"Digest": b"3", "Info": {"Path": "Firmware/Volchok/FirmwareMap.plist"}},
        "Rap,ChipID": {"Digest": b"4", "Info": {}},  # no file behind it
    },
}


def test_payload_carries_the_identity_and_only_the_updaters_firmware_files():
    ipsw = _FakeIPSW()

    payload = build_tethered_preflight_payload(cast(IPSW, ipsw), IDENTITY, "Rose")

    assert payload["BuildIdentity"] == IDENTITY
    assert payload["Rose"] == {
        "Rap,RTKitOS": b"Firmware/Rose/ftab.bin",
        "Rap,SoftwareBinaryDsp1": b"Firmware/Rose/ftab.bin",
    }
    assert "BMU,FirmwareMap" not in payload["Rose"]
    assert ipsw.reads == ["Firmware/Rose/ftab.bin"]  # one file shared by two tags is read once


def test_xpc_encodable_wraps_ints_but_not_bools_or_bytes():
    encoded = _xpc_encodable({"a": 1, "b": True, "c": b"x", "d": [2, {"e": 3}]})

    assert type(encoded["a"]) is XpcInt64Type and encoded["a"] == 1
    assert encoded["b"] is True
    assert encoded["c"] == b"x"
    assert type(encoded["d"][0]) is XpcInt64Type and type(encoded["d"][1]["e"]) is XpcInt64Type
