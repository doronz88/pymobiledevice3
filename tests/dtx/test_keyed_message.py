import struct

from pymobiledevice3.dtx.message_aux import build_keyed_aux


def test_keyed_aux_holds_c_string_keys_with_string_and_integer_values() -> None:
    entries = (
        struct.pack("<II", 1, 8) + b"command\0" + struct.pack("<II", 1, 8) + b"capture\0"
        + struct.pack("<II", 1, 4) + b"pid\0" + struct.pack("<IQ", 6, 77)
    )  # fmt: skip

    assert build_keyed_aux({"command": "capture", "pid": 77}) == struct.pack("<QQ", 0x1F0, len(entries)) + entries
