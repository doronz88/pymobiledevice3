import struct
import zlib

import pytest

from pymobiledevice3.remote.core_device import rfb_clipboard


def _split(message: bytes) -> tuple[int, bytes]:
    msg_type, length = struct.unpack(">B3xi", message[:8])
    assert msg_type == rfb_clipboard.SERVER_CUT_TEXT
    assert len(message) == 8 + abs(length)
    return length, message[8:]


def test_classic_cut_text_is_latin1_with_replacement() -> None:
    length, body = _split(rfb_clipboard.classic_server_cut_text("café שלום"))
    assert length == len(body) > 0
    assert body == b"caf\xe9 ????"
    assert rfb_clipboard.decode_classic_text(b"caf\xe9") == "café"


def test_extended_messages_use_a_negative_length() -> None:
    length, body = _split(rfb_clipboard.extended_notify())
    assert length == -4
    assert struct.unpack(">I", body)[0] == rfb_clipboard.ACTION_NOTIFY | rfb_clipboard.FORMAT_TEXT


def test_caps_carries_one_size_per_advertised_format() -> None:
    _, body = _split(rfb_clipboard.extended_caps())
    flags, text_size = struct.unpack(">II", body)
    assert flags & rfb_clipboard.ACTION_CAPS
    assert flags & 0xFFFF == rfb_clipboard.FORMAT_TEXT
    assert text_size == 0


def test_provide_round_trips_unicode_and_newlines() -> None:
    _, body = _split(rfb_clipboard.extended_provide("שלום\nworld"))
    # On the wire: zlib(u32 length + UTF-8 text with CRLF and a NUL terminator).
    raw = zlib.decompress(body[4:])
    assert raw[4:] == "שלום\r\nworld".encode() + b"\x00"
    assert struct.unpack(">I", raw[:4])[0] == len(raw) - 4
    message = rfb_clipboard.parse_extended(body)
    assert message.action == rfb_clipboard.ACTION_PROVIDE
    assert message.text == "שלום\nworld"


def test_parse_request_has_no_text() -> None:
    _, body = _split(rfb_clipboard.extended_request())
    message = rfb_clipboard.parse_extended(body)
    assert message.action == rfb_clipboard.ACTION_REQUEST
    assert message.text is None


def test_oversized_provide_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _, body = _split(rfb_clipboard.extended_provide("x" * 64))
    monkeypatch.setattr(rfb_clipboard, "MAX_TEXT_BYTES", 16)
    with pytest.raises(ValueError):
        rfb_clipboard.parse_extended(body)


def test_caps_is_not_mistaken_for_a_provide() -> None:
    # A caps message sets the PROVIDE and text bits too (as capabilities), followed by sizes.
    _, body = _split(rfb_clipboard.extended_caps())
    message = rfb_clipboard.parse_extended(body)
    assert message.action == rfb_clipboard.ACTION_CAPS
    assert message.text is None
