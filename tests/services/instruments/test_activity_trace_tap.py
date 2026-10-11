import struct
from typing import Any, cast

import pytest

from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.activity_trace_tap import (
    CMD_DEFINE_TABLE,
    CMD_END_ROW,
    CMD_SENTINEL,
    CMD_STRUCT,
    ActivityTraceTap,
    decode_message_format,
)

OS_LOG_COLUMNS = [
    "time",
    "process",
    "thread",
    "message-type",
    "format-string",
    "backtrace",
    "subsystem",
    "category",
    "sender-image-path",
    "message",
]


def op(opcode: int, argument: int = 0) -> bytes:
    return struct.pack("<H", opcode << 8 | argument)


def push(data: bytes) -> bytes:
    """Push data like the device: trailing zero bits dropped, 14 bits per word, the last word tagged 0b11."""
    bits = int.from_bytes(data, "big")
    bit_count = len(data) * 8
    while bit_count > 14 and bits & 1 == 0:
        bits >>= 1
        bit_count -= 1
    word_count = (bit_count + 13) // 14
    bits <<= word_count * 14 - bit_count
    words = [0x8000 | (bits >> (14 * i)) & 0x3FFF for i in reversed(range(word_count))]
    words[-1] |= 0xC000
    return struct.pack(f"<{word_count}H", *words)


def push_int(value: int) -> bytes:
    """Integers go out as their 64-bit little-endian bytes."""
    return push(struct.pack("<Q", value & 0xFFFF_FFFF_FFFF_FFFF))


def push_str(value: str) -> bytes:
    return push(value.encode() + b"\x00")


def push_struct(*items: bytes) -> bytes:
    return b"".join(items) + op(CMD_STRUCT, len(items))


def message_item(type_: str, value: bytes) -> bytes:
    return push_struct(push_str(type_), value)


def os_log_stream(format_string: str, *items: bytes, thread: int = 0x2149) -> bytes:
    """Define the os-log table and send one row of it, with `items` as its message."""
    table = op(CMD_SENTINEL) + op(CMD_SENTINEL) + push_str("os-log")
    table += push_struct(*(push_str(column) for column in OS_LOG_COLUMNS)) + op(CMD_DEFINE_TABLE)
    process = push_struct(push_int(42), push_str("launchd"))
    row = push_int(0x48AA682F9282) + process + push_struct(push_int(thread), process)
    row += push_str("Default") + push_str(format_string) + op(CMD_SENTINEL) + push_str("kernel") + push_str("")
    row += push_str("/usr/lib/libfoo.dylib") + push_struct(*items)
    return table + row + op(CMD_END_ROW, 0)


def parse(stream: bytes) -> list[Any]:
    tap = ActivityTraceTap(cast(DtxServiceProvider, None))
    tap._set_current_message(stream)
    return list(tap._parse())


@pytest.mark.parametrize("thread", [0x79, 0x2149, 0x16AEE3, 0x13AC36D, 0x166B609, 0xFFFF_FFFF_FFFF])
def test_thread_id_is_decoded_whatever_its_width(thread: int) -> None:
    (message,) = parse(os_log_stream("hello", message_item("narrative-text", push_str("hello")), thread=thread))

    assert message.thread == thread
    assert message.process == 42


def text(value: str) -> bytes:
    return message_item("narrative-text", push_str(value))


def string(value: str) -> bytes:
    return message_item("string", push_str(value))


@pytest.mark.parametrize("value", ["", "a", "kernel", "limit on pid ", "Notes said "])
def test_message_text_is_printed_without_padding(value: str) -> None:
    (message,) = parse(os_log_stream("%s%s", text(value), string(value)))

    assert decode_message_format(message.message) == value * 2
