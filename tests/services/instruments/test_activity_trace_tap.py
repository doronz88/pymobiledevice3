import plistlib
import struct
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, Optional, cast

import pytest
from bpylist2 import archiver

from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.activity_trace_tap import (
    CMD_DEFINE_TABLE,
    CMD_END_ROW,
    CMD_SENTINEL,
    CMD_STRUCT,
    ActivityTraceTap,
    decode_message_arguments,
    decode_message_format,
)
from pymobiledevice3.services.dvt.instruments.tap import TapMessageChannel

# mach continuous time of the synthetic row, in ticks of the 24 MHz timebase
ROW_TIME = 0x48AA682F9282
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


def os_log_stream(format_string: str, *items: bytes, thread: int = 0x2149, time: Optional[int] = ROW_TIME) -> bytes:
    """Define the os-log table and send one row of it, with `items` as its message."""
    table = op(CMD_SENTINEL) + op(CMD_SENTINEL) + push_str("os-log")
    table += push_struct(*(push_str(column) for column in OS_LOG_COLUMNS)) + op(CMD_DEFINE_TABLE)
    process = push_struct(push_int(42), push_str("launchd"))
    row = (op(CMD_SENTINEL) if time is None else push_int(time)) + process + push_struct(push_int(thread), process)
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
    (message,) = parse(os_log_stream("%s%s.", text(value), string(value), text(".")))

    assert decode_message_format(message.message) == value * 2 + "."


def integer(value: int, type_: str = "uint64") -> bytes:
    return message_item(type_, push_int(value))


def double(value: float) -> bytes:
    return message_item("fixed-decimal", push(struct.pack("<d", value)))


def formatted(format_string: str, *items: bytes) -> str:
    (message,) = parse(os_log_stream(format_string, *items))
    return decode_message_format(message.message, message.format_string)


@pytest.mark.parametrize(
    ("format_string", "items", "expected"),
    [
        ("limit on pid %d", [text("limit on pid "), integer(-1)], "limit on pid -1"),
        ("%d", [integer(0xFFFFFFFF)], "-1"),
        ("%{public}hhd", [integer(0xFF)], "-1"),
        ("%lld", [integer(-5)], "-5"),
        ("%i", [integer(1233)], "1233"),
        ("%u", [integer(-1)], "4294967295"),
        ("%lu", [integer(-1)], "18446744073709551615"),
        ("%hu", [integer(0x12345)], "9029"),
        ("%x", [integer(-1, "uint64-hex-lowercase")], "ffffffff"),
        ("0x%08x", [text("0x"), integer(0x1F, "uint64-hex-lowercase")], "0x0000001f"),
        ("%llX", [integer(0xABCDEF0123, "uint64-hex-lowercase")], "ABCDEF0123"),
        ("%p", [integer(0x16FDEB000, "address")], "0x16fdeb000"),
        ("%c", [integer(ord("="))], "="),
        ("%f", [double(2.9523653102880343)], "2.952365"),
        ("%{public}.2f", [double(2.9523653102880343)], "2.95"),
        ("%lf", [double(-1.0)], "-1.000000"),
        ("%f", [double(0.0)], "0.000000"),
        ("%g", [double(0.25)], "0.25"),
        ("100%% at %d", [text("100% at "), integer(7)], "100% at 7"),
        ("%+u", [integer(5)], "5"),
        ("% x", [integer(0xFF, "uint64-hex-lowercase")], "ff"),
        ("%#x", [integer(0, "uint64-hex-lowercase")], "0"),
        ("%#o", [integer(8)], "010"),
        ("%#5o", [integer(8)], "  010"),
        ("%.0d", [integer(0)], ""),
        ("%+.0d", [integer(0)], "+"),
        ("%05.3d", [integer(5)], "  005"),
        ("%05f", [double(float("inf"))], "  inf"),
    ],
)
def test_numbers_are_printed_per_their_conversion(format_string: str, items: list[bytes], expected: str) -> None:
    assert formatted(format_string, *items) == expected


def test_strings_are_printed_as_sent() -> None:
    items = [string("Notes"), text(" said "), string("%d"), text(" for "), integer(-1)]

    assert formatted("%{public}s said %@ for %d", *items) == "Notes said %d for -1"


def test_arguments_past_the_last_one_sent_keep_their_conversions() -> None:
    # os_log sends at most 48 arguments; the rest of the format string comes as plain text
    items = [item for _ in range(48) for item in (integer(-1), text(" "))]

    assert formatted("%d " * 50, *items, text("%d %d ")) == "-1 " * 48 + "%d %d"


def test_numbers_without_a_matching_conversion_are_printed_by_type() -> None:
    assert formatted("%s", integer(-1), text(" "), integer(16, "uint64-hex-lowercase")) == "18446744073709551615 10"


@pytest.mark.parametrize(
    ("format_string", "items", "expected"),
    [
        (
            "%{public, signpost.description:begin_time}llu seed=%{public, name=transaction_seed}#x",
            [text(" seed="), integer(0x6CB, "uint64-hex-lowercase")],
            " seed=0x6cb",
        ),
        (
            "%{public, signpost.description:end_time}llu Result=%{public, signpost.telemetry:number1,name=Result}lld",
            [text(" Result="), integer(-2)],
            " Result=-2",
        ),
        (
            "client-%i %{public, signpost.description:begin_time}llu %{public, signpost.description:end_time}llu",
            [text("client-"), integer(-3), text(" "), text(" ")],
            "client--3",
        ),
    ],
)
def test_signpost_times_without_an_item(format_string: str, items: list[bytes], expected: str) -> None:
    # iOS 27 sends no item for a signpost's begin and end time
    assert formatted(format_string, *items) == expected


def test_signpost_times_with_an_item() -> None:
    # iOS 16 sends the begin time as an item like any other argument
    format_string = "%{public, signpost.description:begin_time}llu seed=%{public, name=transaction_seed}#x"
    items = [integer(8399240568563), text(" seed="), integer(0x451A, "uint64-hex-lowercase")]

    assert formatted(format_string, *items) == "8399240568563 seed=0x451a"


def test_signpost_attributes_send_their_item() -> None:
    items = [text("pid="), integer(-1)]

    assert formatted("%{public, signpost.description:attribute}d", *items[1:]) == "-1"
    assert formatted("pid=%{public, signpost.description:attribute}d", *items) == "pid=-1"


def test_items_that_do_not_fit_their_conversion_are_printed_by_type() -> None:
    # out of step: the hex item lands on %llu and the double on %x
    items = [integer(0x6CB, "uint64-hex-lowercase"), text(" "), double(0.25)]

    assert formatted("%llu %x", *items) == "6cb 4598175219545276416"


class FakeTapChannel:
    def __init__(self, *messages: bytes) -> None:
        self.messages = list(messages)

    async def receive_message(self) -> bytes:
        return self.messages.pop(0)


async def first_message(tap: ActivityTraceTap) -> Any:
    async for message in cast(AsyncIterator[Any], tap):
        return message
    raise AssertionError("the tap stopped without yielding")


def tap_reading(*messages: bytes) -> ActivityTraceTap:
    tap = ActivityTraceTap(cast(DtxServiceProvider, None))
    tap._message_channel = cast(TapMessageChannel, FakeTapChannel(*messages))
    return tap


TIME_MAPPING = {
    # one second before the row: 24,000,000 ticks of 125/3 ns
    "DTActivityTraceTapDeviceMachContinuousTimeKey": ROW_TIME - 24_000_000,
    "DTActivityTraceTapDeviceTimeIntervalSince1970Key": 1791734188.5,
    "DTActivityTraceTapDeviceMachTimebaseNumeratorKey": 125,
    "DTActivityTraceTapDeviceMachTimebaseDenominatorKey": 3,
}


def time_mapping_notice(**fields: Any) -> bytes:
    return archiver.archive({"notice": "Time Mapping", **fields})


async def test_rows_are_stamped_with_the_device_clock() -> None:
    heartbeat = archiver.archive({"k": 8, "heart": ROW_TIME})
    tap = tap_reading(time_mapping_notice(info=TIME_MAPPING), heartbeat, os_log_stream("hello", text("hello")))

    message = await first_message(tap)

    assert message.device_time == datetime.fromtimestamp(1791734189.5)
    assert int.from_bytes(message.time, "little") == ROW_TIME


UNKNOWN_CLASS_ARCHIVE = plistlib.dumps(
    {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$top": {"root": plistlib.UID(1)},
        "$objects": [
            "$null",
            {"$class": plistlib.UID(2)},
            {"$classname": "DTFutureNotice", "$classes": ["DTFutureNotice", "NSObject"]},
        ],
    },
    fmt=plistlib.FMT_BINARY,
)


@pytest.mark.parametrize(
    ("notices", "row_time"),
    [
        pytest.param([], ROW_TIME, id="no notice"),
        pytest.param([time_mapping_notice()], ROW_TIME, id="no info"),
        pytest.param([time_mapping_notice(info=None)], ROW_TIME, id="info is None"),
        pytest.param([time_mapping_notice(info=["x"])], ROW_TIME, id="info is a list"),
        pytest.param(
            [time_mapping_notice(info={k.replace("TraceTap", ""): v for k, v in TIME_MAPPING.items()})],
            ROW_TIME,
            id="renamed keys",
        ),
        pytest.param(
            [time_mapping_notice(info={k: v for k, v in TIME_MAPPING.items() if "Numerator" not in k})],
            ROW_TIME,
            id="no numerator",
        ),
        pytest.param(
            [time_mapping_notice(info={**TIME_MAPPING, "DTActivityTraceTapDeviceMachTimebaseDenominatorKey": 0})],
            ROW_TIME,
            id="zero denominator",
        ),
        pytest.param(
            [time_mapping_notice(info={**TIME_MAPPING, "DTActivityTraceTapDeviceMachTimebaseNumeratorKey": 0})],
            ROW_TIME,
            id="zero numerator",
        ),
        pytest.param(
            [time_mapping_notice(info={**TIME_MAPPING, "DTActivityTraceTapDeviceMachTimebaseDenominatorKey": -3})],
            ROW_TIME,
            id="negative denominator",
        ),
        pytest.param(
            [time_mapping_notice(info={**TIME_MAPPING, "DTActivityTraceTapDeviceTimeIntervalSince1970Key": "soon"})],
            ROW_TIME,
            id="wall clock not a number",
        ),
        pytest.param(
            [time_mapping_notice(info={**TIME_MAPPING, "DTActivityTraceTapDeviceTimeIntervalSince1970Key": 1e20})],
            ROW_TIME,
            id="wall clock out of range",
        ),
        pytest.param(
            [time_mapping_notice(info={**TIME_MAPPING, "DTActivityTraceTapDeviceMachContinuousTimeKey": float("inf")})],
            ROW_TIME,
            id="continuous time not finite",
        ),
        pytest.param([plistlib.dumps({"a": 1}, fmt=plistlib.FMT_BINARY)], ROW_TIME, id="plain plist"),
        pytest.param([b"bplist00\x00\x01garbage"], ROW_TIME, id="corrupt plist"),
        pytest.param([UNKNOWN_CLASS_ARCHIVE], ROW_TIME, id="unknown archived class"),
        pytest.param([archiver.archive(["Time Mapping"])], ROW_TIME, id="archive of a list"),
        pytest.param([time_mapping_notice(info=TIME_MAPPING)], None, id="row without a time"),
    ],
)
async def test_rows_have_no_device_time_without_a_usable_time_mapping(
    notices: list[bytes], row_time: Optional[int]
) -> None:
    message = await first_message(tap_reading(*notices, os_log_stream("hello", text("hello"), time=row_time)))

    assert message.device_time is None


async def test_rows_of_a_table_share_one_class() -> None:
    # the second frame's row also ends with table 0
    tap = tap_reading(os_log_stream("one", text("one")), os_log_stream("two", text("two")))

    messages = cast(AsyncIterator[Any], tap).__aiter__()
    first, second = await messages.__anext__(), await messages.__anext__()

    assert decode_message_format(second.message, second.format_string) == "two"
    assert type(first) is type(second)


def test_a_literal_percent_is_printed_once() -> None:
    assert formatted("%u%% of %u%%", integer(8), text("%% of "), integer(9), text("%%")) == "8% of 9%"


def test_a_line_ends_at_its_last_visible_character() -> None:
    assert formatted("flush %s \n", text("flush "), string("done"), text(" \n")) == "flush done"


def test_a_nil_object_is_printed_as_null() -> None:
    assert formatted("result=%@, error=%{public}@", text("result="), string(""), text(", error="), string("x")) == (
        "result=(null), error=x"
    )


@pytest.mark.parametrize(
    ("conversion", "value", "expected"),
    [
        ("%s", "", "[]"),
        ("%-8s", "ab", "[ab      ]"),
        ("%8s", "ab", "[      ab]"),
        ("%{public}.0s", "", "[]"),
        ("%.1s", "ab", "[a]"),
        ("%*s", "ab", "[ab]"),
    ],
)
def test_strings_are_padded_and_cut_per_their_conversion(conversion: str, value: str, expected: str) -> None:
    assert formatted(f"[{conversion}]", text("["), string(value), text("]")) == expected


# a uuid as an iOS 27.0 device sends it: its halves in a push each, as bytes for data and as integers for a uuid
UUID_HALVES = (bytes.fromhex("15353e6d9b264ea2"), bytes.fromhex("aa0a52ee4bd1fcf6"))


def uuid_item(*halves: bytes) -> bytes:
    return message_item("uuid", push_struct(*(push(half[::-1]) for half in halves)))


def data_item(length: int, *chunks: bytes) -> bytes:
    return message_item("data", push_struct(push(bytes([length])), *(push(chunk) for chunk in chunks)))


@pytest.mark.parametrize(
    ("format_string", "item", "expected"),
    [
        ("%{public,uuid_t}.16P", uuid_item(*UUID_HALVES), "15353E6D-9B26-4EA2-AA0A-52EE4BD1FCF6"),
        ("%{public,uuid_t}.16P", uuid_item(b"\x00", b"\x00"), "00000000-0000-0000-0000-000000000000"),
        ("%{public,uuid}.16P", data_item(16, *UUID_HALVES), "15353E6D-9B26-4EA2-AA0A-52EE4BD1FCF6"),
        ("%.*P", data_item(10, *UUID_HALVES), "15353e6d9b264ea2aa0a"),
        ("%.*P", data_item(0), ""),
    ],
)
def test_uuids_and_data_are_put_back_together(format_string: str, item: bytes, expected: str) -> None:
    assert formatted(format_string, item) == expected


@pytest.mark.parametrize(
    ("conversion", "item", "expected"),
    [
        ("%{bool}d", integer(1), "true"),
        ("%{bool,public}d", integer(0), "false"),
        ("%{BOOL}d", integer(1), "YES"),
        ("%{public, BOOL}u", integer(0), "NO"),
        ("%{darwin.errno}d", integer(2), "[2: No such file or directory]"),
        ("%{errno}d", integer(3, "errno-value"), "[3: No such process]"),
        ("%{errno}d", integer(4096, "errno-value"), "[4096: Unknown error: 4096]"),
        ("%{public}d", integer(-1), "-1"),
        ("%d", integer(3, "errno-value"), "3"),
    ],
)
def test_integers_are_printed_per_their_value_type(conversion: str, item: bytes, expected: str) -> None:
    assert formatted(f"is {conversion}", text("is "), item) == f"is {expected}"


@pytest.mark.parametrize(
    ("conversion", "item", "expected"),
    [
        ("%{network:tcp_flags}x", integer(0xC2, "uint64-hex-lowercase"), "[SEC]"),
        ("%{network:tcp_flags}x", integer(0x11, "uint64-hex-lowercase"), "[F.]"),
        ("%{network:tcp_flags}x", integer(0x52, "uint64-hex-lowercase"), "[S.E]"),
        ("%{network:tcp_state}x", integer(2, "uint64-hex-lowercase"), "SYN_SENT"),
        ("%{network:tcp_state}x", integer(8, "uint64-hex-lowercase"), "LAST_ACK"),
        ("%{network:tcp_state}x", integer(0x2A, "uint64-hex-lowercase"), "2a"),
        ("%{mdns:dn_hash}u", integer(3287482886), "<dn:w/MCBg>"),
        ("%{mdns:rrtype}d", integer(28), "AAAA"),
        ("%{mdns:rrtype}d", integer(65), "HTTPS"),
        ("%{mdns:rrtype}d", integer(999), "999"),
        ("%{mdns:addrmv}d", integer(1), "add"),
        ("%{mdns:nreason}d", integer(3), "query-suppressed"),
        ("%{mdns:yesno}d", integer(0), "no"),
        ("%{public, location:escape_only}s", string('a/b "c"'), '"a\\/b \\"c\\""'),
        ("%{public, location:escape_only}@", string(""), '""'),
    ],
)
def test_arguments_of_a_framework_value_type_are_printed_like_the_device(
    conversion: str, item: bytes, expected: str
) -> None:
    assert formatted(f"is {conversion}", text("is "), item) == f"is {expected}"


def test_arguments_are_listed_by_type_without_the_narrative_text() -> None:
    items = [
        text("pid "),
        integer(-1),
        text(" at "),
        integer(0x659290A00, "address"),
        string("launchd"),
        double(0.25),
        double(float("inf")),
        message_item("private", push(b"\x00")),
        message_item("string", op(CMD_SENTINEL)),
        integer(3, "errno-value"),
        uuid_item(*UUID_HALVES),
        uuid_item(b"\x00", b"\x00"),
        data_item(10, *UUID_HALVES),
    ]
    (message,) = parse(os_log_stream("pid %d at %p %s %f %f %{private}@ %@ %{errno}d %.16P %.16P %.*P", *items))

    assert decode_message_arguments(message.message) == [
        {"type": "uint64", "value": 0xFFFF_FFFF_FFFF_FFFF},
        {"type": "address", "value": 0x659290A00},
        {"type": "string", "value": "launchd"},
        {"type": "fixed-decimal", "value": 0.25},
        {"type": "fixed-decimal", "value": "inf"},
        {"type": "private", "value": None},
        {"type": "string", "value": None},
        {"type": "errno-value", "value": 3},
        {"type": "uuid", "value": "15353e6d-9b26-4ea2-aa0a-52ee4bd1fcf6"},
        {"type": "uuid", "value": "00000000-0000-0000-0000-000000000000"},
        {"type": "data", "value": "15353e6d9b264ea2aa0a"},
    ]


def test_a_row_without_a_message_has_no_arguments() -> None:
    assert decode_message_arguments(None) == []
