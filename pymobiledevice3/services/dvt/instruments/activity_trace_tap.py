import base64
import dataclasses
import json
import math
import os
import re
import struct
import uuid
from collections.abc import AsyncGenerator, Callable, Generator
from datetime import datetime
from io import BytesIO
from typing import Any, Optional, Union, cast

from bpylist2 import archiver

from pymobiledevice3.darwin_errno import DARWIN_ERRNO_MESSAGES
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.tap import Tap

CMD_DEFINE_TABLE = 1
CMD_END_ROW = 2
CMD_CONVERT_MACH_CONTINUOUS = 5
CMD_TABLE_RESET = 0x64
CMD_COPY = 0x65
CMD_SENTINEL = 0x68
CMD_STRUCT = 0x69
CMD_PLACEHOLDER_COUNT = 0x6A
CMD_DEBUG = 0x6B

# a printf conversion as os_log writes it, e.g. "%d", "%{public}llu", "%08x" or "%{private}@"
FORMAT_SPECIFIER = re.compile(r"%(?:\{[^}]*\})?([-+ #0']*)(\d+|\*)?(?:\.(\d*|\*))?(hh|h|ll|l|q|j|z|t|L)?([a-zA-Z@%])")
# bits in an integer argument by length modifier; l, ll, q, j, z and t are all 64-bit on arm64
INTEGER_BITS: dict[Optional[str], int] = {"hh": 8, "h": 16, None: 32}
# conversions for a signpost's begin and end time; iOS 16 sends an item for them, iOS 27 doesn't
SIGNPOST_TIMES = ("signpost.description:begin_time", "signpost.description:end_time")
# the options between a conversion's braces that say who may read the argument, not how to print it
PRIVACY_OPTIONS = ("public", "private", "sensitive")
# TCP header flags in the order %{network:tcp_flags}x prints them, and connection states by number
TCP_FLAGS = ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "."), (0x20, "U"), (0x40, "E"), (0x80, "C"))
TCP_STATES = (
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RECEIVED",
    "ESTABLISHED",
    "CLOSE_WAIT",
    "FIN_WAIT_1",
    "CLOSING",
    "LAST_ACK",
    "FIN_WAIT_2",
    "TIME_WAIT",
)
# the names of the integer value types that are enumerations, by value; a value not listed prints as its number
ENUMERATIONS: dict[str, dict[int, str]] = {
    "mdns:yesno": {0: "no", 1: "yes"},
    "mdns:addrmv": {1: "add"},
    "mdns:nreason": {1: "no-data", 3: "query-suppressed"},
    "mdns:rrtype": {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        64: "SVCB",
        65: "HTTPS",
    },
}


def _parse_time_mapping(message: bytes) -> Optional[tuple[int, float, int, int]]:
    """
    Read the device's clock from a "Time Mapping" notice.

    :returns: (mach continuous time, seconds since 1970 at that time, timebase numerator, timebase denominator),
        or None for any other message or a notice of an unexpected shape.
    """
    try:
        notice: Any = archiver.unarchive(message)
    except Exception:
        return None
    if not isinstance(notice, dict) or cast(dict[str, Any], notice).get("notice") != "Time Mapping":
        return None
    try:
        info = cast(dict[str, Any], notice)["info"]
        continuous = int(info["DTActivityTraceTapDeviceMachContinuousTimeKey"])
        since1970 = float(info["DTActivityTraceTapDeviceTimeIntervalSince1970Key"])
        numerator = int(info["DTActivityTraceTapDeviceMachTimebaseNumeratorKey"])
        denominator = int(info["DTActivityTraceTapDeviceMachTimebaseDenominatorKey"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if numerator <= 0 or denominator <= 0:
        return None
    return continuous, since1970, numerator, denominator


@dataclasses.dataclass
class Table:
    unknown0: str
    unknown2: str
    name: str
    columns: list[Any]
    # the class of the table's rows, built once since `make_dataclass` costs far more than parsing a row
    row_class: Optional[type] = None


def decode_str(s: bytes):
    return s.split(b"\x00", 1)[0].decode()


def ignored_null(s: bytes) -> bytes:
    if len(s) == 0:
        return s

    if s[-1] == 0:
        s = s[:-1]
    return s


def format_number(value: int, specifier: re.Match[str]) -> Optional[str]:
    """
    Print a message argument the way printf prints it for `specifier`.

    :param value: The argument as the device sends it, widened to 64 bits.
    :param specifier: The argument's conversion, matched by `FORMAT_SPECIFIER`.
    :returns: The printed value, or None if the conversion does not print a number (%s, %@, %P, ...).
    """
    flags, width, precision, length, conversion = specifier.groups()
    # a "*" width or precision is not sent as an item of its own, so its value is unknown here
    width = None if width == "*" else width
    precision = None if precision == "*" else precision
    number: Union[int, float]
    if conversion in "fFeEgG":
        number = struct.unpack("<d", struct.pack("<Q", value))[0]
        if not math.isfinite(number):
            # C pads inf and nan with spaces even under "0"
            flags = flags.replace("0", "")
    elif conversion == "p":
        number, flags, conversion = value, "#", "x"
    elif conversion in "diouxX" or (conversion == "c" and length is None):
        bits = 8 if conversion == "c" else INTEGER_BITS.get(length, 64)
        number = value & ((1 << bits) - 1)
        if conversion in "di" and number >> (bits - 1):
            number -= 1 << bits
        # where Python's % differs from C: unsigned conversions take no sign, "#" puts no 0x on a zero,
        # a precision turns off "0" padding and prints a zero as nothing, and "#o" means a leading 0, not 0o
        if conversion in "ouxX":
            flags = flags.replace("+", "").replace(" ", "")
        if conversion in "xX" and number == 0:
            flags = flags.replace("#", "")
        if precision is not None and conversion != "c":
            flags = flags.replace("0", "")
            if number == 0 and not int(precision or 0) and not (conversion == "o" and "#" in flags):
                sign = "+" if "+" in flags else " " if " " in flags else ""
                return ("%" + ("-" if "-" in flags else "") + (width or "") + "s") % sign
        if conversion == "o" and "#" in flags:
            flags = flags.replace("#", "")
            precision = str(max(int(precision or 0), len(f"{number:o}") + (number != 0)))
    else:
        return None
    spec = "%" + flags.replace("'", "")
    if width is not None:
        spec += width
    if precision is not None:
        spec += "." + precision
    return (spec + conversion) % number


def value_type(specifier: re.Match[str]) -> Optional[str]:
    """The value type a conversion names between its braces, e.g. "bool" for "%{public, bool}d"."""
    options = re.match(r"%\{([^}]*)\}", specifier.group(0))
    if options is None:
        return None
    types = [o.strip() for o in options.group(1).split(",") if o.strip() not in PRIVACY_OPTIONS]
    return types[-1] if types else None


def format_typed_number(value: int, type_: Optional[str]) -> Optional[str]:
    """
    Print an integer argument the way os_log prints it for the value type of its conversion.

    :returns: The printed value, or None for a type that prints as the plain number.
    """
    if type_ == "bool":
        return "true" if value else "false"
    if type_ == "BOOL":
        return "YES" if value else "NO"
    if type_ in ("errno", "darwin.errno"):
        return f"[{value}: {DARWIN_ERRNO_MESSAGES.get(value, f'Unknown error: {value}')}]"
    if type_ == "network:tcp_flags":
        return "[" + "".join(letter for bit, letter in TCP_FLAGS if value & bit) + "]"
    if type_ == "network:tcp_state" and value < len(TCP_STATES):
        return TCP_STATES[value]
    if type_ == "mdns:dn_hash":
        return "<dn:" + base64.b64encode(struct.pack(">I", value & 0xFFFFFFFF)).decode().rstrip("=") + ">"
    return ENUMERATIONS.get(type_ or "", {}).get(value)


def join_chunks(chunks: list[bytes]) -> list[bytes]:
    """The 8-byte chunks a uuid or data item is sent in, each a push of its own, restored to 8 bytes."""
    return [chunk[:8].ljust(8, b"\x00") for chunk in chunks]


def item_fits(type_: str, conversion: str) -> bool:
    """Whether a message item of `type_` can be the argument of a `conversion`, e.g. not a hex item for %llu."""
    if "decimal" in type_:
        return conversion in "fFeEgG"
    if "hex" in type_:
        return conversion in "xXp"
    return conversion not in "fFeEgG"


def decode_message_format(message: Any, format_string: Optional[str] = None) -> str:
    """
    Join a row's message items into the logged line.

    :param message: The row's `message` column: (type, data) items, one per piece of narrative text or argument.
    :param format_string: The row's format string. When given, numbers are printed per their printf conversion
        instead of as unsigned 64-bit integers.
    """
    # there is one item per conversion, in order (os_log keeps the first 48); with more items than conversions
    # they cannot be paired up, so those numbers are printed by their type alone
    specifiers = [m for m in FORMAT_SPECIFIER.finditer(format_string or "") if m.group(5) != "%"]
    items = sum(decode_str(type_) != "narrative-text" for type_, _ in message)
    if items < len(specifiers):
        without_times = [m for m in specifiers if not any(time in m.group(0) for time in SIGNPOST_TIMES)]
        if items == len(without_times):
            specifiers = without_times
    if items > len(specifiers):
        specifiers = []
    next_specifier = iter(specifiers)

    s = ""
    for type_, data in message:
        if data and isinstance(data, bytes):
            data = ignored_null(data)
        type_ = decode_str(type_)
        specifier = None if type_ == "narrative-text" else next(next_specifier, None)

        if type_ == "address":
            type_ = "uint64-hex"
        elif type_ == "errno-value":
            type_ = "uint64"

        if type_ in ("narrative-text", "string") and data is None:
            s += "<None>"
        elif type_ == "narrative-text":
            # the text between the conversions is the format string's own, with its "%%" still doubled
            s += decode_str(data).replace("%%", "%")
        elif type_ == "string":
            # the padding that rounds a push up to whole bytes can leave more than one NUL behind
            string = decode_str(data)
            if specifier is not None:
                flags, width, precision, _, conversion = specifier.groups()
                if value_type(specifier) == "location:escape_only":
                    # as a JSON string, with the "/" escaped too
                    string = json.dumps(string, ensure_ascii=False).replace("/", "\\/")
                elif conversion == "@" and not string:
                    # a nil object and an empty description are sent alike; nil is by far the commoner
                    string = "(null)"
                elif conversion == "s" and (width or precision) and "*" not in (width, precision):
                    spec = "%" + ("-" if "-" in flags else "") + (width or "")
                    string = (spec + ("." + precision if precision is not None else "") + "s") % string
            s += string
        elif type_ == "private":
            s += "<private>"
        elif type_.startswith("uint64") or "decimal" in type_:
            uint64 = struct.unpack("<Q", data.ljust(8, b"\x00"))[0]
            number = None
            # a pairing that doesn't fit the item's type means the items and conversions are out of step
            if specifier is not None and item_fits(type_, specifier.group(5)):
                number = format_typed_number(uint64, value_type(specifier))
                if number is None:
                    number = format_number(uint64, specifier)
            if number is not None:
                s += number
            elif "hex" in type_:
                s += hex(uint64)[2:]
            else:
                s += str(uint64)
        elif type_ == "uuid":
            if data is not None:
                # the two halves of the uuid, each as a little-endian integer
                halves = join_chunks(cast(list[bytes], data))[:2]
                s += str(uuid.UUID(bytes=b"".join(half[::-1] for half in halves).ljust(16, b"\x00"))).upper()
        elif type_ == "data":
            if data is not None:
                # the first chunk is the length of the rest
                length, *chunks = join_chunks(cast(list[bytes], data))
                raw = b"".join(chunks)[: int.from_bytes(length, "little")]
                if specifier is not None and value_type(specifier) in ("uuid", "uuid_t") and len(raw) == 16:
                    s += str(uuid.UUID(bytes=raw)).upper()
                else:
                    s += raw.hex()
        else:
            # by default, make sure the data can be concatenated
            s += str(data)
    # the device's own rendering of a line ends at its last visible character
    return s.rstrip()


def decode_message_arguments(message: Any) -> list[dict[str, Any]]:
    """
    List the arguments of a row's message, without the narrative text between them.

    :param message: The row's `message` column, as for `decode_message_format`.
    :returns: One `{"type": ..., "value": ...}` per argument, in the order of the format string's conversions.
        `type` is the device's name for it. `value` is a str for a string, an int for an integer or address
        (unsigned 64-bit, whatever the conversion's signedness), a float for a decimal ("nan", "inf" or
        "-inf" when it isn't finite), a hex str for data, a hyphenated str for a uuid and None for a private or
        missing one.
    """
    arguments: list[dict[str, Any]] = []
    for type_, data in message or ():
        type_ = decode_str(type_)
        if type_ == "narrative-text":
            continue
        value: Any
        if data is None or type_ == "private":
            value = None
        elif type_ == "string":
            value = decode_str(data)
        elif type_ == "uuid":
            halves = join_chunks(cast(list[bytes], data))[:2]
            value = str(uuid.UUID(bytes=b"".join(half[::-1] for half in halves).ljust(16, b"\x00")))
        elif type_ == "data":
            length, *chunks = join_chunks(cast(list[bytes], data))
            value = b"".join(chunks)[: int.from_bytes(length, "little")].hex()
        elif not isinstance(data, bytes):
            value = str(data)
        elif "decimal" in type_:
            value = struct.unpack("<d", data[:8].ljust(8, b"\x00"))[0]
            if not math.isfinite(value):
                # not a JSON number
                value = str(value)
        else:
            # uint64 and its hex variants, address, errno-value, ...
            value = int.from_bytes(data[:8], "little")
        arguments.append({"type": type_, "value": value})
    return arguments


class ActivityTraceTap(Tap):
    """
    Tap the device's unified-logging / activity-trace stream over the Instruments channel.

    Constructed with a `DvtProvider`. It is an async-iterable `Tap`: iterating yields decoded
    log entries (signposts and os_log messages) as `message` dataclass instances whose fields
    follow the table columns advertised by the device, plus `device_time`: the row's `time` on the
    device's clock as a `datetime`, or None if the device has not sent its time mapping (it does so
    before the first row). The underlying wire format is a stack-based opcode stream parsed
    incrementally; opcodes split across DTX frames are carried over and reassembled.
    """

    IDENTIFIER = "com.apple.instruments.server.services.activitytracetap"

    def __init__(self, dvt: DtxServiceProvider, enable_http_archive_logging: bool = False):
        """
        :param dvt: The `DvtProvider` used to open the Instruments channel.
        :param enable_http_archive_logging: When True, request that the device also include HTTP
            archive (HAR) logging in the stream.
        """
        # TODO:
        #   reverse: [DTOSLogLoader _handleRecord:], DTTableRowEncoder::*
        #   to understand each row's structure.

        config: dict[str, Any] = {
            "bm": 0,  # buffer mode
            "combineDataScope": 0,
            "machTimebaseDenom": 3,
            "machTimebaseNumer": 125,
            "onlySignposts": 0,
            "pidToInjectCombineDYLIB": "-1",
            "predicate": "(messageType == info OR messageType == debug OR messageType == default OR "
            "messageType == error OR messageType == fault)",
            "signpostsAndLogs": 1,
            "trackPidToExecNameMapping": True,
            "enableHTTPArchiveLogging": enable_http_archive_logging,
            "targetPID": -3,  # all Process
            "trackExpiredPIDs": 1,
            "ur": 500,
        }

        super().__init__(dvt, self.IDENTIFIER, config)

        self.stack: list[Any] = []
        self.generation = 0
        self.background = 0
        self.tables: list[Table] = []
        # trailing bytes of an opcode that was split across two DTX frames
        self._carry = b""
        # the device's wall clock at one mach continuous time, from the "Time Mapping" notice
        self._time_mapping: Optional[tuple[int, float, int, int]] = None

    async def _get_next_message(self):
        message = b""
        while message.startswith(b"bplist") or len(message) == 0:
            # skip heartbeats, but keep the time mapping to stamp the rows with
            message = await self.channel.receive_message()
            if message.startswith(b"bplist"):
                self._time_mapping = _parse_time_mapping(message) or self._time_mapping
        # an opcode (and its immediate words) may be split across frames; prepend the leftover
        self._set_current_message(self._carry + message)
        self._carry = b""

    def _device_time(self, mach_continuous_time: Any) -> Optional[datetime]:
        if self._time_mapping is None or not isinstance(mach_continuous_time, bytes):
            return None
        continuous, since1970, numerator, denominator = self._time_mapping
        try:
            seconds = (int.from_bytes(mach_continuous_time, "little") - continuous) * numerator / denominator / 1e9
            return datetime.fromtimestamp(since1970 + seconds)
        except (OverflowError, OSError, ValueError):
            return None

    def _set_current_message(self, message: bytes):
        self._message = BytesIO(message)

    def _seek_relative(self, offset: int):
        self._message.seek(offset, os.SEEK_CUR)

    def _read_word(self) -> int:
        buf = self._message.read(2)
        if len(buf) != 2:
            raise EOFError()
        (word,) = struct.unpack("<H", buf)
        return word

    def _handle_push(self, word: int):
        assert word >> 14 in (0b10, 0b11), f"invalid magic for pushed item. word: {hex(word)}"

        count = 0
        imm = 0
        bit_count = 0
        while word >> 14 != 0b11:
            # not end word
            imm = (imm << 14) | (word & 0x3FFF)
            word = self._read_word()
            count += 1
            bit_count += 14

        imm = (imm << 14) | (word & 0x3FFF)
        bit_count += 14

        imm <<= 8 - bit_count % 8
        bit_count += 8 - bit_count % 8

        result = imm.to_bytes(math.ceil(bit_count / 8), "big")
        self.stack.append(result)

        return result

    def _handle_table_reset(self, word: int):
        """start new table vector"""
        self.generation += 1
        self.background = 0
        self.stack = []

    def _handle_sentinel(self, word: int):
        """push a dummy"""
        self.stack.append(None)

    def _handle_struct(self, word: int):
        """replace last `distance` items with a single one which represents them as a tuple"""
        distance = word & 0xFF

        if distance == 0xFF:
            raise NotImplementedError("long struct")

        new_item = self.stack[-distance:]

        del self.stack[-distance:]
        self.stack.append(new_item)

    def _handle_define_table(self, word: int):
        """define a table struct"""
        distance = 4

        table_raw = Table(*self.stack[-distance:])
        table = Table(
            # the raw table fields hold the undecoded bytes off the stack
            name=cast(bytes, table_raw.name).split(b"\x00", 1)[0].decode(),
            columns=[c.split(b"\x00", 1)[0].decode() for c in table_raw.columns],
            unknown0=table_raw.unknown0,
            unknown2=table_raw.unknown2,
        )
        # only the tables with a message are yielded; the rest are signpost intervals
        if "message" in table.columns:
            table.row_class = dataclasses.make_dataclass(
                "message",
                [c.replace("-", "_") for c in table.columns]
                + [("device_time", Optional[datetime], dataclasses.field(default=None))],
            )

        del self.stack[-distance:]
        self.tables.append(table)

    def _handle_debug(self, word: int):
        """pop last pushed item from stack"""
        debug_id = word & 0xFF
        item = self.stack[-1]

        reference = int.from_bytes(item, byteorder="little")

        assert reference == len(self.stack) - 1, (
            f"assert debug {debug_id} got reference: {hex(reference)} instead of: {len(self.stack) - 1}  {item}"
        )
        del self.stack[-1]

    def _handle_copy(self, word: int):
        """copy item at distance from stack"""
        distance = word & 0xFF
        if distance != 0xFF:
            item = self.stack[-distance - 1]
            self.stack.append(item)
        else:
            # long struct - pop distance from stack
            item = self.stack[-1]
            reference = int.from_bytes(item, byteorder="little") - 1
            del self.stack[-1]
            self.stack.append(self.stack[reference])

    def _handle_end_row(self, word: int):
        """flush current row"""
        generation = word & 0xFF
        table = self.tables[generation]
        row = self.stack[-len(table.columns) :]
        del self.stack[-len(table.columns) :]

        if table.row_class is None:
            return None
        message = table.row_class(*row)
        # a pushed value loses its trailing zero bits and comes back padded to whole bytes, so an integer
        # is 2 to 9 bytes long (a thread id of 0x1000000 or more decodes to 6 bytes or more)
        message.process = 0 if message.process is None else int.from_bytes(message.process[0], "little")
        message.thread = int.from_bytes(message.thread[0], "little")

        string_fields = (
            "message_type",
            "format_string",
            "subsystem",
            "category",
            "sender_image_path",
            "event_type",
            "name",
        )
        for f in string_fields:
            if hasattr(message, f):
                v = getattr(message, f)
                setattr(message, f, decode_str(v) if v else v)

        message.device_time = self._device_time(message.time)
        return message

    def _handle_placeholder_count(self, word: int):
        """remove `count` last items from stack"""
        count = word & 0xFF
        if count > 0:
            del self.stack[-count:]

    def _handle_convert_mach_continuous(self, word: int):
        """push an item and pop it. effectively do nothing"""
        pass

    def _parse(self) -> Generator[Any, None, None]:
        operations: dict[int, Callable[[int], Any]] = {
            CMD_TABLE_RESET: self._handle_table_reset,
            CMD_SENTINEL: self._handle_sentinel,
            CMD_STRUCT: self._handle_struct,
            CMD_DEFINE_TABLE: self._handle_define_table,
            CMD_DEBUG: self._handle_debug,
            CMD_COPY: self._handle_copy,
            CMD_END_ROW: self._handle_end_row,
            CMD_PLACEHOLDER_COUNT: self._handle_placeholder_count,
            CMD_CONVERT_MACH_CONTINUOUS: self._handle_convert_mach_continuous,
        }

        while True:
            # remember where this opcode begins, in case the frame ends mid-opcode
            start = self._message.tell()
            try:
                word = self._read_word()
                opcode = word >> 8

                if opcode in operations:
                    result = operations[opcode](word)
                else:
                    self._handle_push(word)
                    result = None
            except EOFError:
                # the frame ended in the middle of an opcode (e.g. a multi-word push);
                # carry the remaining bytes over to the next frame instead of crashing
                self._message.seek(start)
                self._carry = self._message.read()
                break

            if opcode == CMD_END_ROW and result is not None:
                yield result

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        """
        Continuously receive frames and yield the decoded log entries they contain.

        :yields: A dynamically generated `message` dataclass per completed row, with fields named
            after the device-advertised table columns.
        """
        while True:
            await self._get_next_message()
            for message in self._parse():
                yield message
