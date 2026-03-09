from enum import IntEnum, IntFlag

from construct import Const, Int8ul, Int16ul, Int32sl, Int32ul, Struct

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

MAX_MESSAGE_SIZE: int = 128 * 1024 * 1024  # 128 MiB
"""Maximum byte size of any single assembled DTX message."""

MAX_FRAGMENT_SIZE: int = 128 * 1024  # 128 KiB
"""Maximum byte size of a single DTX fragment body (and thus every fragment read)."""

DTX_FRAGMENT_MAGIC: int = 0x1F3D5B79
"""Magic number that starts every DTX fragment header."""

MESSAGE_PAYLOAD_HEADER_SIZE: int = 16
"""Byte length of the per-message payload header that precedes aux + payload bytes."""

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DTXTransportFlags(IntFlag):
    """Bit flags carried in the DTX fragment header ``flags`` field."""

    NONE = 0
    EXPECTS_REPLY = 1 << 0


class DTXMessageType(IntEnum):
    """Numeric type codes used in the DTX payload header ``msg_type`` field."""

    OK = 0
    DATA = 1
    DISPATCH = 2
    OBJECT = 3
    ERROR = 4
    BARRIER = 5
    PRIMITIVE = 6
    COMPRESSED = 7
    PROXIED_MESSAGE = 8


# ---------------------------------------------------------------------------
# Construct structs
# ---------------------------------------------------------------------------

# Fragment (wire) header - minimum 32 bytes; ``header_size`` may indicate more.
dtx_fragment_header = Struct(
    "magic" / Const(DTX_FRAGMENT_MAGIC, Int32ul),
    "header_size" / Int32ul,  # total header size; skip (header_size - 32) extra bytes after parsing
    "index" / Int16ul,  # 0-based fragment index within this message
    "count" / Int16ul,  # total number of fragments for this message
    "data_size" / Int32ul,  # byte length of this fragment's body
    "identifier" / Int32ul,  # message identifier (matches request to response)
    "conversation_index" / Int32ul,  # 0 = initiator, 1 = reply, higher = subsequent
    "channel_code" / Int32sl,
    "flags" / Int32ul,  # DTXTransportFlags
    # with asynchronous reads we can read the fixed-size part first, then skip any extra header bytes before reading the body
    # "extra" / Bytes(lambda ctx: ctx.header_size - FRAGMENT_HEADER_MIN_SIZE),  # optional extra header bytes
)

# Per-message payload header prepended to aux + payload bytes.
# Layout (16 bytes, all little-endian):
#   offset 0  : DTXMessageType  (uint8)
#   offset 1-3: reserved zeros
#   offset 4-7: aux_size  (uint32)
#   offset 8-11: total_size (uint32) = aux_size + payload_size
#   offset 12-15: flags (uint32) - currently unused
dtx_fragment_payload_header = Struct(
    "msg_type" / Int8ul,
    "flags_a" / Int8ul,
    "flags_b" / Int8ul,
    "reserved" / Int8ul,
    "aux_size" / Int32ul,
    "total_size" / Int32ul,
    "flags" / Int32ul,
)


FRAGMENT_HEADER_MIN_SIZE: int = dtx_fragment_header.sizeof()  # 32
"""Minimum byte length of a DTX fragment header."""

FRAGMENT_PAYLOAD_HEADER_SIZE: int = dtx_fragment_payload_header.sizeof()  # 16
"""Byte length of the DTX per-message payload header."""
