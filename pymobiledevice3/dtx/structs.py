from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Annotated

from bytestruct import BinaryStruct, Const, i32, u8, u16, u32

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
# Wire structs
# ---------------------------------------------------------------------------


# Fragment (wire) header - minimum 32 bytes; ``header_size`` may indicate more.
@dataclass
class DtxFragmentHeader(BinaryStruct, byte_order="<"):
    """DTX fragment (wire) header. Field order is the DTX wire format."""

    magic: Annotated[u32, Const(DTX_FRAGMENT_MAGIC)] = field(default=DTX_FRAGMENT_MAGIC, init=False)
    header_size: u32  # total header size
    index: u16  # 0-based fragment index
    count: u16  # total fragment count
    data_size: u32  # this fragment's body length
    identifier: u32  # request/response id
    conversation_index: u32  # 0=initiator, 1=reply
    channel_code: i32
    flags: u32  # DTXTransportFlags


# Per-message payload header prepended to aux + payload bytes.
@dataclass
class DtxFragmentPayloadHeader(BinaryStruct, byte_order="<"):
    """DTX per-message payload header (16 bytes)."""

    msg_type: u8  # DTXMessageType
    flags_a: u8
    flags_b: u8
    reserved: u8
    aux_size: u32
    total_size: u32  # aux_size + payload_size
    flags: u32  # currently unused


FRAGMENT_HEADER_MIN_SIZE: int = DtxFragmentHeader.SIZE  # 32
"""Minimum byte length of a DTX fragment header."""

FRAGMENT_PAYLOAD_HEADER_SIZE: int = DtxFragmentPayloadHeader.SIZE  # 16
"""Byte length of the DTX per-message payload header."""
