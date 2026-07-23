from dataclasses import dataclass
from enum import IntEnum, IntFlag

from construct import Const, Int8ul, Int16ul, Int32sl, Int32ul
from construct_typed import DataclassMixin, DataclassStruct, csfield

try:
    # construct-typing >= 0.8.0 rejects csfield(Const(...)) and requires csfield_const() for const
    # fields. Older versions (0.7.x, the Python 3.9 floor) have no csfield_const (see afc.py).
    from construct_typed import csfield_const  # pyright: ignore[reportAttributeAccessIssue]
except ImportError:  # construct-typing < 0.8.0
    csfield_const = None

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
# construct-typing >= 0.8.0 requires csfield_const() for const fields; 0.7.x (the Python 3.9 floor)
# only has csfield(Const(...)). Pick the form the installed version supports (see afc.py).
_dtx_magic_field = (
    csfield_const(Int32ul, DTX_FRAGMENT_MAGIC)
    if csfield_const is not None
    else csfield(Const(DTX_FRAGMENT_MAGIC, Int32ul))
)


@dataclass
class DtxFragmentHeader(DataclassMixin):
    """Typed DTX fragment (wire) header. ``parse()`` yields typed field access instead of a
    dynamically-typed construct ``Container``.

    csfield_const() returns a ``dataclasses.Field(init=False)`` at runtime, but its 0.8 stub types it
    as the plain value, so pyright can't see the init=False and flags the non-default fields that
    follow — hence the per-field ignores. Field order is the DTX wire format."""

    magic: int = _dtx_magic_field
    header_size: int = csfield(Int32ul)  # pyright: ignore[reportGeneralTypeIssues]  # total header size
    index: int = csfield(Int16ul)  # pyright: ignore[reportGeneralTypeIssues]  # 0-based fragment index
    count: int = csfield(Int16ul)  # pyright: ignore[reportGeneralTypeIssues]  # total fragment count
    data_size: int = csfield(Int32ul)  # pyright: ignore[reportGeneralTypeIssues]  # this fragment's body length
    identifier: int = csfield(Int32ul)  # pyright: ignore[reportGeneralTypeIssues]  # request/response id
    conversation_index: int = csfield(Int32ul)  # pyright: ignore[reportGeneralTypeIssues]  # 0=initiator, 1=reply
    channel_code: int = csfield(Int32sl)  # pyright: ignore[reportGeneralTypeIssues]
    flags: int = csfield(Int32ul)  # pyright: ignore[reportGeneralTypeIssues]  # DTXTransportFlags


dtx_fragment_header = DataclassStruct(DtxFragmentHeader)


# Per-message payload header prepended to aux + payload bytes.
# Layout (16 bytes, all little-endian):
#   offset 0  : DTXMessageType  (uint8)
#   offset 1-3: reserved zeros
#   offset 4-7: aux_size  (uint32)
#   offset 8-11: total_size (uint32) = aux_size + payload_size
#   offset 12-15: flags (uint32) - currently unused
@dataclass
class DtxFragmentPayloadHeader(DataclassMixin):
    """Typed DTX per-message payload header (16 bytes)."""

    msg_type: int = csfield(Int8ul)
    flags_a: int = csfield(Int8ul)
    flags_b: int = csfield(Int8ul)
    reserved: int = csfield(Int8ul)
    aux_size: int = csfield(Int32ul)
    total_size: int = csfield(Int32ul)
    flags: int = csfield(Int32ul)


dtx_fragment_payload_header = DataclassStruct(DtxFragmentPayloadHeader)


FRAGMENT_HEADER_MIN_SIZE: int = dtx_fragment_header.sizeof()  # 32
"""Minimum byte length of a DTX fragment header."""

FRAGMENT_PAYLOAD_HEADER_SIZE: int = dtx_fragment_payload_header.sizeof()  # 16
"""Byte length of the DTX per-message payload header."""
