"""DTX wire protocol framing: enums, structs, fragments and messages.

This module contains everything needed to parse and build the binary DTX
wire format:

- Protocol constants (magic numbers, size limits).
- :class:`DTXMessageType` and :class:`DTXTransportFlags` enumerations.
- :class:`DTXProtocolError` and :class:`DTXNsError` exception classes.
- Construct ``Struct`` definitions for the fragment header and payload header.
- :class:`DTXFragment` dataclass for one raw fragment.
- :class:`DTXFragmenter` for reassembling multi-fragment messages.
- :class:`DTXMessage` dataclass for a fully assembled message ready for dispatch.
"""

from __future__ import annotations

import logging
from contextlib import suppress
from dataclasses import dataclass
from enum import IntEnum, IntFlag

from bpylist2 import archiver
from construct import (
    Const,
    Int8ul,
    Int16ul,
    Int32sl,
    Int32ul,
    Int64ul,
    Struct,
)

from pymobiledevice3.exceptions import DvtException

from .ns_types import NSError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

DTX_FRAGMENT_MAGIC: int = 0x1F3D5B79
"""Magic number that starts every DTX fragment header."""

FRAGMENT_HEADER_MIN_SIZE: int = 32
"""Minimum byte length of a DTX fragment header."""

MESSAGE_PAYLOAD_HEADER_SIZE: int = 16
"""Byte length of the per-message payload header that precedes aux + payload bytes."""

MAX_BUFFERED_COUNT: int = 100
"""Maximum number of in-flight multi-fragment messages buffered simultaneously."""

MAX_BUFFERED_SIZE: int = 30 * 1024 * 1024  # 30 MiB
"""Maximum total bytes buffered across all in-flight multi-fragment messages."""

MAX_MESSAGE_SIZE: int = 128 * 1024 * 1024  # 128 MiB
"""Maximum byte size of any single assembled DTX message."""

MAX_FRAGMENT_SIZE: int = 128 * 1024  # 128 KiB
"""Maximum byte size of a single DTX fragment body."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


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


class DTXTransportFlags(IntFlag):
    """Bit flags carried in the DTX fragment header ``flags`` field."""

    NONE = 0
    EXPECTS_REPLY = 1 << 0


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class DTXProtocolError(DvtException):
    """Raised when the remote DTX stream violates the protocol invariants."""


class DTXNsError(DvtException):
    """Raised when the remote service returns an NSError object."""

    def __init__(self, error: NSError) -> None:
        self.error = error
        super().__init__(f"{error.domain} (code {error.code}, user_info={error.user_info})")


# ---------------------------------------------------------------------------
# Construct structs
# ---------------------------------------------------------------------------

# Fragment (wire) header - minimum 32 bytes; ``cb`` may indicate more.
dtx_fragment_header = Struct(
    "magic" / Const(DTX_FRAGMENT_MAGIC, Int32ul),
    "cb" / Int32ul,  # total header size; skip (cb - 32) extra bytes after parsing
    "index" / Int16ul,  # 0-based fragment index within this message
    "count" / Int16ul,  # total number of fragments for this message
    "data_size" / Int32ul,  # byte length of this fragment's body
    "identifier" / Int32ul,  # message identifier (matches request to response)
    "conversation_index" / Int32ul,  # 0 = initiator, 1 = reply, higher = subsequent
    "channel_code" / Int32sl,
    "flags" / Int32ul,  # DTXTransportFlags
)

# Per-message payload header prepended to aux + payload bytes.
# Layout (16 bytes, all little-endian):
#   offset 0  : DTXMessageType  (uint8)
#   offset 1-3: reserved zeros
#   offset 4-7: aux_size  (uint32)
#   offset 8-15: total_size (uint64) = aux_size + payload_size
dtx_payload_header = Struct(
    "msg_type" / Int8ul,
    "flags_a" / Int8ul,
    "flags_b" / Int8ul,
    "reserved" / Int8ul,
    "aux_size" / Int32ul,
    "total_size" / Int64ul,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DTXFragment:
    """Metadata and optional body for one DTX protocol fragment."""

    index: int
    count: int
    data_size: int  # total assembled message size (first fragment) or own body size
    identifier: int = 0
    conversation_index: int = 0
    channel_code: int = 0
    flags: int = DTXTransportFlags.NONE
    payload: bytes | None = None  # None for the first fragment of a multi-fragment message


class DTXFragmenter:
    """Accumulates the non-first fragments of a multi-fragment DTX message.

    The first fragment (index=0, count>1) declares the *total* assembled payload
    size in its ``data_size`` header field but carries no body bytes.  We use
    that value to pre-allocate a single :class:`bytearray` of the right size.

    Each subsequent fragment's payload is written directly into the buffer at
    the current write offset as soon as it arrives — no DTXFragment references
    are retained, only a lightweight ``(fragment_index, buf_offset, length)``
    tuple is stored per fragment.

    Assembly is zero-copy in the common case (fragments arrive in index order):
    the pre-allocated buffer is returned as-is.  If fragments arrive out of
    order (rare), a debug message is logged and a single sorted copy is made.
    After :meth:`assemble` the fragmenter releases all internal state eagerly so
    memory can be reclaimed as soon as the caller drops its reference.

    Memory-limit checks happen at construction time (before any allocation), so
    the connection can reject oversized messages before committing memory.

    Usage::

        fragmenter = DTXFragmenter(first_fragment, total_buffered, MAX_MESSAGE_SIZE, MAX_BUFFERED_SIZE)
        total_buffered += fragmenter.declared_size

        if fragmenter.add(next_fragment):
            raw, meta = fragmenter.assemble()
            total_buffered -= fragmenter.declared_size
            await _process_message(raw, meta)
            # caller must drop 'fragmenter' here; assemble() already cleared internals
    """

    def __init__(
        self,
        first_fragment: DTXFragment,
        current_buffered: int,
        max_message_size: int,
        max_buffered_size: int,
    ) -> None:
        total = first_fragment.data_size
        if total == 0:
            raise DTXProtocolError(
                f"Multi-fragment message {first_fragment.identifier} has data_size=0 "
                f"in the first fragment; cannot pre-allocate assembly buffer"
            )
        if total > max_message_size:
            raise DTXProtocolError(
                f"Multi-fragment message {first_fragment.identifier} declares total size "
                f"{total} which exceeds MAX_MESSAGE_SIZE {max_message_size}"
            )
        if current_buffered + total > max_buffered_size:
            raise DTXProtocolError(
                f"Pre-allocating {total} bytes for message {first_fragment.identifier} "
                f"would exceed MAX_BUFFERED_SIZE {max_buffered_size}"
            )

        self._first = first_fragment
        self._expected_count: int = first_fragment.count - 1  # body fragments only
        self._buffer = bytearray(total)
        self._write_offset: int = 0
        # (fragment_index, buf_offset, length) — payload bytes are NOT held here
        self._slots: list[tuple[int, int, int]] = []
        self._seen_indices: set[int] = set()

    # ------------------------------------------------------------------

    @property
    def identifier(self) -> int:
        """Message identifier taken from the first fragment."""
        return self._first.identifier

    @property
    def declared_size(self) -> int:
        """Total payload bytes as declared by the first fragment."""
        return len(self._buffer)

    def add(self, fragment: DTXFragment) -> bool:
        """Write *fragment*'s payload into the buffer immediately, store a slot.

        Raises :class:`DTXProtocolError` on duplicate index or missing payload.
        Returns *True* when all body fragments have arrived and
        :meth:`assemble` can be called.
        """
        if fragment.payload is None:
            raise DTXProtocolError(
                f"Non-first fragment {fragment.index} of message {self._first.identifier} has no payload"
            )
        if fragment.index in self._seen_indices:
            raise DTXProtocolError(f"Duplicate fragment index {fragment.index} for message {self._first.identifier}")
        n = len(fragment.payload)
        if self._write_offset + n > len(self._buffer):
            raise DTXProtocolError(
                f"Fragment {fragment.index} of message {self._first.identifier} would write "
                f"{self._write_offset + n} bytes total, exceeding declared size {len(self._buffer)}"
            )
        self._buffer[self._write_offset : self._write_offset + n] = fragment.payload
        self._slots.append((fragment.index, self._write_offset, n))
        self._write_offset += n
        self._seen_indices.add(fragment.index)
        return len(self._slots) == self._expected_count

    def assemble(self) -> tuple[bytearray, DTXFragment]:
        """Return the assembled buffer and the metadata from the first fragment.

        **Zero-copy fast path** (99 % of the time): if fragments arrived in
        index order the pre-allocated buffer already holds the correct layout
        and is returned directly.

        **Out-of-order slow path**: a debug message is logged and the payload
        chunks are copied in sorted order into a fresh bytearray.

        After returning, all internal state is cleared so memory can be
        reclaimed as soon as the caller drops its reference to this object.

        Raises :class:`DTXProtocolError` if written bytes ≠ declared size.
        """
        arrived_indices = [s[0] for s in self._slots]
        sorted_slots = sorted(self._slots, key=lambda s: s[0])
        sorted_indices = [s[0] for s in sorted_slots]

        if arrived_indices == sorted_indices:
            result = self._buffer
        else:
            logger.debug(
                "Message %d: fragments arrived out of order %s, reordering into fresh buffer",
                self._first.identifier,
                arrived_indices,
            )
            result = bytearray(len(self._buffer))
            write_pos = 0
            for _, src_offset, length in sorted_slots:
                result[write_pos : write_pos + length] = self._buffer[src_offset : src_offset + length]
                write_pos += length
            if write_pos != len(result):
                raise DTXProtocolError(
                    f"Assembled {write_pos} bytes but first fragment declared "
                    f"{len(result)} for message {self._first.identifier}"
                )

        meta = self._first
        # Release internals eagerly — caller will drop this object right after.
        self._buffer = bytearray()
        self._slots = []
        self._seen_indices = set()
        return result, meta


@dataclass
class DTXMessage:
    """Fully assembled DTX message ready for channel dispatch."""

    type: DTXMessageType
    # Both slices share the same backing bytearray - no extra copy is made.
    aux_data: memoryview
    payload_data: memoryview

    identifier: int = 0
    conversation_index: int = 0
    channel_code: int = 0
    transport_flags: DTXTransportFlags = DTXTransportFlags.NONE


def format_dtx_message(message: DTXMessage) -> str:
    """Return a human-readable one-line representation of *message*.

    Payload and aux are decoded best-effort; raw bytes are shown on failure.
    This is used for both the reader DEBUG log and channel WARNING logs.
    """
    payload = None
    aux = None
    with suppress(Exception):
        if message.payload_data:
            payload = archiver.unarchive(bytes(message.payload_data))
    with suppress(Exception):
        if message.aux_data:
            from .primitives import parse_aux  # local import avoids module-level cycle risk

            aux = parse_aux(message.aux_data)
    e = "e" if DTXTransportFlags.EXPECTS_REPLY in message.transport_flags else ""
    return (
        f"<DTXMessage: i{message.identifier}.{message.conversation_index}{e}"
        f" c{message.channel_code} type:{message.type.name} payload:{payload} aux:{aux}>"
    )
