"""DTX wire protocol framing: enums, structs, and messages.

This module contains the core DTX wire format components:

- Protocol constants (magic numbers, size limits).
- :class:`DTXMessageType` and :class:`DTXTransportFlags` enumerations.
- :class:`DTXProtocolError` and :class:`DTXNsError` exception classes.
- Construct ``Struct`` definitions for the fragment header and payload header.
- :class:`DTXMessage` dataclass for a fully assembled message ready for dispatch.
- Construct-based codecs: :data:`_dtx_payload`, :data:`_dtx_aux_args`, :data:`_dtx_message`.

Fragment types (:class:`~.fragment.DTXFragment`, :class:`~.fragment.DTXFragmenter`)
and :data:`~.fragment.MAX_FRAGMENT_SIZE` live in :mod:`.fragment`.
"""

from __future__ import annotations

import logging
import plistlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Optional

from bpylist2 import archiver

from .exceptions import DTXNSCodingError, DTXProtocolError
from .fragment import DTXFragment, DTXTransportFlags
from .message_aux import MessageAux
from .structs import MAX_MESSAGE_SIZE, MESSAGE_PAYLOAD_HEADER_SIZE, DTXMessageType, dtx_fragment_payload_header

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(repr=False)
class DTXMessage:
    """Fully assembled DTX message ready for channel dispatch.

    The ``aux_data`` and ``payload_data`` fields hold the raw wire bytes.
    Use the :attr:`aux` and :attr:`payload` properties to get lazily decoded,
    cached Python objects.  The properties handle decode failures gracefully
    (returning an empty list or ``None`` respectively).
    """

    type: DTXMessageType
    # Both slices may share the same backing bytearray — no extra copy is made.
    aux_data: memoryview = memoryview(b"")
    payload_data: memoryview = memoryview(b"")

    identifier: int = 0
    conversation_index: int = 0
    channel_code: int = 0
    flags: int = 0
    transport_flags: DTXTransportFlags = DTXTransportFlags.NONE

    def __post_init__(self) -> None:
        self._aux_cache: Optional[list] = None
        self._aux_decode_exception: Optional[Exception] = None
        self._payload_decoded: bool = False
        self._payload_decoded_exception: Optional[Exception] = None
        self._payload_cache: Any = None

    @property
    def aux(self) -> Sequence[Any]:
        """Decoded auxiliary arguments (lazy, cached)."""
        if self._aux_cache is None and self._aux_decode_exception is None:
            try:
                self._aux_cache = MessageAux.parse(self.aux_data, {}, "aux_data")
            except Exception as e:
                self._aux_decode_exception = e
        if self._aux_decode_exception is not None:
            raise DTXNSCodingError(
                f"Failed to decode DTX aux args: aux_data={bytes(self.aux_data)!r}"
            ) from self._aux_decode_exception
        if self._aux_cache is None:
            self._aux_cache = []
        return self._aux_cache

    @aux.setter
    def aux(self, args: Sequence[Any] = ()) -> None:
        """Set the auxiliary arguments to *args*, updating the underlying aux_data bytes."""
        buf = b""
        try:
            buf = MessageAux.build(args, {}, "aux")  # validate the args before building the final buffer
        except Exception as e:
            raise DTXNSCodingError(f"Failed to encode DTX aux args object with PrimitiveDictionary: {args!r}") from e
        self.aux_data = memoryview(buf)
        self._aux_cache = args or []
        self._aux_decode_exception = None

    @property
    def payload(self) -> Any:
        """Decoded payload object (lazy, cached)."""
        if len(self.payload_data) and not self._payload_decoded and self._payload_decoded_exception is None:
            try:
                try:
                    self._payload_cache = archiver.unarchive(self.payload_data)
                except Exception as e1:
                    self._payload_cache = plistlib.loads(self.payload_data)
                    logger.warning(
                        f"Failed to decode DTX payload with NSKeyedUnarchiver, but successfully decoded with plistlib: {e1}, decoded value: {self._payload_cache!r}"
                    )
            except Exception as e:
                self._payload_decoded_exception = e.__cause__ or e
            self._payload_decoded = True

        if self._payload_decoded_exception is not None:
            raise DTXNSCodingError(
                f"Failed to decode DTX payload: payload_data={bytes(self.payload_data)!r}"
            ) from self._payload_decoded_exception
        return self._payload_cache

    @payload.setter
    def payload(self, obj: Any) -> None:
        """Set the payload to *obj*, updating the underlying payload_data bytes."""
        self.payload_data = memoryview(b"")
        if obj is not None:
            try:
                self.payload_data = memoryview(archiver.archive(obj))
            except Exception as e:
                raise DTXNSCodingError(f"Failed to encode DTX payload object with NSKeyedArchiver: {obj!r}") from e
        self._payload_cache = obj
        self._payload_decoded = True
        self._payload_decoded_exception = None

    @staticmethod
    def parse(first_fragment: DTXFragment, payload_bytes: bytes) -> DTXMessage:
        """Read a complete DTX message from *stream* using metadata from *fragment*."""
        mv = memoryview(payload_bytes)
        assert first_fragment.data_size == len(mv), (
            f"First fragment of message {first_fragment.identifier} declares data_size {first_fragment.data_size} but payload_bytes has length {len(mv)}"
        )
        if first_fragment.data_size > MAX_MESSAGE_SIZE:
            raise DTXProtocolError(
                f"Fragment {first_fragment.index} of message {first_fragment.identifier} declares data_size {first_fragment.data_size} exceeding MAX_MESSAGE_SIZE {MAX_MESSAGE_SIZE}"
            )
        if first_fragment.data_size < MESSAGE_PAYLOAD_HEADER_SIZE:
            raise DTXProtocolError(
                f"Fragment {first_fragment.index} of message {first_fragment.identifier} declares data_size {first_fragment.data_size} smaller than MESSAGE_PAYLOAD_HEADER_SIZE {MESSAGE_PAYLOAD_HEADER_SIZE}"
            )

        header = dtx_fragment_payload_header.parse(mv[:MESSAGE_PAYLOAD_HEADER_SIZE])
        if header.total_size != first_fragment.data_size - MESSAGE_PAYLOAD_HEADER_SIZE:
            raise DTXProtocolError(
                f"Message {first_fragment.identifier} declares inconsistent sizes: fragment={first_fragment!r}, payload header {header!r}"
            )
        try:
            msg_type = DTXMessageType(header.msg_type)
        except ValueError as e:
            raise DTXProtocolError(f"Unknown DTXMessageType in payload header: {header!r}") from e

        return DTXMessage(
            type=msg_type,
            identifier=first_fragment.identifier,
            conversation_index=first_fragment.conversation_index,
            channel_code=first_fragment.channel_code,
            transport_flags=first_fragment.flags,
            flags=header.flags,
            aux_data=mv[MESSAGE_PAYLOAD_HEADER_SIZE : MESSAGE_PAYLOAD_HEADER_SIZE + header.aux_size],
            payload_data=mv[MESSAGE_PAYLOAD_HEADER_SIZE + header.aux_size :],
        )

    def chunks(self) -> list[memoryview]:
        """Return the raw message bytes as a list of memoryview chunks: [payload_header, aux_data, payload_data]."""
        if self.type not in (
            DTXMessageType.OK,
            DTXMessageType.DATA,
            DTXMessageType.DISPATCH,
            DTXMessageType.OBJECT,
            DTXMessageType.ERROR,
        ):
            raise DTXProtocolError(f"Unsupported message type to serialise: {self.type!r}: {self!r}")

        if self.conversation_index != 0 and self.identifier == 0:
            raise DTXProtocolError(
                f"Reply messages must have a non-zero identifier "
                f"(conversation_index != 0 but identifier == 0): {self!r}",
            )
        if self.conversation_index != 0 and self.type not in (
            DTXMessageType.OK,
            DTXMessageType.OBJECT,
            DTXMessageType.ERROR,
        ):
            raise DTXProtocolError(f"Reply messages must have type OK/OBJECT/ERROR, got {self.type!r}: {self!r}")
        if self.type == DTXMessageType.OK and (len(self.payload_data) > 0 or len(self.aux_data) > 0):
            raise DTXProtocolError(f"OK messages must carry no payload and no aux data: {self!r}")
        if self.type == DTXMessageType.ERROR and len(self.payload_data) == 0:
            raise DTXProtocolError(f"ERROR messages must carry a non-empty payload: {self!r}")
        if self.type == DTXMessageType.ERROR and len(self.aux_data) > 0:
            raise DTXProtocolError(f"ERROR messages must carry no aux data: {self!r}")

        return [
            memoryview(
                dtx_fragment_payload_header.build({
                    "msg_type": int(self.type),
                    "flags_a": 0,
                    "flags_b": 0,
                    "reserved": 0,
                    "aux_size": len(self.aux_data),
                    "total_size": len(self.aux_data) + len(self.payload_data),
                    "flags": int(self.flags),
                })
            ),
            self.aux_data,
            self.payload_data,
        ]

    def __repr__(self) -> str:
        payload = None
        aux: Optional[list] = None

        try:
            payload = self.payload
        except Exception as e:
            payload = f"<failed to decode: {e}>"

        try:
            aux = self.aux
        except Exception as e:
            aux = f"<failed to decode: {e}>"

        e = "e" if DTXTransportFlags.EXPECTS_REPLY in self.transport_flags else ""
        return (
            f"<DTXMessage: i{self.identifier}.{self.conversation_index}{e}"
            f" c{self.channel_code} type:{self.type.name} flags:{self.transport_flags:#x}.{self.flags:#x} payload:{payload} aux:{aux}>"
        )
