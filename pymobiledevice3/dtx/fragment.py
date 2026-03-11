"""DTX fragment types and multi-fragment message assembler.

Separated from :mod:`.message` to keep that module focused on the wire codec
and :class:`~.message.DTXMessage` itself.

The public surface intentionally mirrors what ``message.py`` exported before
the split, so callers can update imports without behavioural changes.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from .exceptions import DTXProtocolError
from .structs import (
    DTX_FRAGMENT_MAGIC,
    FRAGMENT_HEADER_MIN_SIZE,
    FRAGMENT_PAYLOAD_HEADER_SIZE,
    MAX_MESSAGE_SIZE,
    DTXTransportFlags,
    dtx_fragment_header,
)

logger = logging.getLogger(__name__)


@dataclass(repr=False)
class DTXFragment:
    """Metadata and optional body for one DTX protocol fragment."""

    index: int
    count: int
    data_size: int  # total assembled message size (first fragment) or own body size
    identifier: int = 0
    conversation_index: int = 0
    channel_code: int = 0
    flags: DTXTransportFlags = DTXTransportFlags.NONE
    payload: memoryview = memoryview(b"")

    @staticmethod
    async def read(stream: asyncio.StreamReader) -> DTXFragment:
        """Parse a DTX fragment from *stream* and return a DTXFragment object."""
        header = dtx_fragment_header.parse(await stream.readexactly(FRAGMENT_HEADER_MIN_SIZE))

        if header.index >= header.count:
            raise DTXProtocolError(
                f"Fragment {header.index} of message {header.identifier} has index >= count ({header.count})"
            )
        if header.data_size > MAX_MESSAGE_SIZE + FRAGMENT_PAYLOAD_HEADER_SIZE * header.count:
            raise DTXProtocolError(
                f"Fragment {header.index}/{header.count} of message {header.identifier} declares data_size "
                f"{header.data_size} which exceeds MAX_MESSAGE_SIZE {MAX_MESSAGE_SIZE}"
            )
        if header.data_size == 0:
            raise DTXProtocolError(f"Fragment {header.index} of message {header.identifier} is empty")

        try:
            parsed_flags = DTXTransportFlags(header.flags)
        except ValueError:
            raise DTXProtocolError(
                f"Fragment {header.index} of message {header.identifier} has invalid flags {header.flags:#x}"
            ) from None

        if header.header_size > FRAGMENT_HEADER_MIN_SIZE:
            await stream.readexactly(header.header_size - FRAGMENT_HEADER_MIN_SIZE)  # skip extra header bytes if any

        if header.index == 0 and header.count > 1:
            # first fragments of multi-fragment messages carry no body bytes; data_size encodes the total assembled size for pre-allocation only
            payload = memoryview(b"")
        else:
            payload = memoryview(await stream.readexactly(header.data_size))

        return DTXFragment(
            index=header.index,
            count=header.count,
            data_size=header.data_size,
            identifier=header.identifier,
            conversation_index=header.conversation_index,
            channel_code=header.channel_code,
            flags=parsed_flags,
            payload=payload,
        )

    def chunks(self) -> list[memoryview]:
        """Return a list of memoryview chunks that make up this fragment for sending."""
        return [
            memoryview(
                dtx_fragment_header.build({
                    "magic": DTX_FRAGMENT_MAGIC,
                    "header_size": FRAGMENT_HEADER_MIN_SIZE,
                    "index": self.index,
                    "count": self.count,
                    "data_size": self.data_size,
                    "identifier": self.identifier,
                    "conversation_index": self.conversation_index,
                    "channel_code": self.channel_code,
                    "flags": int(self.flags),
                })
            ),
            self.payload,
        ]

    def __repr__(self) -> str:
        return (
            f"<DTXFragment: i{self.identifier}.{self.conversation_index} c{self.channel_code} "
            f"index={self.index}/{self.count} flags={self.flags:#x} data_size={self.data_size}>"
        )
