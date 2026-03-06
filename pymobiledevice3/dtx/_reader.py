"""DTX read-path mixin — fragment I/O, reassembly, and channel dispatch.

Intended to be mixed into :class:`~pymobiledevice3.dtx.connection.DTXConnection`;
all ``self.*`` references are resolved at runtime on the concrete class.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from .message import (
    FRAGMENT_HEADER_MIN_SIZE,
    MAX_BUFFERED_COUNT,
    MAX_BUFFERED_SIZE,
    MAX_FRAGMENT_SIZE,
    MAX_MESSAGE_SIZE,
    MESSAGE_PAYLOAD_HEADER_SIZE,
    DTXFragment,
    DTXFragmenter,
    DTXMessage,
    DTXMessageType,
    DTXProtocolError,
    DTXTransportFlags,
    dtx_fragment_header,
    dtx_payload_header,
    format_dtx_message,
)
from .ns_types import NSError

if TYPE_CHECKING:
    from .channel import DTXChannel


class _DTXReaderMixin:
    """Read-path methods for :class:`DTXConnection`.

    Assumes the owning class provides these instance attributes
    (all initialised in ``DTXConnection.__init__``):

    - ``_reader`` — :class:`asyncio.StreamReader`
    - ``_writer`` — :class:`asyncio.StreamWriter` (for socket fileno in logs)
    - ``_fragmenters`` — ``dict[int, DTXFragmenter]``
    - ``_total_buffered`` — :class:`int` running byte count
    - ``_handshake_done`` — :class:`asyncio.Future`
    - ``_channels`` — ``dict[int, DTXChannel]``
    - ``_pending_replies`` — ``dict[int, asyncio.Future[DTXMessage]]``
    - ``_closed`` — :class:`bool`
    - ``logger`` — :class:`logging.Logger`
    - ``close()`` — coroutine (provided by :class:`DTXConnection`)
    - ``send_reply_error()`` — coroutine (provided by :class:`_DTXSenderMixin`)
    """

    # -- attributes provided by DTXConnection (declared for type checkers) --
    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter
    _fragmenters: dict[int, DTXFragmenter]
    _total_buffered: int
    _handshake_done: asyncio.Future
    _channels: dict[int, DTXChannel]
    _pending_replies: dict[int, asyncio.Future]
    _closed: bool
    logger: logging.Logger

    # ------------------------------------------------------------------
    # Debug logging
    # ------------------------------------------------------------------

    def _log_message(self, direction: str, message: DTXMessage) -> None:
        """Best-effort DEBUG log line for a fully assembled DTXMessage."""
        if not self.logger.isEnabledFor(logging.DEBUG):
            return
        self.logger.debug("%-8s %s", direction, format_dtx_message(message))

    # ------------------------------------------------------------------
    # Fragment reader loop
    # ------------------------------------------------------------------

    async def _process_incoming_fragments(self) -> None:
        """Background task: read fragments until the connection closes or errors."""
        try:
            while True:
                fragment = await self._read_fragment()

                if fragment.count == 1:
                    # Single-fragment message: process immediately.
                    raw = bytearray(fragment.payload)  # type: ignore[arg-type]
                    await self._process_message(raw, fragment)
                    continue

                if fragment.index == 0:
                    # First fragment: validate, pre-allocate, register fragmenter.
                    if len(self._fragmenters) >= MAX_BUFFERED_COUNT:
                        raise DTXProtocolError("Total buffered fragment count exceeds maximum")
                    if fragment.identifier in self._fragmenters:
                        raise DTXProtocolError(f"Duplicate first fragment for message {fragment.identifier}")
                    fragmenter = DTXFragmenter(
                        fragment,
                        self._total_buffered,
                        MAX_MESSAGE_SIZE,
                        MAX_BUFFERED_SIZE,
                    )
                    self._fragmenters[fragment.identifier] = fragmenter
                    self._total_buffered += fragmenter.declared_size
                    continue

                fragmenter = self._fragmenters.get(fragment.identifier)
                if fragmenter is None:
                    raise DTXProtocolError(f"Received non-first fragment for unknown message {fragment.identifier}")
                if fragmenter.add(fragment):
                    del self._fragmenters[fragment.identifier]
                    self._total_buffered -= fragmenter.declared_size
                    raw, meta = fragmenter.assemble()
                    await self._process_message(raw, meta)

        except (asyncio.CancelledError, Exception) as exc:
            if not isinstance(exc, asyncio.CancelledError):
                self.logger.error("DTX reader exiting with error: %s", exc)
            if not self._handshake_done.done():
                if isinstance(exc, asyncio.CancelledError):
                    self._handshake_done.set_exception(
                        ConnectionResetError("DTX reader cancelled before handshake completed")
                    )
                else:
                    self._handshake_done.set_exception(exc)
            await self.close()  # type: ignore[attr-defined]

    async def _read_fragment(self) -> DTXFragment:
        """Read exactly one DTX fragment from the transport stream."""
        header_bytes = await self._reader.readexactly(FRAGMENT_HEADER_MIN_SIZE)
        parsed = dtx_fragment_header.parse(header_bytes)

        if parsed.cb < FRAGMENT_HEADER_MIN_SIZE:
            raise DTXProtocolError(f"Fragment header cb={parsed.cb} is below minimum {FRAGMENT_HEADER_MIN_SIZE}")

        # Skip any extra header bytes beyond the known 32-byte minimum.
        # The frida-core reference implementation does the same (see read_fragment).
        extra = parsed.cb - FRAGMENT_HEADER_MIN_SIZE
        if extra > 0:
            await self._reader.readexactly(extra)

        fragment = DTXFragment(
            index=parsed.index,
            count=parsed.count,
            data_size=parsed.data_size,
            identifier=parsed.identifier,
            conversation_index=parsed.conversation_index,
            channel_code=parsed.channel_code,
            flags=parsed.flags,
        )

        # The first fragment of a multi-fragment message carries no body bytes —
        # data_size encodes the *total assembled size* for pre-allocation only.
        # All other fragments must carry a non-empty body.
        if fragment.count > 1 and fragment.index == 0:
            fragment.payload = None
        else:
            if fragment.data_size == 0:
                raise DTXProtocolError("Empty fragment body is not allowed")
            if fragment.data_size > MAX_FRAGMENT_SIZE:
                raise DTXProtocolError(
                    f"Fragment data_size {fragment.data_size} exceeds MAX_FRAGMENT_SIZE {MAX_FRAGMENT_SIZE}"
                )
            fragment.payload = await self._reader.readexactly(fragment.data_size)

        return fragment

    # ------------------------------------------------------------------
    # Message processing
    # ------------------------------------------------------------------

    async def _process_message(self, raw_message: bytearray, fragment: DTXFragment) -> None:
        """Parse *raw_message* and dispatch it to the appropriate channel or reply waiter."""
        if len(raw_message) < MESSAGE_PAYLOAD_HEADER_SIZE:
            raise DTXProtocolError("Malformed message: too short for payload header")

        mv = memoryview(raw_message)
        pheader = dtx_payload_header.parse(bytes(mv[:MESSAGE_PAYLOAD_HEADER_SIZE]))

        try:
            msg_type = DTXMessageType(pheader.msg_type)
        except ValueError as e:
            if fragment.flags & DTXTransportFlags.EXPECTS_REPLY == DTXTransportFlags.EXPECTS_REPLY:
                err = NSError(
                    1, "DTXMessage", {"NSLocalizedDescription": f"Unrecognized message type: {pheader.msg_type}"}
                )
                await self.send_reply_error(fragment.channel_code, fragment.identifier, err)  # type: ignore[attr-defined]
            raise DTXProtocolError(
                f"Unknown DTXMessageType value: {pheader.msg_type} err:{e} "
                f"(fragment=id:{fragment.identifier} conv:{fragment.conversation_index} ch:{fragment.channel_code})"
            ) from e

        if msg_type == DTXMessageType.COMPRESSED:
            if fragment.flags & DTXTransportFlags.EXPECTS_REPLY == DTXTransportFlags.EXPECTS_REPLY:
                err = NSError(
                    1,
                    "DTXMessage",
                    {"NSLocalizedDescription": "Compressed messages are not supported in this implementation"},
                )
                await self.send_reply_error(fragment.channel_code, fragment.identifier, err)  # type: ignore[attr-defined]
            raise DTXProtocolError(
                f"Received compressed fragment: identifier={fragment.identifier}, "
                f"conversation_index={fragment.conversation_index}, channel_code={fragment.channel_code}"
            )

        aux_size: int = pheader.aux_size
        total_size: int = pheader.total_size
        message_size = len(raw_message)

        if (
            aux_size > message_size
            or total_size > message_size
            or total_size != message_size - MESSAGE_PAYLOAD_HEADER_SIZE
            or aux_size > total_size
        ):
            raise DTXProtocolError(
                f"Malformed message: inconsistent size fields "
                f"(message_size={message_size}, aux_size={aux_size}, total_size={total_size}, "
                f"fragment=id:{fragment.identifier} conv:{fragment.conversation_index} ch:{fragment.channel_code})"
            )

        aux_end = MESSAGE_PAYLOAD_HEADER_SIZE + aux_size
        # Slices share the backing bytearray — no extra copy.
        aux_data = mv[MESSAGE_PAYLOAD_HEADER_SIZE:aux_end]
        payload_data = mv[aux_end : aux_end + (total_size - aux_size)]

        # Apply channel-code sign correction (frida-core dtx.vala, process_message).
        # Server-initiated dispatches (conversation_index == 0) arrive with a negative
        # channel_code on the wire; negate it to recover the registered positive code.
        channel_code = fragment.channel_code
        if fragment.conversation_index % 2 == 0:
            channel_code = -channel_code

        is_notification = fragment.conversation_index == 0

        message = DTXMessage(
            type=msg_type,
            identifier=fragment.identifier,
            conversation_index=fragment.conversation_index,
            channel_code=channel_code,
            transport_flags=DTXTransportFlags(fragment.flags),
            aux_data=aux_data,
            payload_data=payload_data,
        )

        self._log_message("received", message)

        if not is_notification and msg_type in (DTXMessageType.OK, DTXMessageType.OBJECT, DTXMessageType.ERROR):
            # Correlate to a waiting reply future.
            if f := self._pending_replies.get(message.identifier):
                if not f.done():
                    f.set_result(message)
                else:
                    self.logger.debug(
                        "Received duplicate reply message with id %d on channel %d",
                        message.identifier,
                        channel_code,
                    )
            else:
                self.logger.debug(
                    "Received uncorrelated reply message with id %d on channel %d",
                    message.identifier,
                    channel_code,
                )
            return

        channel = self._channels.get(channel_code)
        if channel is None:
            # The channel may not be registered yet: the remote end may have sent
            # messages on a reverse channel (e.g. -1) immediately after requesting
            # it, before our channel-0 handler task had a chance to run
            # _on_channel_request.  Yield once so pending tasks can register it.
            await asyncio.sleep(0)
            channel = self._channels.get(channel_code)
        if channel is None:
            if DTXTransportFlags.EXPECTS_REPLY in message.transport_flags:
                self.logger.warning(
                    "No channel registered for code %d after yield - dropping EXPECTS_REPLY message"
                    " (remote will not receive ACK): %s",
                    channel_code,
                    format_dtx_message(message),
                )
            else:
                self.logger.debug("No channel registered for code %d - dropping message", channel_code)
            return

        channel._enqueue_message(message)
