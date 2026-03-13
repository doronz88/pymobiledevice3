"""DTX read-path mixin — fragment I/O, reassembly, and channel dispatch.

Intended to be mixed into :class:`~pymobiledevice3.dtx.connection.DTXConnection`;
all ``self.*`` references are resolved at runtime on the concrete class.
"""

from __future__ import annotations

import asyncio
import errno
import logging
from typing import TYPE_CHECKING

from pymobiledevice3.exceptions import ConnectionTerminatedError

from .exceptions import DTXProtocolError
from .fragment import DTXFragment
from .fragmenter import DTXFragmenter
from .message import (
    DTXMessage,
    DTXMessageType,
    DTXTransportFlags,
)
from .ns_types import NSError

if TYPE_CHECKING:
    from .channel import DTXChannel

MAX_BUFFERED_COUNT: int = 100
"""Maximum number of in-flight multi-fragment messages buffered simultaneously."""

MAX_BUFFERED_SIZE: int = 30 * 1024 * 1024  # 30 MiB
"""Maximum total bytes buffered across all in-flight multi-fragment messages."""

TERMINATING_ERRNOS = {
    errno.EPIPE,
    errno.ECONNABORTED,
    errno.ECONNRESET,
    errno.ENOTCONN,
    errno.ETIMEDOUT,
}


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
    - ``_schedule_reply_error()`` — schedule an error reply (provided by :class:`_DTXSenderMixin`)
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
        self.logger.debug("%-8s %r", direction, message)

    @staticmethod
    def _normalize_reader_exception(exc: Exception) -> Exception:
        if isinstance(
            exc, (ConnectionTerminatedError, asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError)
        ):
            return ConnectionTerminatedError() if not isinstance(exc, ConnectionTerminatedError) else exc
        if isinstance(exc, TimeoutError):
            normalized = ConnectionTerminatedError()
            normalized.__cause__ = exc
            return normalized
        if isinstance(exc, OSError) and exc.errno in TERMINATING_ERRNOS:
            normalized = ConnectionTerminatedError()
            normalized.__cause__ = exc
            return normalized
        return exc

    # ------------------------------------------------------------------
    # Fragment reader loop
    # ------------------------------------------------------------------

    async def _process_incoming_fragments(self) -> None:
        """Background task: read fragments until the connection closes or errors."""
        try:
            while True:
                fragment = await DTXFragment.read(self._reader)

                if fragment.count == 1:
                    # Single-fragment message: process immediately.
                    await self._process_message(fragment.payload, fragment)
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
            normalized_exc = exc
            if isinstance(exc, Exception):
                normalized_exc = self._normalize_reader_exception(exc)
            if not isinstance(exc, asyncio.CancelledError):
                if isinstance(normalized_exc, ConnectionTerminatedError):
                    self.logger.info("DTX reader exiting: connection terminated")
                else:
                    self.logger.error("DTX reader exiting with error: %s", exc)
            if not self._handshake_done.done():
                if isinstance(exc, asyncio.CancelledError):
                    self._handshake_done.set_exception(
                        ConnectionResetError("DTX reader cancelled before handshake completed")
                    )
                else:
                    self._handshake_done.set_exception(normalized_exc)
            await self.close()  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Message processing
    # ------------------------------------------------------------------

    async def _process_message(self, raw_message: bytearray, fragment: DTXFragment) -> None:
        """Parse *raw_message* and dispatch it to the appropriate channel or reply waiter."""
        # this will riase DTXProtocolError if the message is malformed in any way (including unknown message type)
        message = DTXMessage.parse(fragment, raw_message)

        if message.type == DTXMessageType.COMPRESSED:
            if DTXTransportFlags.EXPECTS_REPLY in fragment.flags:
                err = NSError(
                    1,
                    "DTXMessage",
                    {"NSLocalizedDescription": "Compressed messages are not supported in this implementation"},
                )
                self._schedule_reply_error(  # type: ignore[attr-defined]
                    fragment.channel_code, fragment.identifier, fragment.conversation_index + 1, err
                )
            raise DTXProtocolError(
                f"Received compressed fragment: identifier={fragment.identifier}, "
                f"conversation_index={fragment.conversation_index}, channel_code={fragment.channel_code}"
            )

        self._log_message("received", message)

        is_notification = fragment.conversation_index == 0
        if message.conversation_index % 2 == 0:
            message.channel_code = -message.channel_code

        if not is_notification and message.type in (DTXMessageType.OK, DTXMessageType.OBJECT, DTXMessageType.ERROR):
            # Correlate to a waiting reply future.
            if f := self._pending_replies.get(message.identifier):
                if not f.done():
                    f.set_result(message)
                else:
                    self.logger.debug(
                        "Received duplicate reply message %r",
                        message,
                    )
            else:
                self.logger.debug(
                    "Received uncorrelated reply message %r",
                    message,
                )
            return

        channel = self._channels.get(message.channel_code)
        if channel is None:
            # The channel may not be registered yet: the remote end may have sent
            # messages on a reverse channel (e.g. -1) immediately after requesting
            # it, before our channel-0 handler task had a chance to run
            # _on_channel_request.  Yield once so pending tasks can register it.
            await asyncio.sleep(0)
            channel = self._channels.get(message.channel_code)
        if channel is None:
            self.logger.warning(
                "No channel registered for code %d - dropping message %r", message.channel_code, message
            )
            if DTXTransportFlags.EXPECTS_REPLY in message.transport_flags:
                error = NSError(
                    1,
                    "DTXMessage",
                    {"NSLocalizedDescription": f"No channel registered for code {message.channel_code}"},
                )
                self._schedule_reply_error(  # type: ignore[attr-defined]
                    message.channel_code, message.identifier, message.conversation_index + 1, error
                )
            return

        channel._enqueue_message(message)
