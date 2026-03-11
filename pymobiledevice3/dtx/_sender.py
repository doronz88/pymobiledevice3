"""DTX send-path mixin — serialises outgoing messages and tracks pending replies.

Intended to be mixed into :class:`~pymobiledevice3.dtx.connection.DTXConnection`;
all ``self.*`` references are resolved at runtime on the concrete class.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from typing import Any

from pymobiledevice3.exceptions import ConnectionTerminatedError

from .exceptions import DTXProtocolError
from .fragment import DTXTransportFlags
from .fragmenter import DTXFragmenter
from .message import (
    DTXMessage,
    DTXMessageType,
)
from .ns_types import NSError


class _DTXSenderMixin:
    """Send-path methods for :class:`DTXConnection`.

    Assumes the owning class provides these instance attributes
    (all initialised in ``DTXConnection.__init__``):

    - ``_writer`` — :class:`asyncio.StreamWriter`
    - ``_send_lock`` — :class:`asyncio.Lock` serialising frame writes
    - ``_next_msg_id`` — :class:`int` counter for outgoing message IDs
    - ``_pending_replies`` — ``dict[int, asyncio.Future[DTXMessage]]``
    - ``logger`` — :class:`logging.Logger`
    - ``_log_message`` — callable (provided by :class:`_DTXReaderMixin`)
    """

    # -- attributes provided by DTXConnection (declared for type checkers) --
    _writer: asyncio.StreamWriter
    _send_lock: asyncio.Lock
    _next_msg_id: int
    _pending_replies: dict[int, asyncio.Future]
    _pending_outgoing_replies: list[asyncio.Future]
    _closed: bool
    logger: logging.Logger

    # ------------------------------------------------------------------
    # Low-level frame serialisation
    # ------------------------------------------------------------------

    async def _send_message(self, message: DTXMessage) -> None:
        """Serialise and write *message* to the transport as a single fragment."""
        if self._closed:
            raise ConnectionTerminatedError("Cannot send message: connection is closed")

        async with self._send_lock:
            if message.identifier == 0:
                message.identifier = self._next_msg_id
                self._next_msg_id += 1

            wire_code = message.channel_code if message.conversation_index % 2 == 0 else -message.channel_code

            if DTXTransportFlags.EXPECTS_REPLY in message.transport_flags:
                future: asyncio.Future = asyncio.get_running_loop().create_future()
                self._pending_replies[message.identifier] = future
            try:
                async for fragment in DTXFragmenter.fragment(*message.chunks()):
                    fragment.identifier = message.identifier
                    fragment.conversation_index = message.conversation_index
                    fragment.channel_code = wire_code
                    fragment.flags = message.transport_flags

                    for chunk in fragment.chunks():
                        self._writer.write(chunk)
            except Exception as e:
                self._pending_replies.pop(message.identifier, None)
                raise DTXProtocolError(f"Failed to serialise DTXMessage: {e}") from e
            try:
                await self._writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                self._pending_replies.pop(message.identifier, None)
                raise ConnectionTerminatedError("Connection lost while sending") from e

            self._log_message("sent", message)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Outgoing message helpers
    # ------------------------------------------------------------------

    async def send_notification(
        self,
        channel_code: int,
        payload: Any,
        aux_args: Sequence[Any] = (),
        expects_reply: bool = False,
    ) -> int:
        """Send an OBJECT (or ERROR) notification on *channel_code*.

        Returns the assigned message identifier.
        """
        assert payload is not None, "Notifications must have a payload"

        msg = DTXMessage(
            type=DTXMessageType.ERROR if isinstance(payload, NSError) else DTXMessageType.OBJECT,
            channel_code=channel_code,
            transport_flags=DTXTransportFlags.EXPECTS_REPLY if expects_reply else DTXTransportFlags.NONE,
        )
        msg.payload = payload
        msg.aux = aux_args
        await self._send_message(msg)
        return msg.identifier

    async def send_data(
        self,
        channel_code: int,
        data: bytes,
        aux_args: Sequence[Any] = (),
        expects_reply: bool = False,
    ) -> int:
        """Send a DATA frame with opaque *data* bytes on *channel_code*.

        Returns the assigned message identifier.
        """
        msg = DTXMessage(
            type=DTXMessageType.DATA,
            channel_code=channel_code,
            transport_flags=DTXTransportFlags.EXPECTS_REPLY if expects_reply else DTXTransportFlags.NONE,
        )
        msg.payload = data
        msg.aux = aux_args
        await self._send_message(msg)
        return msg.identifier

    async def send_dispatch(
        self,
        channel_code: int,
        method: str,
        args: Sequence[Any] = (),
        expects_reply: bool = True,
    ) -> int:
        """Send a DISPATCH (method call) on *channel_code*.

        Returns the assigned message identifier.
        """
        msg = DTXMessage(
            type=DTXMessageType.DISPATCH,
            channel_code=channel_code,
            transport_flags=DTXTransportFlags.EXPECTS_REPLY if expects_reply else DTXTransportFlags.NONE,
        )
        msg.payload = method
        msg.aux = args
        await self._send_message(msg)
        return msg.identifier

    async def _send_reply(
        self,
        channel_code: int,
        msg_id: int,
        conv_idx: int,
        msg_type: DTXMessageType,
        payload: Any = None,
        aux_args: Sequence[Any] = (),
    ) -> None:
        """Send a typed reply (OK / OBJECT / ERROR) for a received request."""
        assert conv_idx, f"Replies must have a non-zero conversation index (got {conv_idx})"
        if msg_type == DTXMessageType.OK:
            assert payload is None, "OK replies must not have a payload"
            assert not aux_args, "OK replies must not have aux arguments"
        elif msg_type == DTXMessageType.ERROR:
            assert payload is not None, "ERROR replies must have a payload"
            assert not aux_args, "ERROR replies must not have aux arguments"
            assert isinstance(payload, NSError), f"ERROR reply payload must be an NSError, got {type(payload)}"

        msg = DTXMessage(
            type=msg_type,
            identifier=msg_id,
            conversation_index=conv_idx,
            channel_code=channel_code,
            transport_flags=DTXTransportFlags.NONE,
        )
        msg.payload = payload
        msg.aux = aux_args
        await self._send_message(msg)

    # ------------------------------------------------------------------
    # Public reply helpers
    # ------------------------------------------------------------------

    async def send_reply(
        self,
        channel_code: int,
        msg_id: int,
        conv_idx: int,
        payload: Any = None,
        aux_args: Sequence[Any] = (),
    ) -> None:
        """Send a success (OBJECT) reply carrying *payload*."""
        await self._send_reply(channel_code, msg_id, conv_idx, DTXMessageType.OBJECT, payload, aux_args)

    async def send_reply_ack(self, channel_code: int, msg_id: int, conv_idx: int) -> None:
        """Send an ACK-only (OK) reply with no payload."""
        await self._send_reply(channel_code, msg_id, conv_idx, DTXMessageType.OK)

    async def send_reply_error(self, channel_code: int, msg_id: int, conv_idx: int, error: NSError) -> None:
        """Send an error (ERROR) reply with *error* as the payload."""
        await self._send_reply(channel_code, msg_id, conv_idx, DTXMessageType.ERROR, error)

    def _schedule_reply_error(self, channel_code: int, msg_id: int, conv_idx: int, error: NSError) -> None:
        """Schedule an error reply to be sent"""
        t = asyncio.create_task(self.send_reply_error(channel_code, msg_id, conv_idx, error))
        self._pending_outgoing_replies.append(t)
        t.add_done_callback(self._pending_outgoing_replies.remove)

    # ------------------------------------------------------------------
    # Reply correlation
    # ------------------------------------------------------------------

    async def _wait_for_reply(self, msg_id: int) -> DTXMessage:
        """Await the reply Future registered under *msg_id*.

        Raises :class:`DTXProtocolError` if no Future is registered for
        *msg_id* (i.e. the message was sent without ``EXPECTS_REPLY``).
        The Future is removed from ``_pending_replies`` when the awaiter
        returns normally; cancelled awaiters leave the Future in place so
        other waiters can still receive the eventual reply.
        """
        future = self._pending_replies.get(msg_id)
        if future is None:
            raise DTXProtocolError(f"No pending reply with msg_id {msg_id}")
        waiter_cancelled = False
        try:
            return await future
        except asyncio.CancelledError:
            waiter_cancelled = True
            raise
        finally:
            if not waiter_cancelled:
                self._pending_replies.pop(msg_id, None)
