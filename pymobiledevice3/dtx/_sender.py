"""DTX send-path mixin — serialises outgoing messages and tracks pending replies.

Intended to be mixed into :class:`~pymobiledevice3.dtx.connection.DTXConnection`;
all ``self.*`` references are resolved at runtime on the concrete class.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from typing import Any

from bpylist2 import archiver

from pymobiledevice3.exceptions import ConnectionTerminatedError

from .message import (
    DTX_FRAGMENT_MAGIC,
    FRAGMENT_HEADER_MIN_SIZE,
    MAX_FRAGMENT_SIZE,
    MESSAGE_PAYLOAD_HEADER_SIZE,
    DTXMessage,
    DTXMessageType,
    DTXProtocolError,
    DTXTransportFlags,
    dtx_fragment_header,
    dtx_payload_header,
)
from .ns_types import NSError
from .primitives import _args_to_aux_bytes


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
    _closed: bool
    logger: logging.Logger

    # ------------------------------------------------------------------
    # Low-level frame serialisation
    # ------------------------------------------------------------------

    async def _send_message(self, message: DTXMessage) -> None:
        """Serialise and write *message* to the transport as a single fragment."""
        assert len(message.aux_data) + len(message.payload_data) + MESSAGE_PAYLOAD_HEADER_SIZE <= MAX_FRAGMENT_SIZE, (
            "Multi-fragment messages are not yet supported in this implementation"
        )

        if self._closed:
            raise ConnectionTerminatedError("Cannot send message: connection is closed")

        pheader = dtx_payload_header.build({
            "msg_type": int(message.type),
            "flags_a": 0,
            "flags_b": 0,
            "reserved": 0,
            "aux_size": len(message.aux_data),
            "total_size": len(message.aux_data) + len(message.payload_data),
        })

        wire_code = message.channel_code if message.conversation_index % 2 == 0 else -message.channel_code

        async with self._send_lock:
            if message.identifier == 0:
                message.identifier = self._next_msg_id
                self._next_msg_id += 1
            if DTXTransportFlags.EXPECTS_REPLY in message.transport_flags:
                future: asyncio.Future = asyncio.get_running_loop().create_future()
                self._pending_replies[message.identifier] = future
            mheader = dtx_fragment_header.build({
                "magic": DTX_FRAGMENT_MAGIC,
                "cb": FRAGMENT_HEADER_MIN_SIZE,
                "index": 0,
                "count": 1,
                "data_size": len(message.aux_data) + len(message.payload_data) + MESSAGE_PAYLOAD_HEADER_SIZE,
                "identifier": message.identifier,
                "conversation_index": message.conversation_index,
                "channel_code": wire_code,
                "flags": int(message.transport_flags),
            })
            self._writer.write(mheader)
            self._writer.write(pheader)
            self._writer.write(message.aux_data)
            self._writer.write(message.payload_data)
            try:
                await self._writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
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
        payload_bytes = archiver.archive(payload)

        msg = DTXMessage(
            type=DTXMessageType.ERROR if isinstance(payload, NSError) else DTXMessageType.OBJECT,
            channel_code=channel_code,
            transport_flags=DTXTransportFlags.EXPECTS_REPLY if expects_reply else DTXTransportFlags.NONE,
            aux_data=memoryview(_args_to_aux_bytes(aux_args)),
            payload_data=memoryview(payload_bytes),
        )
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
            aux_data=memoryview(_args_to_aux_bytes(aux_args)),
            payload_data=memoryview(data),
        )
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
        payload_bytes = archiver.archive(method)

        msg = DTXMessage(
            type=DTXMessageType.DISPATCH,
            channel_code=channel_code,
            transport_flags=DTXTransportFlags.EXPECTS_REPLY if expects_reply else DTXTransportFlags.NONE,
            aux_data=memoryview(_args_to_aux_bytes(args)),
            payload_data=memoryview(payload_bytes),
        )
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
        assert msg_type in (DTXMessageType.OK, DTXMessageType.OBJECT, DTXMessageType.ERROR), (
            f"Invalid reply message type: {msg_type}"
        )
        assert conv_idx, f"Replies must have a non-zero conversation index (got {conv_idx})"
        if msg_type == DTXMessageType.OK:
            assert payload is None, "OK replies must not have a payload"
            assert not aux_args, "OK replies must not have aux arguments"
        elif msg_type == DTXMessageType.ERROR:
            assert payload is not None, "ERROR replies must have a payload"
            assert not aux_args, "ERROR replies must not have aux arguments"
            assert isinstance(payload, NSError), f"ERROR reply payload must be an NSError, got {type(payload)}"

        payload_bytes = archiver.archive(payload) if payload is not None else b""

        msg = DTXMessage(
            type=msg_type,
            identifier=msg_id,
            conversation_index=conv_idx,
            channel_code=channel_code,
            transport_flags=DTXTransportFlags.NONE,
            aux_data=memoryview(_args_to_aux_bytes(aux_args)),
            payload_data=memoryview(payload_bytes),
        )
        await self._send_message(msg)

    # ------------------------------------------------------------------
    # Public reply helpers
    # ------------------------------------------------------------------

    async def send_reply(
        self, channel_code: int, msg_id: int, conv_idx: int, payload: Any = None, *aux_args: Any
    ) -> None:
        """Send a success (OBJECT) reply carrying *payload*."""
        await self._send_reply(channel_code, msg_id, conv_idx, DTXMessageType.OBJECT, payload, aux_args)

    async def send_reply_ack(self, channel_code: int, msg_id: int, conv_idx: int) -> None:
        """Send an ACK-only (OK) reply with no payload."""
        await self._send_reply(channel_code, msg_id, conv_idx, DTXMessageType.OK)

    async def send_reply_error(self, channel_code: int, msg_id: int, conv_idx: int, error: NSError) -> None:
        """Send an error (ERROR) reply with *error* as the payload."""
        await self._send_reply(channel_code, msg_id, conv_idx, DTXMessageType.ERROR, error)

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
