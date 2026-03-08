"""DTX logical channel — per-channel message queue and dispatch.

A :class:`DTXChannel` represents one logical DTX channel identified by an
integer code.  Each channel owns an :class:`asyncio.Queue` and a background
reader task that dequeues messages and calls the appropriate handler:

- ``on_invoke``       — incoming DISPATCH messages (method + args)
- ``on_data``         — incoming DATA frames (raw bytes)
- ``on_notification`` — incoming server-initiated OBJECT / OK messages

Channels are created and managed by
:class:`~pymobiledevice3.dtx.connection.DTXConnection`; do not
instantiate them directly.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable
from contextlib import suppress
from functools import partial
from typing import TYPE_CHECKING, Any, Callable

from bpylist2 import archiver

from pymobiledevice3.exceptions import ConnectionTerminatedError, UnrecognizedSelectorError

from .message import (
    DTXMessage,
    DTXMessageType,
    DTXNsError,
    DTXProtocolError,
    DTXTransportFlags,
    format_dtx_message,
)
from .ns_types import NSError
from .primitives import parse_aux

if TYPE_CHECKING:
    from .connection import DTXConnection

logger = logging.getLogger(__name__)


class DTXChannel:
    """Logical DTX channel.

    Each channel owns an asyncio message queue and a reader task that
    dequeues messages and dispatches them to the appropriate handler.
    Three optional async callback slots can be set on an instance:

    - ``on_invoke``: called for incoming DISPATCH messages (method, args).
    - ``on_data``: called for incoming DATA frames (raw bytes payload).
    - ``on_notification``: called for server-initiated OBJECT/OK messages.
    """

    # Optional async callbacks for received messages.
    on_invoke: Callable[[str, list[Any]], Awaitable[Any]] | None = None
    on_data: Callable[[bytes], Awaitable[Any]] | None = None
    on_notification: Callable[[Any], Awaitable[Any]] | None = None

    def __init__(self, code: int, identifier: str, connection: DTXConnection) -> None:
        self.code = code
        self.identifier = identifier
        self._connection = connection
        self.logger = connection.logger.getChild(f"channel({code})")

        self._closed = False
        self._reader_task: asyncio.Task | None = None

        self._queue: asyncio.Queue[DTXMessage] = asyncio.Queue()
        self._pending_tasks: set[asyncio.Task] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def invoke(self, method: str, *args: Any, expects_reply: bool = True) -> Any:
        """Invoke *method* on this channel and return the decoded reply value."""
        self._check_open()
        msg_id = await self._connection.send_dispatch(
            channel_code=self.code,
            method=method,
            args=args,
            expects_reply=expects_reply,
        )
        if not expects_reply:
            return None
        return await self._unwrap_reply(msg_id, f"invoke({method!r})")

    async def notify(self, notification: Any, *aux_args: Any, expects_reply: bool = False) -> Any:
        """Send a server-bound notification and optionally await the reply."""
        self._check_open()
        msg_id = await self._connection.send_notification(self.code, notification, aux_args, expects_reply)
        if not expects_reply:
            return None
        return await self._unwrap_reply(msg_id, f"notify({notification!r})")

    async def send_data(self, data: bytes, *aux_args: Any, expects_reply: bool = False) -> Any:
        """Send a DATA frame and optionally await the reply."""
        self._check_open()
        msg_id = await self._connection.send_data(self.code, data, aux_args, expects_reply)
        if not expects_reply:
            return None
        return await self._unwrap_reply(msg_id, f"send_data(len={len(data)})")

    # ------------------------------------------------------------------
    # Internal message handlers
    # ------------------------------------------------------------------

    async def _unwrap_reply(self, msg_id: int, context: str) -> Any:
        """Await a correlated reply and unwrap it into a Python value.

        Returns the decoded OBJECT payload, ``None`` for OK, or raises
        :class:`DTXNsError` / :class:`UnrecognizedSelectorError` on error.
        """
        reply = await self._connection._wait_for_reply(msg_id)
        if reply.type not in (DTXMessageType.OK, DTXMessageType.OBJECT, DTXMessageType.ERROR):
            raise DTXProtocolError(f"Unexpected reply type {reply.type!r} for {context} on channel {self.code}")
        if reply.type == DTXMessageType.ERROR:
            error: NSError = archiver.unarchive(bytes(reply.payload_data))
            if not isinstance(error, NSError):
                raise DTXProtocolError(
                    f"Expected NSError in ERROR reply for {context} on channel {self.code}, got {error!r}"
                )
            if error.user_info is not None and error.user_info.get("NSLocalizedDescription", "").endswith(
                " - it does not respond to the selector"
            ):
                raise UnrecognizedSelectorError(error.user_info["NSLocalizedDescription"])
            raise DTXNsError(error)
        if reply.type == DTXMessageType.OBJECT:
            return archiver.unarchive(bytes(reply.payload_data))
        return None  # OK

    async def _handle_dispatch(self, message: DTXMessage) -> Any:
        """Incoming DISPATCH: method name in payload, args in aux."""
        if self.on_invoke is None:
            with suppress(Exception):
                self.logger.warning(
                    "Received DISPATCH message on channel %d with no handler: method=%r aux=%r",
                    self.code,
                    archiver.unarchive(bytes(message.payload_data)),
                    parse_aux(message.aux_data),
                )
            return NSError(
                1, "DTXMessage", {"NSLocalizedDescription": "No dispatch handler registered for this channel"}
            )

        method = archiver.unarchive(bytes(message.payload_data))
        if not isinstance(method, str):
            with suppress(Exception):
                self.logger.warning(
                    "Received DISPATCH message on channel %d with non-string method name: payload=%r aux=%r",
                    self.code,
                    method,
                    parse_aux(message.aux_data),
                )
            return NSError(1, "DTXMessage", {"NSLocalizedDescription": f"Expected method name string, got {method!r}"})
        aux = parse_aux(message.aux_data)

        return await self.on_invoke(method, aux)

    async def _handle_notification(self, message: DTXMessage) -> Any:
        """Incoming server-initiated OBJECT / OK (conversation_index == 0)."""
        if self.on_notification is None:
            with suppress(Exception):
                self.logger.warning(
                    "Received notification message on channel %d with no handler: payload=%r aux=%r",
                    self.code,
                    archiver.unarchive(bytes(message.payload_data)),
                    parse_aux(message.aux_data),
                )
            return NSError(
                1, "DTXMessage", {"NSLocalizedDescription": "No notification handler registered for this channel"}
            )

        if message.payload_data:
            payload = archiver.unarchive(bytes(message.payload_data))
        else:
            self.logger.warning(
                "Received notification message on channel %d with empty payload: aux=%r",
                self.code,
                parse_aux(message.aux_data),
            )
            payload = None

        return await self.on_notification(payload)

    async def _handle_data(self, message: DTXMessage) -> Any:
        """Incoming DATA message: payload is opaque bytes, aux may have metadata."""
        if self.on_data is None:
            self.logger.warning(
                "Received DATA message on channel %d with no handler: len(payload)=%d aux=%r",
                self.code,
                len(message.payload_data),
                parse_aux(message.aux_data),
            )
            return NSError(1, "DTXMessage", {"NSLocalizedDescription": "No data handler registered for this channel"})

        return await self.on_data(bytes(message.payload_data))

    async def _handle_barrier(self, message: DTXMessage) -> None:
        """Ensure that all previously received messages on this channel have been
        processed by the client before processing further messages. No payload or
        aux is expected."""
        return None

    async def _handle_message(self, message: DTXMessage) -> None:
        assert message.channel_code == self.code, (
            f"Received message for channel {message.channel_code} in handler for channel {self.code}"
        )
        msg_type = message.type
        res = None
        try:
            if msg_type == DTXMessageType.DISPATCH:
                res = await self._handle_dispatch(message)
            elif msg_type in (DTXMessageType.OK, DTXMessageType.OBJECT, DTXMessageType.ERROR):
                assert message.conversation_index == 0, (
                    f"Received reply message with conversation_index {message.conversation_index} != 0 on channel {self.code}"
                )
                res = await self._handle_notification(message)
            elif msg_type == DTXMessageType.DATA:
                res = await self._handle_data(message)
            elif msg_type == DTXMessageType.BARRIER:
                res = await self._handle_barrier(message)
            else:
                res = NSError(
                    1,
                    "DTXMessage",
                    {"NSLocalizedDescription": f"Received unsupported message type {msg_type} on channel {self.code}"},
                )
        except DTXProtocolError as e:
            self.logger.exception("Protocol error in message handling for channel %d: message=%r", self.code, message)
            res = NSError(1, "DTXMessage", {"NSLocalizedDescription": f"Protocol error in message handling: {e!r}"})
        except DTXNsError as e:
            res = e.error
        except Exception as e:
            self.logger.exception("Error in message handler for channel %d", self.code)
            res = NSError(1, "DTXMessage", {"NSLocalizedDescription": f"Error in message handler: {e!r}"})
        finally:
            if DTXTransportFlags.EXPECTS_REPLY in message.transport_flags:
                msg_type = (
                    DTXMessageType.OK
                    if res is None
                    else (DTXMessageType.OBJECT if not isinstance(res, NSError) else DTXMessageType.ERROR)
                )
                msg = DTXMessage(
                    type=msg_type,
                    identifier=message.identifier,
                    conversation_index=message.conversation_index + 1,
                    channel_code=self.code,
                    transport_flags=DTXTransportFlags.NONE,
                    aux_data=memoryview(b""),
                    payload_data=memoryview(archiver.archive(res) if res is not None else b""),
                )
                await self._connection._send_message(msg)

    def _handle_failure(self, exc: Exception, msg: DTXMessage) -> None:
        if isinstance(exc, ConnectionTerminatedError):
            if self.logger.isEnabledFor(logging.WARNING):
                self.logger.warning("received connection termination: %s", format_dtx_message(msg))
            self._shutdown("connection terminated")
        else:
            self.logger.exception(
                "Error handling message on channel %d: message=%r", self.code, format_dtx_message(msg), exc_info=exc
            )

    def _handle_done(self, fut: asyncio.Future, msg: DTXMessage) -> None:
        self._pending_tasks.discard(fut)
        try:
            fut.result()
        except Exception as exc:
            self._handle_failure(exc, msg)

    def _enqueue_message(self, message: DTXMessage) -> None:
        """Enqueue an incoming message for processing by the reader loop."""
        self._check_open()
        self._queue.put_nowait(message)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _start(self) -> None:
        if self._reader_task is not None:
            return
        self._reader_task = asyncio.create_task(self._reader_loop(), name=f"DTXChannelReader-{self.code}")

    def _shutdown(self, reason: str = "") -> None:
        """Close and stop the channel, draining and warning about any queued messages."""
        if self._closed:
            return
        self._closed = True
        pending = self._queue.qsize()
        if pending:
            self.logger.warning(
                "Channel %d shutting down (%s) with %d unprocessed message(s) in queue",
                self.code,
                reason or "requested",
                pending,
            )
        # Drain the queue so no stale messages linger.
        while not self._queue.empty():
            with suppress(Exception):
                self._queue.get_nowait()
        if self._reader_task is not None:
            self.logger.debug("Stopping reader task for channel %d (%s)", self.code, reason or "requested")
            self._reader_task.cancel()
            self._reader_task = None

    async def __aenter__(self) -> DTXChannel:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self._connection.cancel_channel(self)

    def _close(self) -> None:
        """Alias for :meth:`_shutdown` used by connection teardown."""
        self._shutdown("connection closed")

    def _check_open(self) -> None:
        if self._closed:
            raise ConnectionTerminatedError("Channel is closed")

    async def _reader_loop(self) -> None:
        """Continuously read messages from the connection and dispatch them to the
        appropriate handlers until the channel is closed."""
        while not self._closed:
            try:
                message = await self._queue.get()
                if message is None:
                    self.logger.warning("Channel reader loop exiting: None message received")
                    break
                if message.type == DTXMessageType.BARRIER and self._pending_tasks:
                    self.logger.debug(
                        "Waiting for %d pending message handler tasks to complete before processing BARRIER message on channel %d",
                        len(self._pending_tasks),
                        self.code,
                    )
                    await asyncio.wait(self._pending_tasks)
                t = asyncio.create_task(
                    self._handle_message(message), name=f"DTXChannelMessageHandler-{self.code}-{message.identifier}"
                )
                self._pending_tasks.add(t)
                t.add_done_callback(partial(self._handle_done, msg=message))
            except asyncio.CancelledError:
                if not self._closed:
                    self.logger.exception("Channel reader loop cancelled")
                break
            except ConnectionTerminatedError:
                self.logger.debug("Channel reader loop exiting: connection terminated")
                break
            except Exception:
                if not self._closed:
                    self.logger.exception("Error in channel reader loop for channel %d", self.code)
                break
        self._shutdown("reader loop exiting")
