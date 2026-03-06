"""DTX protocol connection — lifecycle, channel management and capability handshake.

:class:`DTXConnection` is the top-level object for a DTX session.  It owns:

- the asyncio ``StreamReader`` / ``StreamWriter`` pair to the device;
- the fragment reassembly state machine (via :class:`_DTXReaderMixin`);
- the send path (via :class:`_DTXSenderMixin`);
- the channel registry (``DTXChannel`` instances keyed by channel code);
- the pending-reply map (correlated by message identifier);
- the control channel (channel 0) and its :class:`DTXControlService`.

Typical usage::

    conn = await DTXConnection.from_socket(sock)
    async with conn:
        svc = await conn.open_channel("com.apple.instruments.server.services.deviceinfo")
        result = await svc.do_invoke("runningProcesses")
"""

from __future__ import annotations

import asyncio
import logging
import socket as _socket
from contextlib import suppress
from typing import Any, Callable, Optional, overload

from pymobiledevice3.exceptions import ConnectionTerminatedError

from ._reader import _DTXReaderMixin
from ._sender import _DTXSenderMixin
from .channel import DTXChannel
from .context import DTX_GLOBAL_CTX, DTXContext
from .message import DTXFragmenter, DTXMessage, DTXProtocolError
from .ns_types import NSError
from .service import DTX_SERVICE_T, DTXControlService, DTXDynamicService, DTXProxyService, DTXService


class DTXConnection(_DTXSenderMixin, _DTXReaderMixin):
    """
    DTX protocol connection.

    Manages the full DTX lifecycle:

    - Reads raw bytes from the transport and reassembles multi-fragment messages.
    - Bounds fragment buffers (count, size) and validates fragment ordering.
    - Dispatches assembled messages to the correct ``DTXChannel``.
    - Provides :meth:`open_channel` to open named service channels.
    - Handles the initial capability-notification handshake automatically
      inside :meth:`connect`.

    Use :meth:`from_socket` to create a connection from a raw :class:`socket.socket`,
    or instantiate directly with an ``asyncio.StreamReader`` / ``asyncio.StreamWriter``
    pair (useful when the caller already owns the streams).
    """

    @classmethod
    async def from_socket(cls, sock: _socket.socket) -> DTXConnection:
        """Create a :class:`DTXConnection` from a raw :class:`socket.socket`.

        Opens asyncio streams over *sock* and delegates to the primary constructor.
        """
        reader, writer = await asyncio.open_connection(sock=sock)
        return cls(reader, writer)

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        fileno = -1
        with suppress(Exception):
            fileno = self._writer.get_extra_info("socket").fileno()
        self.logger = logging.getLogger(__name__).getChild(f"DTXConnection({fileno})")

        # Fragment reassembly state (used by _DTXReaderMixin)
        self._fragmenters: dict[int, DTXFragmenter] = {}
        self._total_buffered: int = 0

        # Send state (used by _DTXSenderMixin)
        self._next_msg_id: int = 1
        self._send_lock = asyncio.Lock()
        self._pending_replies: dict[int, asyncio.Future[DTXMessage]] = {}

        # Channel registry
        self._channels: dict[int, DTXChannel] = {}
        self._next_channel_code: int = 1
        self._channel_lock = asyncio.Lock()
        self._services: dict[int, DTXService] = {}

        # Background reader task
        self._reader_task: asyncio.Task | None = None
        self._closed: bool = False

        # Per-connection context — user populates this before/after connecting.
        # Channel contexts are children of this.
        # "connection" is set here so all child channel contexts can reach the
        # DTXConnection via ctx["connection"] without walking _channel._connection.
        self.ctx: DTXContext = DTXContext(parent=DTX_GLOBAL_CTX, connection=self)

        # Per-connection service class registry: identifier → DTXService subclass.
        # DTXConnection instantiates the class with a channel context when needed.
        self._services_cls: dict[str, type[DTXService]] = {}

        # Channel 0 — implicit control channel for handshake and channel lifecycle.
        self._ctrl_channel: DTXChannel = DTXChannel(0, "ctrl", self)
        self._channels[0] = self._ctrl_channel
        ctrl_ctx = self.ctx.child(channel=self._ctrl_channel)
        self._control_svc: DTXControlService = DTXControlService(ctrl_ctx)
        self._services[0] = self._control_svc

        # Condition notified whenever a new service is registered (open_channel or
        # _on_channel_request). Used by wait_for_service / wait_for_proxied_service.
        self._service_condition: asyncio.Condition = asyncio.Condition()

        # Resolved with the peer's capabilities dict on successful handshake.
        self._handshake_done: asyncio.Future[dict] = asyncio.get_event_loop().create_future()
        self.supported_identifiers: dict = {}

        # Set when aclose() finishes — callers can await wait_disconnected() to know
        # when the TCP connection has actually been torn down (e.g. after a kill signal).
        self._disconnected: asyncio.Event = asyncio.Event()

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Start the reader loop and perform the capability-notification handshake.

        Paired with :meth:`aclose`.  Using the async context manager (``async with``)
        is equivalent and preferred when the lifetime is lexically scoped::

            async with DtxServiceProvider(lockdown) as provider:
                async with provider as conn:
                    ...

        For lazy or externally-managed lifetimes call these directly::

            conn = DTXConnection(reader, writer)
            conn.register_services(MyService)
            await conn.connect()
            svc = await conn.open_channel(MyService)
            ...
            await conn.aclose()
        """
        self._reader_task = asyncio.create_task(self._process_incoming_fragments(), name="dtx-reader")
        self._ctrl_channel._start()
        await self._perform_handshake()

    async def aclose(self) -> None:
        """Stop the reader, cancel pending operations, and close all channels.

        This is the canonical async-resource close method (``contextlib.aclosing``
        compatible).  :meth:`close` is a back-compat alias.
        """
        if self._closed:
            return
        self._closed = True
        if self._reader_task is not None and asyncio.current_task() is not self._reader_task:
            self._reader_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await self._reader_task

        with suppress(Exception):
            self._reader.feed_eof()
        with suppress(Exception):
            self._writer.close()
        with suppress(Exception):
            await asyncio.wait_for(self._writer.wait_closed(), timeout=5.0)

        async with self._channel_lock:
            for channel in list(self._channels.values()):
                channel._shutdown("connection closing")
            self._channels.clear()
            self._services.clear()

        for f in self._pending_replies.values():
            if not f.done():
                f.set_exception(ConnectionTerminatedError("Connection closed"))
        self._pending_replies.clear()

        self._disconnected.set()

    async def wait_disconnected(self) -> None:
        """Wait until the connection has fully closed (reader task exited and cleanup done).

        Useful as a reliable signal that the device has actually dropped the TCP connection,
        e.g. after sending a fire-and-forget kill signal::

            await process_ctrl.killPid_(pid)
            await asyncio.wait_for(conn.wait_disconnected(), timeout=30)
            # device is confirmed down — safe to reconnect
        """
        await self._disconnected.wait()

    async def close(self) -> None:
        """Alias for :meth:`aclose` kept for back-compatibility."""
        await self.aclose()

    async def __aenter__(self) -> DTXConnection:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    # Channel management
    # ------------------------------------------------------------------

    @overload
    async def open_channel(self, identifier: str) -> DTXService: ...

    @overload
    async def open_channel(self, cls: type[DTX_SERVICE_T]) -> DTX_SERVICE_T: ...

    @overload
    async def open_channel(self, identifier: str, cls: type[DTX_SERVICE_T]) -> DTX_SERVICE_T: ...

    async def open_channel(self, identifier_or_cls: str, cls: Optional[type[DTXService]] = None) -> DTXService:
        """Open a named service channel and return the bound :class:`DTXService`.

        Looks up *identifier* in the per-connection service class registry.
        If found, instantiates the class with a channel context (child of
        ``self.ctx`` with ``"channel"`` set).  Falls back to
        :class:`DTXDynamicService` if the identifier is not registered.

        For ``dtxproxy:`` identifiers both sub-service names are looked up and
        a :class:`DTXProxyService` is assembled synchronously under the channel
        lock to prevent races.

        Sends ``_requestChannelWithCode:identifier:`` on the control channel
        and awaits the OK reply before returning::

            conn.register_service(DeviceInfoService)
            svc = await conn.open_channel(DeviceInfoService.IDENTIFIER)
            result = await svc.do_invoke("runningProcesses")
        """
        identifier: str = identifier_or_cls
        if isinstance(identifier_or_cls, type):
            if cls is not None:
                raise ValueError(f"Cannot specify two types: {identifier_or_cls} and {cls}")
            cls = identifier_or_cls
            identifier: str = cls.IDENTIFIER

        if not identifier:
            raise ValueError("Identifier cannot be empty")

        async with self._channel_lock:
            code = self._next_channel_code
            self._next_channel_code += 1
            channel = DTXChannel(code, identifier, self)
            self._channels[code] = channel
            if cls is not None:
                s = self._instantiate_service_from_class(cls, channel)
            else:
                s = self._instantiate_service(identifier, channel, remote=False)

        try:
            await self._control_svc.request_channel(code, identifier)
        except Exception:
            async with self._channel_lock:
                self._channels.pop(code, None)
            self.logger.exception("Error opening channel identifier=%r code=%d", identifier, code)
            channel._shutdown("open channel error")
            raise

        async with self._channel_lock:
            self._services[code] = s
            channel._start()

        async with self._service_condition:
            self._service_condition.notify_all()

        return s

    async def cancel_channel(self, channel: DTXChannel) -> None:
        """Cancel *channel* and remove it from the registry."""
        async with self._channel_lock:
            self._services.pop(channel.code, None)
            ch = self._channels.pop(channel.code, None)
            if ch:
                ch._shutdown("channel cancelled")
        await self._control_svc.cancel_channel(channel.code)

    def register_service(self, cls: type[DTXService]) -> None:
        """Register a :class:`DTXService` subclass for *cls.IDENTIFIER*.

        When the identifier is subsequently opened (either by
        :meth:`open_channel` or by an incoming ``_requestChannelWithCode:``
        from the remote end), the class is instantiated with a
        :class:`DTXContext` child of ``self.ctx``::

            conn.register_service(DeviceInfoService)
            conn.register_service(ProcessControlService)
        """
        if cls.IDENTIFIER is None:
            raise ValueError(f"{cls.__name__} must define IDENTIFIER")
        old = self._services_cls.get(cls.IDENTIFIER)
        if old is not None and old is not cls:
            self.logger.warning(
                "Overwriting existing service registration for identifier %r: %r -> %r", cls.IDENTIFIER, old, cls
            )
        self._services_cls[cls.IDENTIFIER] = cls

    def register_services(self, *classes: type[DTXService]) -> None:
        """Register multiple :class:`DTXService` subclasses at once::

        conn.register_services(IDEInterface, DriverInterface, DaemonInterface)
        """
        for cls in classes:
            self.register_service(cls)

    async def wait_for_service(
        self,
        predicate: type[DTX_SERVICE_T] | Callable[[DTXService], bool],
        *,
        timeout: float | None = None,
    ) -> DTX_SERVICE_T:
        """Wait until a registered service matching *predicate* exists and return it.

        *predicate* can be a service class (``isinstance`` check) or any callable
        that takes a :class:`DTXService` and returns ``bool``.  All services
        registered at the time of each wakeup are checked — existing services
        are matched immediately without waiting::

            svc = await conn.wait_for_service(MyService, timeout=10.0)

            # With a predicate for disambiguation when multiple exist:
            svc = await conn.wait_for_service(
                lambda s: isinstance(s, MyService) and s.session_id == sid,
                timeout=10.0,
            )

        Raises :exc:`asyncio.TimeoutError` if *timeout* elapses.
        """
        if isinstance(predicate, type):
            _cls = predicate

            def predicate(svc: DTXService) -> bool:
                return isinstance(svc, _cls)

        async def _find() -> DTXService:
            async with self._service_condition:
                while True:
                    for svc in self._services.values():
                        if predicate(svc):
                            return svc
                    await self._service_condition.wait()

        return await asyncio.wait_for(_find(), timeout=timeout)

    async def wait_for_proxied_service(
        self,
        predicate: type[DTX_SERVICE_T] | Callable[[DTXService], bool],
        *,
        remote: bool,
        timeout: float | None = None,
    ) -> DTX_SERVICE_T:
        """Wait for a sub-service of a :class:`DTXProxyService` matching *predicate*.

        Inspects ``remote_service`` when *remote* is ``True``, or
        ``local_service`` when *remote* is ``False``.
        Returns the matching sub-service directly (not the proxy wrapper)::

            ide = await conn.wait_for_proxied_service(
                IDEInterface, remote=False, timeout=10.0
            )
            driver = await conn.wait_for_proxied_service(
                XCTestDriverInterface, remote=True, timeout=10.0
            )

        Raises :exc:`asyncio.TimeoutError` if *timeout* elapses.
        """
        if isinstance(predicate, type):
            _cls = predicate

            def predicate(svc: DTXService) -> bool:
                return isinstance(svc, _cls)

        async def _find() -> DTXService:
            async with self._service_condition:
                while True:
                    for svc in self._services.values():
                        if isinstance(svc, DTXProxyService):
                            candidate = svc.remote_service if remote else svc.local_service
                            if predicate(candidate):
                                return candidate
                    await self._service_condition.wait()

        return await asyncio.wait_for(_find(), timeout=timeout)

    # ------------------------------------------------------------------
    # Internal channel callbacks (called by DTXControlService)
    # ------------------------------------------------------------------

    async def _on_channel_request(
        self,
        code: int,
        identifier: str,
    ) -> NSError | None:
        assert code > 0, f"Channel code must be positive, got {code}"
        code = -code  # negate to distinguish from locally initiated channels

        async with self._channel_lock:
            if code in self._channels:
                return NSError(1, "DTXMessage", {"NSLocalizedDescription": f"Channel code {-code} is already in use"})
            channel = DTXChannel(code, identifier, self)
            self._channels[code] = channel
            try:
                s = self._instantiate_service(identifier, channel, remote=True)
            except Exception as e:
                self.logger.exception("Error instantiating service identifier=%r code=%d", identifier, code)
                self._channels.pop(code, None)
                return NSError(
                    1, "DTXMessage", {"NSLocalizedDescription": f"Failed to instantiate {identifier!r}: {e!r}"}
                )
            self._services[code] = s
            channel._start()

        async with self._service_condition:
            self._service_condition.notify_all()
        return None

    async def _on_channel_cancelled(self, channel_code: int) -> None:
        self.logger.warning("Received channel cancellation for code %d", channel_code)
        async with self._channel_lock:
            self._services.pop(channel_code, None)
            ch = self._channels.pop(channel_code, None)
            if ch:
                ch._shutdown("channel cancelled by remote")
            else:
                self.logger.error("Received cancellation for unknown channel %d", channel_code)
                raise DTXProtocolError(f"Received channel cancellation for unknown channel {channel_code}")

    async def _on_capabilities_received(self, capabilities: dict) -> None:
        self.logger.debug("Received capabilities from remote: %r", capabilities)
        self.supported_identifiers = capabilities
        if not self._handshake_done.done():
            self._handshake_done.set_result(capabilities)

    # ------------------------------------------------------------------
    # Internal service instantiation helpers
    # ------------------------------------------------------------------

    def _instantiate_service_from_class(self, cls: type[DTXService], channel: DTXChannel) -> DTXService:
        """Instantiate a service directly from *cls*."""
        return cls(self.ctx.child(channel=channel))

    def _instantiate_service(self, identifier: str, channel: DTXChannel, remote: bool) -> DTXService:
        """Synchronously create and return the service for *identifier*.

        Must be called with ``_channel_lock`` held so dtxproxy assembly is
        atomic with channel registration.

        :param remote: ``True`` if the channel was opened by the remote end
            (triggers local/remote name swap for dtxproxy identifiers).
        """
        if identifier.startswith("dtxproxy:"):
            return self._instantiate_dtxproxy(identifier, channel, remote=remote)
        cls = self._services_cls.get(identifier)
        if cls is None:
            self.logger.debug("No service registered for %r, using DTXDynamicService", identifier)
            cls = DTXDynamicService
        return self._instantiate_service_from_class(cls, channel)

    def _instantiate_dtxproxy(self, identifier: str, channel: DTXChannel, remote: bool) -> DTXProxyService:
        """Synchronously assemble a :class:`DTXProxyService` for a dtxproxy channel.

        The identifier format is ``dtxproxy:LocalName:RemoteName`` from our
        perspective when ``remote=False``.  When ``remote=True`` (remote
        opened the channel), names are swapped.

        Both sub-services receive a child context that has ``"dtxproxy"`` set
        to the proxy instance so their ``__init__`` skips channel wiring and
        they can reach their counterpart via ``self._ctx["dtxproxy"]``.
        """
        assert identifier.startswith("dtxproxy:") and identifier.count(":") == 2, (
            f"Unexpected dtxproxy identifier format: {identifier!r}"
        )
        _, local_name, remote_name = identifier.split(":")
        if remote:
            local_name, remote_name = remote_name, local_name

        proxy_ctx = self.ctx.child(channel=channel)
        proxy = DTXProxyService(proxy_ctx)

        sub_ctx = proxy_ctx.child(dtxproxy=proxy)

        local_cls = self._services_cls.get(local_name)
        if local_cls is None:
            self.logger.warning("dtxproxy: no service registered for local %r, using dynamic", local_name)
        proxy.local_service = (local_cls or DTXDynamicService)(sub_ctx.child(is_remote=False))

        remote_cls = self._services_cls.get(remote_name)
        if remote_cls is None:
            self.logger.debug("dtxproxy: no service registered for remote %r, using dynamic", remote_name)
        proxy.remote_service = (remote_cls or DTXDynamicService)(sub_ctx.child(is_remote=True))

        return proxy

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    async def _perform_handshake(self) -> None:
        """Exchange ``_notifyOfPublishedCapabilities:`` with the server.

        Sends our capabilities dict and waits until the server's counterpart
        arrives (stored in :attr:`supported_identifiers`).
        """
        capabilities = {
            "com.apple.private.DTXBlockCompression": 0,
            "com.apple.private.DTXConnection": 1,
        }
        await self._control_svc.notify_capabilities(capabilities)
        try:
            await asyncio.wait_for(asyncio.shield(self._handshake_done), timeout=15.0)
        except asyncio.TimeoutError as exc:
            raise ConnectionError("DTX capability handshake timed out") from exc
