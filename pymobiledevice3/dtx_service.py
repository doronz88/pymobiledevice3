from __future__ import annotations

import logging
import sys
from typing import Any, ClassVar, Generic, Optional, TypeVar

from typing_extensions import Self

from pymobiledevice3.dtx import DTXConnection
from pymobiledevice3.dtx import DTXDynamicService as _DTXDynamicService
from pymobiledevice3.dtx import DTXService as _DTXService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider

if sys.version_info >= (3, 13):
    _SVC_T = TypeVar("_SVC_T", bound=_DTXService, default=_DTXDynamicService)
else:
    _SVC_T = TypeVar("_SVC_T", bound=_DTXService)


class DtxService(Generic[_SVC_T]):
    CHANNEL_IDENTIFIER: ClassVar[Optional[str]] = None
    """Optional raw channel identifier string.

    When set, the channel is opened by this string rather than by the service
    class resolved from ``_SVC_T`` or defaults to :class:`~pymobiledevice3.dtx.DTXDynamicService`.
    This is the highest-priority resolution path.
    """

    _inferred_service_class: ClassVar[Optional[type[_DTXService]]] = None
    """Service class inferred from the ``_SVC_T`` type parameter.

    Populated automatically by :meth:`__init_subclass__` when the subclass is
    defined as ``DtxService[SomeClass]``.  Do not set this manually.
    """

    def __init_subclass__(cls, **kw: Any) -> None:
        super().__init_subclass__(**kw)
        # Look for a direct DtxService[X] base on *this* class only.
        # Using ``base.__origin__ is DtxService`` (PEP 560 / Python 3.7+) is
        # more precise than inspecting arg-count with typing.get_args —
        # it won't accidentally match DtxProxyService[A, B] or unrelated bases.
        for base in getattr(cls, "__orig_bases__", ()):
            if getattr(base, "__origin__", None) is DtxService:
                args = getattr(base, "__args__", ())
                if args and isinstance(args[0], type) and issubclass(args[0], _DTXService):
                    cls._inferred_service_class = args[0]
                break
        # Note: no validation here — DtxProxyService resets _inferred_service_class
        # to None for its own subclasses and performs its own validation.

    def __init__(
        self,
        provider: DtxServiceProvider,
        service: Optional[_SVC_T] = None,
    ) -> None:
        """
        :param provider: Active (or not-yet-connected) :class:`DtxServiceProvider`
            that owns the underlying
            :class:`~pymobiledevice3.dtx.DTXConnection`.
        :param service: Pre-opened :class:`~pymobiledevice3.dtx.DTXService`
            to re-use.  When supplied the instance does **not** manage its
            lifecycle.
        """
        self._provider = provider
        self._service: Optional[_SVC_T] = service
        self.logger = logging.getLogger(self.__module__)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def provider(self) -> DtxServiceProvider:
        """The owning :class:`DtxServiceProvider`."""
        return self._provider

    @property
    def dtx(self) -> DTXConnection:
        """The underlying :class:`~pymobiledevice3.dtx.DTXConnection`.

        Shorthand for ``self.provider.dtx``.
        """
        return self._provider.dtx

    @property
    def service(self) -> _SVC_T:
        """The active :class:`~pymobiledevice3.dtx.DTXService` channel.

        Raises :exc:`RuntimeError` if :meth:`connect` has not been called yet.
        The return type matches the ``_SVC_T`` type parameter or :class:`~pymobiledevice3.dtx.DTXDynamicService`.
        """
        if self._service is None:
            raise RuntimeError("not connected — use `async with` or await connect()")
        return self._service

    # ------------------------------------------------------------------
    # Hook
    # ------------------------------------------------------------------

    async def _acquire_channel(self) -> _SVC_T:
        """Open and return the DTX channel for this service.

        Resolution order:

        1. :attr:`CHANNEL_IDENTIFIER` set **and** ``_SVC_T`` inferred →
           ``open_channel(identifier, cls)`` (typed lookup by explicit id).
        2. :attr:`CHANNEL_IDENTIFIER` set, no inferred class →
           ``open_channel(identifier)`` (registry/dynamic lookup; used by
           :class:`~pymobiledevice3.dtx_proxy_service.DtxProxyService` so the
           sub-service registry wires the proxy correctly).
        3. Only ``_SVC_T`` inferred → ``open_channel(cls)`` (identifier from
           ``cls.IDENTIFIER``).

        Override for non-standard acquisition, for example to wait for a
        remote-initiated proxied channel::

            async def _acquire_channel(self):
                return await self.dtx.wait_for_proxied_service(
                    XCTestDriverInterface, remote=True, timeout=90.0
                )
        """
        if self.CHANNEL_IDENTIFIER is not None:
            if self._inferred_service_class is not None:
                return await self._provider.dtx.open_channel(self.CHANNEL_IDENTIFIER, self._inferred_service_class)
            return await self._provider.dtx.open_channel(self.CHANNEL_IDENTIFIER)
        assert self._inferred_service_class is not None, (
            "Cannot infer service class — specify CHANNEL_IDENTIFIER or provide a concrete "
            "type parameter, e.g. DtxService[MyService]"
        )
        return await self._provider.dtx.open_channel(self._inferred_service_class)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Ensure the provider is connected and acquire the channel.

        No-op if already connected.  Connects the provider if it has not been
        connected yet (safe to call even when the provider is already live).
        """
        await self._provider.connect()
        if self._inferred_service_class is not None:
            self._provider.dtx.register_service(self._inferred_service_class)
        if self._service is not None:
            return
        self._service = await self._acquire_channel()

    async def close(self) -> None:
        """No-op — channel lifetime is managed by the :class:`DtxServiceProvider`.

        Override if you need to perform teardown on the channel (e.g. sending
        a graceful shutdown message) before the connection is closed.
        """

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
