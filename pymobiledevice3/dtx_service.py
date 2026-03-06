"""DTX service wrapper — manages a single DTX channel within a DtxServiceProvider.

:class:`DtxService` is the DTX-layer counterpart of
:class:`~pymobiledevice3.services.lockdown_service.LockdownService`:

- :class:`~pymobiledevice3.lockdown_service_provider.LockdownServiceProvider`
  manages the device/transport connection.
- :class:`~pymobiledevice3.dtx_service_provider.DtxServiceProvider` owns the
  :class:`~pymobiledevice3.dtx.DTXConnection`.
- :class:`DtxService` wraps a single DTX channel
  (:class:`~pymobiledevice3.dtx.DTXService`) opened via a
  :class:`~pymobiledevice3.dtx_service_provider.DtxServiceProvider`.

Typical usage (host-initiated channel)::

    class DeviceInfoChannel(DtxService):
        SERVICE_CLASS = DeviceInfoService  # a dtx.DTXService subclass

    async with DvtProvider(lockdown) as provider:
        async with DeviceInfoChannel(provider) as ch:
            procs = await ch.service.runningProcesses()

Remote-initiated channel (override :meth:`_acquire_channel`)::

    class XCTestDriverChannel(DtxService):
        SERVICE_CLASS = XCTestDriverInterface

        async def _acquire_channel(self):
            return await self.dtx.wait_for_proxied_service(
                XCTestDriverInterface, remote=True, timeout=90.0
            )

Sharing a pre-opened channel::

    async with DvtProvider(lockdown) as provider:
        raw = await provider.dtx.open_channel(DeviceInfoService)
        svc1 = DeviceInfoChannel(provider, service=raw)
        svc2 = AnotherChannel(provider, service=raw)  # same channel, different wrapper
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar, Generic, Optional, TypeVar

from typing_extensions import Self

from pymobiledevice3.dtx import DTXConnection
from pymobiledevice3.dtx import DTXService as _DTXService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider

_SVC_T = TypeVar("_SVC_T", bound=_DTXService)


class DtxService(Generic[_SVC_T]):
    """Wraps a single DTX channel within a :class:`DtxServiceProvider`.

    Subclasses declare the channel to open via :attr:`SERVICE_CLASS` (a
    :class:`~pymobiledevice3.dtx.DTXService` subclass).
    :attr:`CHANNEL_IDENTIFIER` is optional and overrides
    ``SERVICE_CLASS.IDENTIFIER`` when set::

        class DeviceInfo(DtxService):
            SERVICE_CLASS = DeviceInfoService

    For remote-initiated channels (e.g. channels pushed *from the device*
    into a proxy slot), override :meth:`_acquire_channel`::

        class XCTestDriver(DtxService):
            SERVICE_CLASS = XCTestDriverInterface

            async def _acquire_channel(self):
                return await self.dtx.wait_for_proxied_service(
                    XCTestDriverInterface, remote=True, timeout=90.0
                )

    Multiple channels over the same connection — share the provider::

        async with TestManagerProvider(lockdown) as tm:
            async with IDEInterfaceChannel(tm) as ide:
                async with XCTestDriverChannel(tm) as driver:
                    ...

    Pass ``service=`` to inject a pre-opened
    :class:`~pymobiledevice3.dtx.DTXService` instance (the
    :class:`DtxService` wrapper does **not** own or close it)::

        raw = await provider.dtx.open_channel(DeviceInfoService)
        ch  = DeviceInfoChannel(provider, service=raw)
    """

    SERVICE_CLASS: ClassVar[type[_DTXService]]
    """The :class:`~pymobiledevice3.dtx.DTXService` subclass to
    instantiate when opening the channel.  **Must** be set by each subclass
    unless :meth:`_acquire_channel` is fully overridden."""

    CHANNEL_IDENTIFIER: ClassVar[Optional[str]] = None
    """Optional override for the channel identifier string.

    When ``None`` (the default) :attr:`SERVICE_CLASS.IDENTIFIER
    <pymobiledevice3.dtx.DTXService.IDENTIFIER>` is used.
    Set this when you want to open a channel by a raw string rather than by
    class lookup, or when you need a different identifier than the one baked
    into :attr:`SERVICE_CLASS`.
    """

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
        The return type matches :attr:`SERVICE_CLASS` (the ``_SVC_T`` type parameter).
        """
        if self._service is None:
            raise RuntimeError("not connected — use `async with` or await connect()")
        return self._service

    # ------------------------------------------------------------------
    # Hook
    # ------------------------------------------------------------------

    async def _acquire_channel(self) -> _SVC_T:
        """Open and return the DTX channel for this service.

        Default implementation opens the channel by :attr:`SERVICE_CLASS`
        (or by :attr:`CHANNEL_IDENTIFIER` when set).

        Override for non-standard acquisition, for example to wait for a
        remote-initiated proxied channel::

            async def _acquire_channel(self):
                return await self.dtx.wait_for_proxied_service(
                    XCTestDriverInterface, remote=True, timeout=90.0
                )

        Or to wait for any service pushed by the device::

            async def _acquire_channel(self):
                return await self.dtx.wait_for_service(
                    MyRemoteService, timeout=30.0
                )
        """
        if self.CHANNEL_IDENTIFIER is not None:
            return await self._provider.dtx.open_channel(self.CHANNEL_IDENTIFIER)
        return await self._provider.dtx.open_channel(self.SERVICE_CLASS)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Ensure the provider is connected and acquire the channel.

        No-op if already connected.  Connects the provider if it has not been
        connected yet (safe to call even when the provider is already live).
        """
        await self._provider.connect()
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
