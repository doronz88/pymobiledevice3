"""DTX service provider — manages a :class:`DTXConnection` lifecycle.

:class:`DtxServiceProvider` is the DTX-layer counterpart of
:class:`~pymobiledevice3.services.lockdown_service.LockdownService`:

- :class:`~pymobiledevice3.lockdown_service_provider.LockdownServiceProvider`
  opens a :class:`~pymobiledevice3.service_connection.ServiceConnection` via
  ``start_lockdown_service()``.
- :class:`DtxServiceProvider` opens a
  :class:`~pymobiledevice3.dtx.DTXConnection` on top of that
  transport, performing the capability handshake and registering any
  pre-declared service classes.

Typical usage::

    class DvtProvider(DtxServiceProvider):
        SERVICE_NAME     = "com.apple.instruments.remoteserver.DVTSecureSocketProxy"
        RSD_SERVICE_NAME = "com.apple.instruments.dtservicehub"
        OLD_SERVICE_NAME = "com.apple.instruments.remoteserver"

    async with DvtProvider(lockdown) as provider:
        svc = await provider.dtx.open_channel(DeviceInfoService)
        procs = await svc.runningProcesses()

Pass an already-open :class:`~pymobiledevice3.dtx.DTXConnection`
via ``dtx=`` to share a transport across multiple callers without reopening
the underlying connection.
"""

from __future__ import annotations

import logging
import socket as _socket
from typing import Any, ClassVar, Optional

from packaging.version import Version
from typing_extensions import Self

from pymobiledevice3.dtx import DTXConnection, DTXService
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider


class DtxServiceProvider:
    """Manages the lifecycle of a :class:`DTXConnection` opened through a
    :class:`~pymobiledevice3.lockdown_service_provider.LockdownServiceProvider`.

    Subclasses declare the set of service names for each connection type and
    the :class:`~pymobiledevice3.dtx.DTXService` subclasses that
    should be registered for remote-initiated channels:

    .. code-block:: python

        class TestManagerProvider(DtxServiceProvider):
            SERVICE_NAME     = "com.apple.testmanagerd.lockdown.secure"
            RSD_SERVICE_NAME = "com.apple.dt.testmanagerd.remote"
            OLD_SERVICE_NAME = "com.apple.testmanagerd.lockdown"
            REGISTER_SERVICES = (
                XCTestManager_IDEInterface,
                XCTestManager_DaemonConnectionInterface,
                XCTestDriverInterface,
            )

    The :meth:`service_name_for` classmethod encapsulates the standard
    ``isinstance(provider, RemoteServiceDiscoveryService)`` / version check
    that is repeated across the codebase.  Subclasses may override it for
    non-standard selection logic.
    """

    SERVICE_NAME: ClassVar[str]
    RSD_SERVICE_NAME: ClassVar[Optional[str]] = None
    OLD_SERVICE_NAME: ClassVar[Optional[str]] = None
    REGISTER_SERVICES: ClassVar[tuple[type[DTXService], ...]] = ()

    # ------------------------------------------------------------------
    # Class-level helpers
    # ------------------------------------------------------------------

    @classmethod
    def service_name_for(cls, service_provider: LockdownServiceProvider) -> str:
        """Return the appropriate lockdown service name for *service_provider*.

        Default logic (mirrors the pattern used throughout the codebase):

        - :class:`~pymobiledevice3.remote.remote_service_discovery.RemoteServiceDiscoveryService`
          → :attr:`RSD_SERVICE_NAME` if set, otherwise :attr:`SERVICE_NAME`.
        - iOS < 14 over lockdown → :attr:`OLD_SERVICE_NAME` if set, otherwise
          :attr:`SERVICE_NAME`.
        - Everything else → :attr:`SERVICE_NAME`.

        Subclasses are free to override for non-standard selection logic.
        """
        from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

        if isinstance(service_provider, RemoteServiceDiscoveryService):
            return cls.RSD_SERVICE_NAME if cls.RSD_SERVICE_NAME is not None else cls.SERVICE_NAME
        if cls.OLD_SERVICE_NAME is not None and Version(service_provider.product_version).major < 14:
            return cls.OLD_SERVICE_NAME
        return cls.SERVICE_NAME

    @classmethod
    def _default_strip_ssl(cls, service_provider: LockdownServiceProvider) -> bool:
        """Return ``True`` when the SSL context must be stripped after negotiation.

        This is required for lockdown connections to the old pre-iOS 14 service
        names where the device gates DTX traffic behind a TLS handshake but
        expects raw bytes afterwards.  RSD connections never need it.
        """
        from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

        if isinstance(service_provider, RemoteServiceDiscoveryService):
            return False
        if cls.OLD_SERVICE_NAME is not None:
            return Version(service_provider.product_version).major < 14
        return False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __init__(
        self,
        lockdown: LockdownServiceProvider,
        strip_ssl: Optional[bool] = None,
        dtx: Optional[DTXConnection] = None,
    ) -> None:
        """
        :param lockdown: Device connection used to open the underlying service.
        :param strip_ssl: Override SSL-stripping behaviour.  ``None`` (default)
            delegates to :meth:`_default_strip_ssl`.
        :param dtx: Pre-built :class:`DTXConnection` to re-use.  When supplied
            the provider does **not** close the connection on exit (it does not
            own it).
        """
        self.lockdown = lockdown
        self._service_name = self.service_name_for(lockdown)
        self._strip_ssl = self._default_strip_ssl(lockdown) if strip_ssl is None else strip_ssl
        self._dtx: Optional[DTXConnection] = dtx
        self._owns_dtx: bool = dtx is None
        self.logger = logging.getLogger(self.__module__)

    @property
    def dtx(self) -> DTXConnection:
        """The active :class:`DTXConnection`.  Raises if not yet connected."""
        if self._dtx is None:
            raise RuntimeError("not connected — use `async with` or await connect()")
        return self._dtx

    async def connect(self) -> None:
        """Open the transport, perform the DTX handshake, and register services.

        No-op if already connected.
        """
        if self._dtx is not None:
            return
        self._dtx = await self._open_dtx_connection(self.lockdown, self._service_name, strip_ssl=self._strip_ssl)
        await self._dtx.connect()
        if self.REGISTER_SERVICES:
            self._dtx.register_services(*self.REGISTER_SERVICES)

    async def close(self) -> None:
        """Close the :class:`DTXConnection` if this provider owns it."""
        if self._owns_dtx and self._dtx is not None:
            await self._dtx.aclose()
            self._dtx = None

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    async def _open_dtx_connection(
        lockdown: LockdownServiceProvider,
        service_name: str,
        *,
        strip_ssl: bool = False,
    ) -> DTXConnection:
        """Open a raw connection to *service_name* and return an uninitialised
        :class:`DTXConnection` ready for :meth:`~DTXConnection.connect`.

        When *strip_ssl* is ``True`` the method performs a synchronous TLS
        handshake and then unwraps the SSL context so that the DTX framing
        runs over the plain TCP transport — required for
        ``com.apple.instruments.remoteserver`` and similar pre-iOS 14 services.
        """
        attr = await lockdown.get_service_connection_attributes(service_name, False)
        svc = await lockdown.create_service_connection(attr["Port"])
        await svc._ensure_started()

        if attr.get("EnableServiceSSL", False):
            with lockdown.ssl_file() as f:  # type: ignore[attr-defined]
                if strip_ssl:
                    svc.setblocking(True)
                    svc.ssl_start_sync(f)
                else:
                    await svc.ssl_start(f)

        if (
            strip_ssl
            and attr.get("EnableServiceSSL", False)
            and (svc.socket is not None and hasattr(svc.socket, "_sslobj"))
        ):
            raw_socket = getattr(svc.socket, "_sock", None)
            if raw_socket is None:
                raw_socket = _socket.socket(fileno=svc.socket.detach())
            else:
                svc.socket._sslobj = None
            svc.socket = raw_socket
            svc.reader = None
            svc.writer = None
            svc.socket.setblocking(False)
            await svc.start()

        return DTXConnection(svc.reader, svc.writer)
