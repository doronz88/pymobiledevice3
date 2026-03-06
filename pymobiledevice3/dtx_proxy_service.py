import sys
from typing import Any, ClassVar, Generic, Optional, TypeVar

from pymobiledevice3.dtx.service import DTXDynamicService as _DTXDynamicService
from pymobiledevice3.dtx.service import DTXProxyService as _DTXProxyService
from pymobiledevice3.dtx.service import DTXService as _DTXService
from pymobiledevice3.dtx_service import DtxService

if sys.version_info >= (3, 13):
    LOCAL_SVC_T = TypeVar("LOCAL_SVC_T", bound=_DTXService, default=_DTXDynamicService)
    REMOTE_SVC_T = TypeVar("REMOTE_SVC_T", bound=_DTXService, default=_DTXDynamicService)
else:
    LOCAL_SVC_T = TypeVar("LOCAL_SVC_T", bound=_DTXService)
    REMOTE_SVC_T = TypeVar("REMOTE_SVC_T", bound=_DTXService)


class DtxProxyService(DtxService[_DTXProxyService], Generic[LOCAL_SVC_T, REMOTE_SVC_T]):
    """Bidirectional proxy that bridges two :class:`DTXService` instances on one channel."""

    CHANNEL_IDENTIFIER: ClassVar[Optional[str]] = None
    """The raw channel identifier string to open for this proxy.  Must follow the format
    ``dtxproxy:LocalServiceIdentifier:RemoteServiceIdentifier``.  Can be omitted when
    both type parameters are concrete :class:`~pymobiledevice3.dtx.DTXService` subclasses
    with an ``IDENTIFIER`` — it will be auto-generated."""

    _inferred_local_service_class: ClassVar[Optional[type[_DTXService]]] = None
    """The local service class inferred from the ``LOCAL_SVC_T`` type parameter."""

    _inferred_remote_service_class: ClassVar[Optional[type[_DTXService]]] = None
    """The remote service class inferred from the ``REMOTE_SVC_T`` type parameter."""

    _local_service: Optional[LOCAL_SVC_T] = None
    """The service instance for incoming dispatches from the remote peer."""
    _remote_service: Optional[REMOTE_SVC_T] = None
    """The service instance for outgoing calls to the remote peer."""

    def __init_subclass__(cls, **kw: Any) -> None:
        super().__init_subclass__(**kw)

        # DtxService.__init_subclass__ (called via super() above) may have
        # inherited _inferred_service_class = _DTXProxyService from this class.
        # Reset it: proxy subclasses open their channel by CHANNEL_IDENTIFIER,
        # not by a single service class.  _acquire_channel in DtxService will
        # call open_channel(CHANNEL_IDENTIFIER) without a class arg, letting
        # the registry wire the two sub-services properly.
        cls._inferred_service_class = None

        # Reset proxy-specific inferred classes so we don't inherit from a
        # parent DtxProxyService subclass.
        cls._inferred_local_service_class = None
        cls._inferred_remote_service_class = None

        # Use base.__origin__ (PEP 560, Python 3.7+) to locate the
        # DtxProxyService[A, B] parameterization precisely.
        for base in getattr(cls, "__orig_bases__", ()):
            if getattr(base, "__origin__", None) is DtxProxyService:
                args = getattr(base, "__args__", ())
                if (
                    len(args) == 2
                    and isinstance(args[0], type)
                    and issubclass(args[0], _DTXService)
                    and isinstance(args[1], type)
                    and issubclass(args[1], _DTXService)
                ):
                    cls._inferred_local_service_class = args[0]
                    cls._inferred_remote_service_class = args[1]
                break

        # Auto-generate CHANNEL_IDENTIFIER from the type parameters if not set explicitly.
        if cls.CHANNEL_IDENTIFIER is None:
            local = cls._inferred_local_service_class
            remote = cls._inferred_remote_service_class
            if local is not None and remote is not None:
                cls.CHANNEL_IDENTIFIER = f"dtxproxy:{local.IDENTIFIER}:{remote.IDENTIFIER}"
            else:
                raise TypeError(
                    f"{cls.__name__} must define CHANNEL_IDENTIFIER or specify concrete type "
                    "parameters, e.g. DtxProxyService[LocalService, RemoteService]"
                )

        if not cls.CHANNEL_IDENTIFIER.startswith("dtxproxy:"):
            raise TypeError(f"{cls.__name__}.CHANNEL_IDENTIFIER must start with 'dtxproxy:'")

    async def connect(self) -> None:
        await self._provider.connect()
        if self._inferred_local_service_class is not None:
            self._provider.dtx.register_service(self._inferred_local_service_class)
        if self._inferred_remote_service_class is not None:
            self._provider.dtx.register_service(self._inferred_remote_service_class)
        if self._service is not None:
            return
        # _acquire_channel delegates to DtxService._acquire_channel which calls
        # open_channel(CHANNEL_IDENTIFIER) — no class arg — so the connection
        # uses the just-registered sub-services from the registry.
        self._service = await self._acquire_channel()
        # Unwrap the low-level DTXProxyService's sub-service instances.
        self._local_service = self._service.local_service
        self._remote_service = self._service.remote_service

    @property
    def local_service(self) -> LOCAL_SVC_T:
        """The active :class:`~pymobiledevice3.dtx.DTXService` local end of the channel.

        Raises :exc:`RuntimeError` if :meth:`connect` has not been called yet.
        The return type matches the ``LOCAL_SVC_T`` type parameter.
        """
        if self._local_service is None:
            raise RuntimeError("not connected — use `async with` or await connect()")
        return self._local_service

    @property
    def remote_service(self) -> REMOTE_SVC_T:
        """The active :class:`~pymobiledevice3.dtx.DTXService` remote end of the channel.

        Raises :exc:`RuntimeError` if :meth:`connect` has not been called yet.
        The return type matches the ``REMOTE_SVC_T`` type parameter.
        """
        if self._remote_service is None:
            raise RuntimeError("not connected — use `async with` or await connect()")
        return self._remote_service
