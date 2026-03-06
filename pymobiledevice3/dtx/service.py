"""DTX service base classes and decorator machinery.

This module provides the building blocks for implementing DTX-based services:

Decorators
~~~~~~~~~~
- :func:`dtx_method`           — declare an outgoing ObjC selector call
- :func:`dtx_on_invoke`        — handle a specific incoming selector
- :func:`dtx_on_data`          — handle incoming DATA frames
- :func:`dtx_on_notification`  — handle incoming server-initiated OBJECT/OK
- :func:`dtx_on_dispatch`      — catch-all for unmatched incoming selectors

Service classes
~~~~~~~~~~~~~~~
- :class:`DTXService`          — base class; wires decorators to channel callbacks
- :class:`DTXDynamicService`   — dynamic proxy via ``__getattr__``
- :class:`DTXControlService`   — channel-0 capability handshake and channel lifecycle
- :class:`DTXProxyService`     — bidirectional proxy bridging two services on one channel

Helper functions
~~~~~~~~~~~~~~~~
- :func:`_python_name_to_objc_selector` — convert Python ``foo_bar_`` → ``foo:bar:``
- :func:`_objc_selector_to_python_name` — convert ``foo:bar:`` → ``foo_bar_``
- :func:`_apply_primitive_coercions`    — coerce args via annotation-driven type hints
"""

from __future__ import annotations

import inspect
import logging
import re
import sys
from collections.abc import Awaitable
from functools import partial, wraps
from typing import Any, Callable, ClassVar, TypeVar, get_type_hints

from .channel import DTXChannel
from .context import DTX_GLOBAL_CTX, DTXContext  # noqa: F401 — re-exported for back-compat
from .ns_types import NSError
from .primitives import PInt32, _PrimitiveBase

logger = logging.getLogger(__name__)

_MISSING = object()  # sentinel for missing attribute values in __init_subclass__
DTX_SERVICE_T = TypeVar("DTX_SERVICE_T", bound="DTXService")

__namespace_re__ = re.compile(r"^_([A-Z_]+_)+")


# ---------------------------------------------------------------------------
# Selector name conversion
# ---------------------------------------------------------------------------


def _objc_selector_to_python_name(selector: str) -> str:
    """Convert an Objective-C selector name to a valid Python attribute name.

    Colons in the selector become underscores::

        "foo:bar:" → "foo_bar_"
    """
    if not selector:
        return selector

    return selector.replace(":", "_")


def _python_name_to_objc_selector(name: str) -> str:
    """Convert a Python attribute name to an Objective-C selector name.

    Underscores become colons.  A leading ``_UPPERCASE_`` namespace prefix is
    preserved and its suffix is converted independently::

        "_XCT_logMessage_" → "_XCT_logMessage:"
        "runningProcesses"  → "runningProcesses"
        "setConfig_"        → "setConfig:"
    """
    if not name:
        return name

    match = __namespace_re__.match(name)
    if match:
        prefix = match.group(0)
        suffix = name[len(prefix) :]
        return prefix + suffix.replace("_", ":")
    elif name.startswith("_"):
        return "_" + name[1:].replace("_", ":")

    return name.replace("_", ":")


# ---------------------------------------------------------------------------
# Primitive coercion helper
# ---------------------------------------------------------------------------


def _apply_primitive_coercions(args: tuple, coercions: tuple) -> tuple:
    """Coerce *args* to :class:`_PrimitiveBase` types driven by annotation hints.

    For each position *i*, if ``coercions[i]`` is a :class:`_PrimitiveBase`
    subclass **and** the argument is not already a :class:`_PrimitiveBase`
    instance (so an explicit call-site type always wins), the argument is wrapped
    with the annotated type.

    Positions beyond ``len(coercions)`` are left unchanged (supports variadic
    calls).
    """
    result = list(args)
    for i, coerce_type in enumerate(coercions):
        if i >= len(result):
            break
        if coerce_type is None:
            continue
        if not (isinstance(coerce_type, type) and issubclass(coerce_type, _PrimitiveBase)):
            continue
        if not isinstance(result[i], _PrimitiveBase):
            result[i] = coerce_type(result[i])
    return tuple(result)


# ---------------------------------------------------------------------------
# DTX service decorators
# ---------------------------------------------------------------------------


def dtx_method(selector_or_fn=None, /, **invoke_kwargs):
    """Decorator for outgoing DTX calls.

    Replaces the decorated method body with a ``self._channel.invoke(...)``
    call generated at class-creation time.  Type annotations on stub
    parameters drive automatic :class:`_PrimitiveBase` coercion.

    Usage::

        @dtx_method                             # infer selector from Python name
        @dtx_method("setConfig:")               # explicit ObjC selector
        @dtx_method(expects_reply=False)        # inferred selector + fixed kwargs
        @dtx_method("setConfig:", expects_reply=False)
    """
    if callable(selector_or_fn):
        selector_or_fn._dtx_method = (None, {})
        return selector_or_fn
    selector = selector_or_fn

    def decorator(fn):
        fn._dtx_method = (selector, invoke_kwargs)
        return fn

    return decorator


def dtx_on_invoke(selector_or_fn=None, /):
    """Register a method as the handler for a specific incoming ObjC selector.

    Usage::

        @dtx_on_invoke                          # infer selector from Python name
        @dtx_on_invoke("_XCT_logMessage:")      # explicit selector
    """
    if callable(selector_or_fn):
        selector_or_fn._dtx_on_invoke = None  # None → infer from method name
        return selector_or_fn
    selector = selector_or_fn

    def decorator(fn):
        fn._dtx_on_invoke = selector
        return fn

    return decorator


def dtx_on_data(fn):
    """Register a method as the handler for incoming DATA frames (raw bytes)."""
    fn._dtx_on_data = True
    return fn


def dtx_on_notification(fn):
    """Register a method as the handler for incoming OBJECT/OK notifications."""
    fn._dtx_on_notification = True
    return fn


def dtx_on_dispatch(fn):
    """Catch-all handler for incoming DISPATCH messages not matched by
    :func:`dtx_on_invoke`.  The method receives ``(selector: str, *args)``."""
    fn._dtx_on_dispatch = True
    return fn


# ---------------------------------------------------------------------------
# DTXService
# ---------------------------------------------------------------------------


class DTXService:
    """Base class for services communicating over a DTX channel.

    Subclasses declare outgoing calls with :func:`dtx_method` and incoming
    message handlers with :func:`dtx_on_invoke`, :func:`dtx_on_data`,
    :func:`dtx_on_notification`, or :func:`dtx_on_dispatch`.
    Channel callbacks are wired automatically in :meth:`__init__`.
    """

    IDENTIFIER: ClassVar[str | None] = None

    # Class-level routing tables, populated by __init_subclass__.
    _dtx_dispatch: ClassVar[dict[str, str]] = {}
    _dtx_data_handler: ClassVar[str | None] = None
    _dtx_notification_handler: ClassVar[str | None] = None
    _dtx_dispatch_handler: ClassVar[str | None] = None

    def __init_subclass__(cls, **kw: Any) -> None:
        super().__init_subclass__(**kw)

        new_dispatch: dict[str, str] = {}
        new_data_handler: str | None = None
        new_notification_handler: str | None = None
        new_dispatch_handler: str | None = None

        for name, val in vars(cls).items():
            if not callable(val):
                continue

            if (sel := getattr(val, "_dtx_on_invoke", _MISSING)) is not _MISSING:
                new_dispatch[sel if sel is not None else _python_name_to_objc_selector(name)] = name

            if getattr(val, "_dtx_on_data", False):
                new_data_handler = name

            if getattr(val, "_dtx_on_notification", False):
                new_notification_handler = name

            if getattr(val, "_dtx_on_dispatch", False):
                new_dispatch_handler = name

            if (dtx := getattr(val, "_dtx_method", None)) is not None:
                method_selector, invoke_kwargs = dtx
                if method_selector is None:
                    method_selector = _python_name_to_objc_selector(name)
                _sel, _kw = method_selector, dict(invoke_kwargs)

                # Build per-parameter coercion table from type annotations.
                # With 'from __future__ import annotations' all annotations are
                # strings; get_type_hints() evaluates them in the module's namespace.
                _coercions: tuple = ()
                try:
                    module_globals = vars(sys.modules.get(cls.__module__, None) or {})
                    hints = get_type_hints(val, globalns=module_globals)
                    params = [p for p in inspect.signature(val).parameters if p != "self"]
                    _coercions = tuple(hints.get(p) for p in params)
                except Exception:
                    pass

                async def _wrapper(
                    self,
                    *args: Any,
                    __sel: str = _sel,
                    __kw: dict = _kw,
                    __coercions: tuple = _coercions,
                    **extra: Any,
                ) -> Any:
                    if __coercions:
                        args = _apply_primitive_coercions(args, __coercions)
                    return await self._channel.invoke(__sel, *args, **{**__kw, **extra})

                wraps(val)(_wrapper)
                _wrapper.__qualname__ = f"{cls.__qualname__}.{name}"
                setattr(cls, name, _wrapper)

        # Merge dispatch table: base entries first so child selectors override.
        merged: dict[str, str] = {}
        for base in reversed(cls.__mro__[1:]):
            if base is object:
                continue
            merged.update(base.__dict__.get("_dtx_dispatch", {}))
        merged.update(new_dispatch)
        cls._dtx_dispatch = merged

        # Only override handler attrs on classes that explicitly declare them
        # (uninherited ClassVar on DTXService provides None as the default).
        if new_data_handler is not None:
            cls._dtx_data_handler = new_data_handler
        if new_notification_handler is not None:
            cls._dtx_notification_handler = new_notification_handler
        if new_dispatch_handler is not None:
            cls._dtx_dispatch_handler = new_dispatch_handler

    def __init__(self, ctx: DTXContext) -> None:
        self._ctx = ctx
        self._channel: DTXChannel = ctx["channel"]

        # Skip wiring when instantiated as a sub-service of a DTXProxyService.
        # The proxy itself handles dispatch routing via its own @dtx_on_dispatch.
        if "dtxproxy" in ctx:
            return

        cls = type(self)
        if cls._dtx_dispatch or cls._dtx_dispatch_handler is not None:
            self._channel.on_invoke = self.__on_dispatch__

        data_handler = cls._dtx_data_handler
        if data_handler is not None:
            self._channel.on_data = getattr(self, data_handler)

        notif_handler = cls._dtx_notification_handler
        if notif_handler is not None:
            self._channel.on_notification = getattr(self, notif_handler)

    async def __aenter__(self: DTX_SERVICE_T) -> DTX_SERVICE_T:
        await self._channel.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self._channel.__aexit__(exc_type, exc_val, exc_tb)

    async def __on_dispatch__(self, selector: str, args: list[Any]) -> Any:
        """Route an incoming DISPATCH to the right @dtx_on_invoke handler,
        falling back to the @dtx_on_dispatch catch-all."""
        method_name = type(self)._dtx_dispatch.get(selector)
        if method_name is not None:
            return await getattr(self, method_name)(*args)
        dispatch_handler = type(self)._dtx_dispatch_handler
        if dispatch_handler is not None:
            return await getattr(self, dispatch_handler)(selector, *args)
        logger.warning(
            "%s: received dispatch for selector %r with no registered handler",
            type(self).__name__,
            selector,
        )
        return NSError.create_doesnt_respond_to_selector(selector)

    # ------------------------------------------------------------------
    # Convenience wrappers for outgoing messages (usable without @dtx_method)
    # ------------------------------------------------------------------

    async def send_notification(self, notification: Any, *aux_args: Any, expects_reply: bool = False) -> Any:
        """Send a server-bound notification and optionally await the reply."""
        return await self._channel.notify(notification, *aux_args, expects_reply=expects_reply)

    async def do_invoke(self, method: str, *args: Any, expects_reply: bool = True) -> Any:
        """Invoke *method* on this channel and return the decoded reply value.

        This is a high-level convenience wrapper around :meth:`DTXChannel.invoke`.
        Prefer :func:`dtx_method`-decorated stubs for typed outgoing calls; use
        this method for ad-hoc or dynamic selector invocations.
        """
        return await self._channel.invoke(method, *args, expects_reply=expects_reply)

    async def send_data(self, data: bytes, *aux_args: Any, expects_reply: bool = False) -> Any:
        """Send a DATA frame and optionally await the reply."""
        return await self._channel.send_data(data, *aux_args, expects_reply=expects_reply)


class DTXDynamicService(DTXService):
    """Dynamic proxy that maps attribute access to DTX selector calls.

    Any attribute not defined as a class method is routed through
    ``__getattr__`` → ``__getitem__`` → ``do_invoke``, translating Python
    names to ObjC selectors via :func:`_python_name_to_objc_selector`.

    Incoming dispatches are handled by :meth:`__dynamic_dispatch__`: for each
    incoming selector the corresponding Python-mangled name is looked up in
    subclass ``__dict__`` entries above ``DTXDynamicService`` in the MRO.
    """

    def __getitem__(self, item: str) -> Callable[..., Awaitable[Any]]:
        """Return a coroutine factory that invokes the given ObjC selector."""
        return partial(self.do_invoke, item)

    def __getattr__(self, name: str) -> Callable[..., Awaitable[Any]]:
        """Translate a Python attribute name to an ObjC selector and return a callable."""
        return self[_python_name_to_objc_selector(name)]

    @dtx_on_dispatch
    async def __dynamic_dispatch__(self, selector: str, *args: Any) -> Any:
        method = _objc_selector_to_python_name(selector)
        for cls in type(self).__mro__:
            if cls is DTXDynamicService:
                break
            if method in cls.__dict__:
                attr = getattr(self, method)
                if not callable(attr):
                    logger.warning(
                        "%s: dispatch for %r (method %r) is not callable",
                        type(self).__name__,
                        selector,
                        method,
                    )
                    return NSError.create_doesnt_respond_to_selector(selector)
                if inspect.iscoroutinefunction(attr):
                    return await attr(*args)
                return attr(*args)
        logger.warning(
            "%s: dispatch for %r (method %r) is not implemented",
            type(self).__name__,
            selector,
            method,
        )
        return NSError.create_doesnt_respond_to_selector(selector)


class DTXControlService(DTXService):
    """Service for DTX channel 0: capability handshake and channel lifecycle.

    Uses :func:`dtx_method` for the three outgoing control calls and
    :func:`dtx_on_invoke` for the three peer-initiated dispatches.
    Annotation-driven coercion (:class:`PInt32`) ensures channel codes are
    sent as INT32 without manual :class:`PInt32` wrapping.
    """

    # ------------------------------------------------------------------
    # Outgoing
    # ------------------------------------------------------------------

    @dtx_method("_notifyOfPublishedCapabilities:", expects_reply=False)
    async def notify_capabilities(self, capabilities: dict) -> None:
        """Announce our capability dictionary to the peer."""

    @dtx_method("_requestChannelWithCode:identifier:")
    async def request_channel(self, channel_code: PInt32, identifier: str) -> None:
        """Ask the peer to open the named service channel with the given code."""

    @dtx_method("_channelCanceled:")
    async def cancel_channel(self, channel_code: PInt32) -> None:
        """Tell the peer to cancel the channel with the given code."""

    # ------------------------------------------------------------------
    # Incoming
    # ------------------------------------------------------------------

    @dtx_on_invoke("_notifyOfPublishedCapabilities:")
    async def _recv_capabilities(self, capabilities: dict) -> None:
        await self._ctx["connection"]._on_capabilities_received(capabilities)

    @dtx_on_invoke("_requestChannelWithCode:identifier:")
    async def _recv_channel_request(self, code: int, identifier: str) -> str | None:
        return await self._ctx["connection"]._on_channel_request(code, identifier)

    @dtx_on_invoke("_channelCanceled:")
    async def _recv_channel_cancelled(self, code: int) -> None:
        await self._ctx["connection"]._on_channel_cancelled(code)


class DTXProxyService(DTXService):
    """Bidirectional proxy that bridges two :class:`DTXService` instances on one channel.

    Incoming dispatches are forwarded to *local_service*; outgoing calls
    (``send_notification``, ``do_invoke``, ``send_data``) are forwarded to
    *remote_service*.

    Sub-services are assigned via the :attr:`local_service` and
    :attr:`remote_service` property setters, which also wire the channel
    callbacks.  Sub-services receive a child context with ``"dtxproxy"`` set
    to this proxy instance so their ``__init__`` skips callback wiring and
    they can reach their counterpart via ``self._ctx["dtxproxy"].remote_service``.

    Usage::

        proxy = DTXProxyService(ctx)
        proxy.local_service = IDEInterface(ctx.child(dtxproxy=proxy))
        proxy.remote_service = DaemonInterface(ctx.child(dtxproxy=proxy))
    """

    def __init__(self, ctx: DTXContext) -> None:
        super().__init__(ctx)
        self._local_service: DTXService | None = None
        self._remote_service: DTXService | None = None

    @property
    def local_service(self) -> DTXService:
        """The service that receives incoming dispatches from the remote end."""
        if self._local_service is None:
            raise AttributeError("local_service has not been assigned yet")
        return self._local_service

    @local_service.setter
    def local_service(self, svc: DTXService) -> None:
        self._local_service = svc
        # Wire the channel's dispatch/data callbacks to this proxy's handlers,
        # which delegate to the local service.  Re-wire on every assignment so
        # the proxy always reflects the current local service.
        cls = type(self)
        if cls._dtx_dispatch or cls._dtx_dispatch_handler is not None:
            self._channel.on_invoke = self.__on_dispatch__
        data_handler = cls._dtx_data_handler
        if data_handler is not None:
            self._channel.on_data = getattr(self, data_handler)

    @property
    def remote_service(self) -> DTXService:
        """The service whose channel methods are used for outgoing calls."""
        if self._remote_service is None:
            raise AttributeError("remote_service has not been assigned yet")
        return self._remote_service

    @remote_service.setter
    def remote_service(self, svc: DTXService) -> None:
        self._remote_service = svc
        notif_handler = type(self)._dtx_notification_handler
        if notif_handler is not None:
            self._channel.on_notification = getattr(self, notif_handler)

    @dtx_on_dispatch
    async def __proxy_dispatch__(self, selector: str, *args: Any) -> Any:
        return await self.local_service.__on_dispatch__(selector, list(args))

    @dtx_on_data
    async def __proxy_data__(self, data: bytes) -> Any:
        handler = type(self.local_service)._dtx_data_handler
        if handler:
            return await getattr(self.local_service, handler)(data)
        return None

    @dtx_on_notification
    async def __proxy_notification__(self, notification: Any) -> Any:
        handler = type(self.remote_service)._dtx_notification_handler
        if handler:
            return await getattr(self.remote_service, handler)(notification)
        return None

    async def send_notification(self, notification: Any, *aux_args: Any, expects_reply: bool = False) -> Any:
        """Forward a notification through the remote service."""
        return await self.remote_service.send_notification(notification, *aux_args, expects_reply=expects_reply)

    async def do_invoke(self, method: str, *args: Any, expects_reply: bool = True) -> Any:
        """Forward a selector invocation through the remote service."""
        return await self.remote_service.do_invoke(method, *args, expects_reply=expects_reply)

    async def send_data(self, data: bytes, *aux_args: Any, expects_reply: bool = False) -> Any:
        """Forward a DATA frame through the remote service."""
        return await self.remote_service.send_data(data, *aux_args, expects_reply=expects_reply)
