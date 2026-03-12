"""DTXContext — scoped key/value store threading state through a DTX connection.

See :class:`DTXContext` and :data:`DTX_GLOBAL_CTX`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, Optional, overload

if TYPE_CHECKING:
    from .channel import DTXChannel
    from .connection import DTXConnection
    from .service import DTXProxyService


class DTXContext(dict):
    """Scoped context dictionary threading state through a DTX connection.

    Entries in a child context shadow those in the parent; missing keys fall
    through to the parent chain.  Three scopes exist in practice:

    - **global** — ``DTX_GLOBAL_CTX``: process-wide defaults (e.g. logging config).
    - **connection** — ``conn.ctx``: per-connection state (e.g. session IDs,
      ``xctest_config``).  Parent is global.
    - **channel** — created by :class:`DTXConnection` for each channel open.
      Always has ``"channel"`` set to the :class:`DTXChannel` instance and
      ``"connection"`` set to the owning :class:`DTXConnection` (inherited
      from the parent connection context).  When a :class:`DTXProxyService`
      is being constructed, also has ``"dtxproxy"`` set to the proxy instance
      (signals :class:`DTXService.__init__` to skip channel-callback wiring).

    Usage::

        conn.ctx["xctest_config"] = xctest_config
        conn.ctx["runner_ready"] = asyncio.Event()

        # Inside a service handler:
        cfg = self._ctx["xctest_config"]
        self._ctx["runner_ready"].set()

        # Reach up to the proxy from a proxied service:
        proxy = self._ctx["dtxproxy"]
        await proxy.remote_service.invoke("ping")
    """

    def __init__(self, parent: Optional[DTXContext] = None, **initial: Any) -> None:
        super().__init__(**initial)
        self._parent = parent

    def __missing__(self, key: str) -> Any:
        if self._parent is not None:
            return self._parent[key]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        """Like ``dict.get`` but walks the parent chain (``dict.get`` bypasses ``__missing__``)."""
        try:
            return self[key]
        except KeyError:
            return default

    @overload
    def __getitem__(self, key: Literal["channel"]) -> DTXChannel: ...
    @overload
    def __getitem__(self, key: Literal["connection"]) -> DTXConnection: ...
    @overload
    def __getitem__(self, key: Literal["dtxproxy"]) -> DTXProxyService: ...
    @overload
    def __getitem__(self, key: str) -> Any: ...
    def __getitem__(self, key: str) -> Any:
        return super().__getitem__(key)

    def child(self, **overrides: Any) -> DTXContext:
        """Return a new child context with *overrides* pre-populated."""
        return DTXContext(parent=self, **overrides)


#: Process-wide default context.  Set entries here to make them available
#: across all connections without explicit per-connection assignment.
DTX_GLOBAL_CTX: DTXContext = DTXContext()
