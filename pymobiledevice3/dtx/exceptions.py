import asyncio
import copy
import errno
from typing import Optional, TypeVar

from pymobiledevice3.exceptions import ConnectionTerminatedError

from .ns_types import NSError

E = TypeVar("E", bound=BaseException)


def copy_exception(exc: Optional[E]) -> Optional[E]:
    """Return a shallow copy of *exc* with its current ``__traceback__`` snapshotted.

    When a Future holds a reference to an exception and is later awaited,
    Python prepends new frames to ``exc.__traceback__`` in-place — before any
    ``except``/``suppress`` handler can act.  Passing the original exception
    object to ``aclose()`` and then calling ``wait_closed()`` (whose transport
    close-waiter may hold the same object) causes that traceback pollution to
    be visible when the exception is eventually re-raised by a consumer such as
    ``TapService.messages()``.

    This utility creates a fresh object of the same type so subsequent raises of
    the ORIGINAL object do not pollute this copy's ``__traceback__``.

    Returns *None* unchanged so call sites can pass ``exc_val`` directly without
    a ``None``-guard.
    """
    if exc is None:
        return None
    new_exc = copy.copy(exc)
    new_exc.__traceback__ = exc.__traceback__
    new_exc.__cause__ = exc.__cause__
    new_exc.__context__ = exc.__context__
    new_exc.__suppress_context__ = exc.__suppress_context__
    return new_exc  # type: ignore[return-value]


def get_root_exception(exc: BaseException) -> BaseException:
    """Recursively get the root cause of *exc*."""
    cause = exc.__cause__
    if cause is not None:
        return get_root_exception(cause)
    context = exc.__context__
    if context is not None:
        return get_root_exception(context)
    return exc


def is_connection_error(exc: BaseException) -> bool:
    """Return True if *exc* or any of its causes is a connection-related error."""
    root = get_root_exception(exc)
    if isinstance(
        root,
        (
            ConnectionTerminatedError,
            asyncio.IncompleteReadError,
            ConnectionResetError,
            BrokenPipeError,
            ConnectionError,
        ),
    ):
        return True
    return isinstance(root, OSError) and root.errno in (
        errno.ECONNRESET,
        errno.ENOTCONN,
        errno.EPIPE,
        errno.ECONNABORTED,
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ENETDOWN,
        errno.ENETUNREACH,
        errno.ETIMEDOUT,
    )


class DTXProtocolError(Exception):
    """Raised when the remote DTX stream violates the protocol invariants."""


class DTXNSCodingError(Exception):
    """Raised when NSCoding (de)serialization fails for a message payload or auxiliary arguments."""


class DTXNsError(Exception):
    """Raised when the remote service returns an NSError object."""

    def __init__(self, error: NSError) -> None:
        self.error = error
        super().__init__(f"{error.domain} (code {error.code}, user_info={error.user_info})")
