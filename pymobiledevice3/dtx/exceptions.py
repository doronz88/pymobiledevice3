import asyncio
import errno

from pymobiledevice3.exceptions import ConnectionTerminatedError

from .ns_types import NSError


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
