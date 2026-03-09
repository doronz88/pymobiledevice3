from .ns_types import NSError


class DTXProtocolError(Exception):
    """Raised when the remote DTX stream violates the protocol invariants."""


class DTXNSCodingError(Exception):
    """Raised when NSCoding (de)serialization fails for a message payload or auxiliary arguments."""


class DTXNsError(Exception):
    """Raised when the remote service returns an NSError object."""

    def __init__(self, error: NSError) -> None:
        self.error = error
        super().__init__(f"{error.domain} (code {error.code}, user_info={error.user_info})")
