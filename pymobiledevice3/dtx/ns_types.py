"""NSKeyedArchive-compatible Objective-C type wrappers for DTX.

This module defines the Python proxy classes that :mod:`bpylist2.archiver`
uses when deserialising NSKeyedArchive payloads received from a DTX peer.
All classes are registered with the archiver at import time via
``archiver.update_class_map(...)`` so no explicit registration call is
needed by callers.

Exported classes
----------------
- :class:`NSNull`
- :class:`NSError`
- :class:`NSUUID`
- :class:`NSURL`
- :class:`NSValue`
- :class:`NSMutableData`
- :class:`NSMutableString`
- :class:`DTTapMessage`
- :class:`NSDate`
"""

from __future__ import annotations

import datetime
import os
import uuid
from typing import Any, Optional

from bpylist2 import archiver

# ---------------------------------------------------------------------------
# NS archive helpers
# ---------------------------------------------------------------------------


class DTTapMessage:
    """Proxy for all ``DTTapMessage`` subclasses from the device diagnostics tap."""

    @staticmethod
    def decode_archive(archive_obj) -> Any:
        """Decode an archived DTTapMessage by extracting its embedded plist."""
        return archive_obj.decode("DTTapMessagePlist")


class NSNull:
    """Proxy for Objective-C ``NSNull``."""

    @staticmethod
    def decode_archive(archive_obj) -> None:
        """Decode an archived NSNull — always returns ``None``."""
        return None


class NSError:
    """Wraps an Objective-C NSError object received from the remote DTX peer."""

    def __init__(self, code: int, domain: str, user_info: Optional[dict] = None):
        self.code: int = code
        self.domain: str = domain
        self.user_info: Optional[dict] = user_info

    def encode_archive(self, archive_obj: archiver.ArchivingObject) -> None:
        """Encode this NSError into an NSKeyedArchive object."""
        archive_obj.encode("NSDomain", self.domain)
        archive_obj.encode("NSCode", self.code)
        archive_obj.encode("NSUserInfo", self.user_info)

    @staticmethod
    def decode_archive(archive_obj) -> NSError:
        """Decode an NSKeyedArchive object into an :class:`NSError` instance."""
        domain = archive_obj.decode("NSDomain")
        code = archive_obj.decode("NSCode")
        user_info = archive_obj.decode("NSUserInfo")
        assert (
            (user_info is None or isinstance(user_info, dict)) and isinstance(domain, str) and isinstance(code, int)
        ), (
            f"Invalid NSError archive: domain={domain!r} code={code!r} user_info={user_info!r}, archive_obj={archive_obj!r}"
        )
        return NSError(code, domain, user_info)

    @staticmethod
    def create_doesnt_respond_to_selector(selector: str) -> NSError:
        """Create an NSError indicating that a selector is unrecognised."""
        return NSError(
            1,
            "DTXMessage",
            {"NSLocalizedDescription": f"Unable to invoke {selector!r} - it does not respond to the selector"},
        )

    @staticmethod
    def create_from_dispatch_exception(selector: str, exc: Exception) -> NSError:
        """Create an NSError wrapping an exception raised during selector dispatch."""
        return NSError(1, "DTXMessage", {"NSLocalizedDescription": f"In invocation of method {selector!r}: {exc!r}"})


class NSUUID(uuid.UUID):
    """Proxy for Objective-C ``NSUUID`` — a subclass of :class:`uuid.UUID`."""

    @staticmethod
    def uuid4() -> NSUUID:
        """Generate a random version-4 NSUUID."""
        return NSUUID(bytes=os.urandom(16))

    def encode_archive(self, archive_obj: archiver.ArchivingObject) -> None:
        """Encode this NSUUID into an NSKeyedArchive object."""
        archive_obj.encode("NS.uuidbytes", self.bytes)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> NSUUID:
        """Decode an NSKeyedArchive object into an :class:`NSUUID` instance."""
        return NSUUID(bytes=archive_obj.decode("NS.uuidbytes"))


class NSURL:
    """Proxy for Objective-C ``NSURL``."""

    def __init__(self, base, relative):
        self.base = base
        self.relative = relative

    def encode_archive(self, archive_obj: archiver.ArchivingObject) -> None:
        """Encode this NSURL into an NSKeyedArchive object."""
        archive_obj.encode("NS.base", self.base)
        archive_obj.encode("NS.relative", self.relative)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> NSURL:
        """Decode an NSKeyedArchive object into an :class:`NSURL` instance."""
        return NSURL(archive_obj.decode("NS.base"), archive_obj.decode("NS.relative"))


class NSValue:
    """Proxy for Objective-C ``NSValue`` — decodes the embedded rect value."""

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> Any:
        """Decode an NSKeyedArchive object into the underlying NSValue data."""
        return archive_obj.decode("NS.rectval")


class NSMutableData:
    """Proxy for Objective-C ``NSMutableData``."""

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> Any:
        """Decode an NSKeyedArchive object into the underlying bytes data."""
        return archive_obj.decode("NS.data")


class NSMutableString:
    """Proxy for Objective-C ``NSMutableString``."""

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> Any:
        """Decode an NSKeyedArchive object into the underlying string."""
        return archive_obj.decode("NS.string")


class NSDate:
    """Proxy for Objective-C ``NSDate``.

    Stores the raw Core Data timestamp (seconds since 2001-01-01 00:00:00 UTC).
    """

    # 2001-01-01T00:00:00 UTC expressed as a Unix timestamp
    _COCOA_EPOCH_UNIX: float = 978307200.0

    def __init__(self, timestamp: float):
        self.timestamp: float = timestamp

    @property
    def utc(self) -> datetime.datetime:
        """Return the date as a UTC :class:`~datetime.datetime`."""
        return datetime.datetime.fromtimestamp(self.timestamp + self._COCOA_EPOCH_UNIX, tz=datetime.timezone.utc)

    def __repr__(self) -> str:
        return f"NSDate({self.utc.isoformat()})"

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> NSDate:
        """Decode an NSKeyedArchive NSDate object."""
        t = archive_obj.decode("NS.time")
        return NSDate(float(t) if t is not None else 0.0)


# ---------------------------------------------------------------------------
# Archiver registration  (runs at import time)
# ---------------------------------------------------------------------------

archiver.update_class_map({
    "DTSysmonTapMessage": DTTapMessage,
    "DTTapHeartbeatMessage": DTTapMessage,
    "DTTapStatusMessage": DTTapMessage,
    "DTKTraceTapMessage": DTTapMessage,
    "DTActivityTraceTapMessage": DTTapMessage,
    "DTTapMessage": DTTapMessage,
    "NSNull": NSNull,
    "NSError": NSError,
    "NSUUID": NSUUID,
    "NSURL": NSURL,
    "NSValue": NSValue,
    "NSMutableData": NSMutableData,
    "NSMutableString": NSMutableString,
    "NSDate": NSDate,
})

archiver.Archive.inline_types = list({*archiver.Archive.inline_types, bytes})
