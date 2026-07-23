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
- :class:`NSMutableArray`
- :class:`NSMutableData`
- :class:`NSMutableString`
- :class:`DTTapMessage`
- :class:`NSDate`
"""

from __future__ import annotations

import datetime
import os
import uuid
from typing import Any, Optional, cast

from bpylist2 import archiver

# ---------------------------------------------------------------------------
# NS archive helpers
# ---------------------------------------------------------------------------


def patch_class_hierarchy(
    archive_obj: archiver.ArchivingObject,
    class_name: str,
    hierarchy: list[str],
) -> None:
    """Overwrite the '$classes' list for *class_name* in the live archive."""
    a = cast(Any, archive_obj._archiver)  # type: ignore[attr-defined]
    uid = a.class_map.get(class_name)
    if uid is not None:
        a.objects[uid.data]["$classes"] = hierarchy


class DTTapMessage:
    """Proxy for all ``DTTapMessage`` subclasses from the device diagnostics tap."""

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> Any:
        """Decode an archived DTTapMessage by extracting its embedded plist."""
        return cast(Any, archive_obj.decode("DTTapMessagePlist"))


class NSNull:
    """Proxy for Objective-C ``NSNull``."""

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> None:
        """Decode an archived NSNull — always returns ``None``."""
        return None


class NSError:
    """Wraps an Objective-C NSError object received from the remote DTX peer."""

    def __init__(self, code: int, domain: str, user_info: Optional[dict[str, Any]] = None):
        self.code: int = code
        self.domain: str = domain
        self.user_info: Optional[dict[str, Any]] = user_info

    def encode_archive(self, archive_obj: archiver.ArchivingObject) -> None:
        """Encode this NSError into an NSKeyedArchive object."""
        ao = cast(Any, archive_obj)
        ao.encode("NSDomain", self.domain)
        ao.encode("NSCode", self.code)
        ao.encode("NSUserInfo", self.user_info)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> NSError:
        """Decode an NSKeyedArchive object into an :class:`NSError` instance."""
        domain = cast(Any, archive_obj.decode("NSDomain"))
        code = cast(Any, archive_obj.decode("NSCode"))
        user_info = cast(Any, archive_obj.decode("NSUserInfo"))
        assert (
            (user_info is None or isinstance(user_info, dict)) and isinstance(domain, str) and isinstance(code, int)
        ), (
            f"Invalid NSError archive: domain={domain!r} code={code!r} user_info={user_info!r}, archive_obj={archive_obj!r}"
        )
        return NSError(code, domain, cast(Any, user_info))

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
        ao = cast(Any, archive_obj)
        ao.encode("NS.uuidbytes", self.bytes)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> NSUUID:
        """Decode an NSKeyedArchive object into an :class:`NSUUID` instance."""
        return NSUUID(bytes=cast(Any, archive_obj.decode("NS.uuidbytes")))


class NSURL:
    """Proxy for Objective-C ``NSURL``."""

    def __init__(self, base: Any, relative: Any):
        self.base = base
        self.relative = relative

    def encode_archive(self, archive_obj: archiver.ArchivingObject) -> None:
        """Encode this NSURL into an NSKeyedArchive object."""
        ao = cast(Any, archive_obj)
        ao.encode("NS.base", self.base)
        ao.encode("NS.relative", self.relative)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> NSURL:
        """Decode an NSKeyedArchive object into an :class:`NSURL` instance."""
        return NSURL(archive_obj.decode("NS.base"), archive_obj.decode("NS.relative"))


class NSValue:
    """Proxy for Objective-C ``NSValue`` — decodes the embedded rect value."""

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> Any:
        """Decode an NSKeyedArchive object into the underlying NSValue data."""
        return cast(Any, archive_obj.decode("NS.rectval"))


class NSMutableArray(list[Any]):
    """List subclass that preserves NSMutableArray NSKeyedArchive encoding.

    bpylist2 normally encodes Python ``list`` as NSArray.  Some private DVT
    APIs require NSMutableArray on the wire, while decode paths still expect
    Foundation arrays to behave like ordinary Python lists.
    """

    def encode_archive(self, archive_obj: archiver.ArchivingObject) -> None:
        a = archive_obj._archiver  # type: ignore[attr-defined]
        archive_obj._archive_obj["NS.objects"] = [a.archive(item) for item in self]  # type: ignore[attr-defined]
        patch_class_hierarchy(archive_obj, "NSMutableArray", ["NSMutableArray", "NSArray", "NSObject"])

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> NSMutableArray:
        raw = cast(list[Any], archive_obj.decode("NS.objects") or [])
        return NSMutableArray([archive_obj.decode_index(item) for item in raw])


class NSMutableData:
    """Proxy for Objective-C ``NSMutableData``."""

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> Any:
        """Decode an NSKeyedArchive object into the underlying bytes data."""
        return cast(Any, archive_obj.decode("NS.data"))


class NSMutableString:
    """Proxy for Objective-C ``NSMutableString``."""

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject) -> Any:
        """Decode an NSKeyedArchive object into the underlying string."""
        return cast(Any, archive_obj.decode("NS.string"))


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
        t = cast(Any, archive_obj.decode("NS.time"))
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
    "NSMutableArray": NSMutableArray,
    "NSMutableData": NSMutableData,
    "NSMutableString": NSMutableString,
    "NSDate": NSDate,
})

archiver.ARCHIVE_CLASS_MAP[NSMutableArray] = "NSMutableArray"  # type: ignore[index]
_archive_cls: Any = archiver.Archive
_archive_cls.inline_types = list({*_archive_cls.inline_types, bytes})
