import dataclasses
import plistlib
import uuid
from typing import Any, Optional, cast

from pymobiledevice3.exceptions import InstallCoordinationError
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcUInt64Type

#: Both version gates are validated by the daemon; a request missing either is silently dropped and
#: the connection is torn down without any reply.
REQUEST_VERSION = 1
PROTOCOL_VERSION = 1

REQUEST_TYPE_INSTALL = 1
REQUEST_TYPE_REVERT_STASH = 2
REQUEST_TYPE_UNINSTALL = 3
REQUEST_TYPE_QUERY = 4

#: CoreFoundation's marker for an NSURL encoded into an XPC dictionary. The daemon rejects a plain
#: string where it expects a URL, so URLs must be sent in this form.
CFURL_MAGIC = uuid.UUID("C3853DCC-9776-4114-B6C1-FD9F51944A6D")


def encode_url(url: str) -> dict[str, Any]:
    """Encode *url* the way CoreFoundation serializes an NSURL into an XPC dictionary."""
    return {
        "com.apple.CFURL.magic": CFURL_MAGIC,
        "com.apple.CFURL.base": None,
        "com.apple.CFURL.string": url,
    }


def decode_url(value: Any) -> Optional[str]:
    """Extract the string from a CoreFoundation-encoded NSURL, or ``None`` if it is not one."""
    if isinstance(value, dict):
        url: Optional[str] = cast(dict[str, Any], value).get("com.apple.CFURL.string")
        return url
    return None


def _describe_error_data(error_data: bytes) -> str:
    """Best-effort human-readable message out of an archived NSError.

    ``ErrorData`` is an ``NSKeyedArchiver`` archive of an ``NSError``. Rather than registering
    classes for a full unarchive, pull the longest string out of ``$objects``, which in practice is
    the localized description.
    """
    try:
        archive = plistlib.loads(error_data)
        strings = [obj for obj in archive.get("$objects", []) if isinstance(obj, str) and " " in obj]
        if strings:
            return max(strings, key=len)
    except Exception:
        pass
    return f"<undecodable NSError, {len(error_data)} bytes>"


@dataclasses.dataclass
class InstallRecord:
    """The LaunchServices install record the daemon holds for an installed application."""

    db_uuid: str
    db_sequence: int
    install_path: Optional[str]
    persistent_identifier: bytes


class InstallCoordinationProxyService(RemoteService):
    """
    Query the install-coordination proxy (``com.apple.remote.installcoordination_proxy``).

    Unlike most RemoteXPC services this one does not use XPC request/reply correlation: the daemon
    answers by sending fresh messages on the connection, so replies are read off the stream. Every
    request must carry ``RequestVersion`` and ``ProtocolVersion``; if either is missing or wrong the
    daemon cancels the connection without answering.

    Only the read-only ``Query`` request is implemented. The daemon also exposes ``Install``
    (which streams its payload over an out-of-band XPC file transfer), ``Uninstall`` and
    ``RevertStash``.

    Requires an iOS 17+ RSD tunnel. Use as an async context manager.
    """

    SERVICE_NAME = "com.apple.remote.installcoordination_proxy"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def query(self, bundle_identifier: str) -> InstallRecord:
        """
        Look up the install record for an installed application.

        :param bundle_identifier: bundle identifier to look up, e.g. ``com.apple.Preferences``.
        :raises InstallCoordinationError: if the application is unknown or the daemon reported a failure.
        """
        await self.service.send_request({
            "RequestVersion": XpcUInt64Type(REQUEST_VERSION),
            "ProtocolVersion": XpcUInt64Type(PROTOCOL_VERSION),
            "RequestType": XpcUInt64Type(REQUEST_TYPE_QUERY),
            "BundleID": bundle_identifier,
        })
        response = await self.service.receive_response()
        if not response.get("Success"):
            error_data = response.get("ErrorData")
            detail = _describe_error_data(error_data) if isinstance(error_data, bytes) else "no error detail"
            raise InstallCoordinationError(f"query failed for {bundle_identifier}: {detail}")
        return InstallRecord(
            db_uuid=response["DBUUID"],
            db_sequence=response["DBSequence"],
            install_path=decode_url(response.get("InstallPath")),
            persistent_identifier=response["PersistentIdentifier"],
        )
