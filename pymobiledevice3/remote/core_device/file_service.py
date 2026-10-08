import asyncio
import dataclasses
import json
import os
import struct
import time
import uuid
from collections.abc import AsyncGenerator
from enum import Enum, IntEnum
from typing import Any, Optional, Union

from pymobiledevice3.exceptions import CoreDeviceError
from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type

# Capability tags the control service advertises in the RSD handshake. These are NOT invoke()
# feature identifiers: the control service rejects the CoreDevice.featureIdentifier envelope with
# "The command provided by the client is not valid" (com.apple.dt.remoteservices.error 11014,
# verified on-device) and only speaks its Cmd-keyed session protocol below.
FEATURE_LIST_FILES = "com.apple.coredevice.feature.listFiles"
FEATURE_TRANSFER_FILES = "com.apple.coredevice.feature.transferFiles"
FEATURE_FILE_SYSTEM_OPERATION = "com.apple.coredevice.feature.filesystemoperation"
FEATURE_MONITOR_FILE_CHANGES = "com.apple.coredevice.feature.monitorfilechanges"

#: Largest piece of a file sent or requested in one message.
_FILE_CHUNK_SIZE = 512 * 1024


class Domain(IntEnum):
    APP_DATA_CONTAINER = 1
    APP_GROUP_DATA_CONTAINER = 2
    TEMPORARY = 3
    SYSTEM_CRASH_LOGS = 5

    @classmethod
    def from_name(cls, name: "DomainName") -> "Domain":
        return cls[name.name]


class DomainName(str, Enum):
    """Human-readable names for `Domain` (member names mirror it); resolve with `Domain.from_name()`."""

    APP_DATA_CONTAINER = "appDataContainer"
    APP_GROUP_DATA_CONTAINER = "appGroupDataContainer"
    TEMPORARY = "temporary"
    SYSTEM_CRASH_LOGS = "systemCrashLogs"


@dataclasses.dataclass(frozen=True)
class FileChangeEvent:
    """A change the device reported under a monitored location."""

    #: ``created``, ``modified``, ``removed`` or ``renamed``. These follow the device's FSEvents
    #: stream: changes made in quick succession arrive coalesced, and a rename reports the new name.
    event_type: str
    #: Path of the item, relative to the domain's root.
    relative_path: str
    domain: Union[Domain, int]
    #: The app or group identifier the domain was opened with, when the device reports one.
    domain_identifier: Optional[str] = None


class FileServiceService(CoreDeviceService):
    """
    Read, write and watch files in one of the device's file-service domains.

    A session covers one domain: an app's data container, an app group container (both named by
    ``identifier``), the temporary directory or the system crash logs. Paths are relative to it.

    Always close the service (or use ``async with``). When a client disappears with a session still
    open, the device's ``dtfileserviced`` stops answering new requests until it is restarted.
    """

    CTRL_SERVICE_NAME = "com.apple.coredevice.fileservice.control"

    def __init__(self, rsd: RemoteServiceDiscoveryService, domain: Domain, identifier: str = "") -> None:
        super().__init__(rsd, self.CTRL_SERVICE_NAME)
        self.domain: Domain = domain
        self.session: Optional[str] = None
        self.identifier = identifier

    async def connect(self) -> None:
        await super().connect()
        response = await self.send_receive_request({
            "Cmd": "CreateSession",
            "Domain": XpcUInt64Type(self.domain),
            "Identifier": self.identifier,
            "Session": "",
            "User": "mobile",
        })
        self.session = response["NewSessionID"]

    async def retrieve_directory_list(self, path: str = ".") -> AsyncGenerator[list[str], None]:
        self.rsd.require_feature(self.CTRL_SERVICE_NAME, FEATURE_LIST_FILES)
        return (
            await self.send_receive_request({
                "Cmd": "RetrieveDirectoryList",
                "MessageUUID": str(uuid.uuid4()),
                "Path": path,
                "SessionID": self.session,
            })
        )["FileList"]

    async def retrieve_file(self, path: str = ".") -> bytes:
        self.rsd.require_feature(self.CTRL_SERVICE_NAME, FEATURE_TRANSFER_FILES)
        response = await self.send_receive_request({"Cmd": "RetrieveFile", "Path": path, "SessionID": self.session})
        data_service = self.rsd.get_service_port("com.apple.coredevice.fileservice.data")
        # Route through the RSD's dialer (set by the userspace tunnel to relay through its
        # in-process stack); falls back to the stdlib default for the kernel-tunnel path.
        open_connection = self.rsd.open_connection or asyncio.open_connection
        reader, writer = await open_connection(self.service.address[0], data_service)
        writer.write(b"rwb!FILE" + struct.pack(">QQQQ", response["Response"], 0, response["NewFileID"], 0))
        await writer.drain()
        await reader.readexactly(0x24)
        return await reader.readexactly(struct.unpack(">I", await reader.readexactly(4))[0])

    async def propose_empty_file(
        self,
        path: str = ".",
        file_permissions: int = 0o644,
        uid: int = 501,
        gid: int = 501,
        creation_time: float = time.time(),
        last_modification_time: float = time.time(),
    ) -> None:
        """Request to write an empty file at given path."""
        # Proposing a file is the write direction of the file-transfer flow.
        self.rsd.require_feature(self.CTRL_SERVICE_NAME, FEATURE_TRANSFER_FILES)
        await self.send_receive_request({
            "Cmd": "ProposeEmptyFile",
            "FileCreationTime": XpcInt64Type(creation_time),
            "FileLastModificationTime": XpcInt64Type(last_modification_time),
            "FilePermissions": XpcInt64Type(file_permissions),
            "FileOwnerUserID": XpcInt64Type(uid),
            "FileOwnerGroupID": XpcInt64Type(gid),
            "Path": path,
            "SessionID": self.session,
        })

    async def file_system_operation(self, operation_type: str, **arguments: Any) -> dict[str, Any]:
        """
        Perform one ``FileSystemOperation`` and return its reply.

        This is the primitive behind the file and directory methods below; use it for the operations
        they do not wrap (directory handles, extended attributes).

        :param operation_type: e.g. ``CreateDirectory`` or ``GetExtendedAttribute``.
        :param arguments: the operation's arguments, sent alongside it.
        :raises CoreDeviceError: if the device fails the operation.
        """
        self.rsd.require_feature(self.CTRL_SERVICE_NAME, FEATURE_FILE_SYSTEM_OPERATION)
        return await self.send_receive_request({
            "Cmd": "FileSystemOperation",
            "OperationType": operation_type,
            "SessionID": self.session,
            **arguments,
        })

    async def create_directory(self, path: str) -> None:
        """Create a directory."""
        await self.file_system_operation("CreateDirectory", Path=path)

    async def remove_directory(self, path: str) -> None:
        """Remove an empty directory."""
        await self.file_system_operation("RemoveDirectory", Path=path)

    async def remove_file(self, path: str) -> None:
        """Remove a file or a symbolic link."""
        await self.file_system_operation("RemoveFile", Path=path)

    async def rename(self, old_path: str, new_path: str) -> None:
        """Rename or move an item within the domain."""
        await self.file_system_operation("Rename", OldPath=old_path, NewPath=new_path)

    async def create_symbolic_link(self, path: str, target_path: str) -> None:
        """Create a symbolic link at ``path`` pointing to ``target_path``."""
        await self.file_system_operation("CreateSymbolicLink", Path=path, TargetPath=target_path)

    async def read_symbolic_link(self, path: str) -> str:
        """Get the target of a symbolic link."""
        return (await self.file_system_operation("ReadSymbolicLink", Path=path))["TargetPath"]

    async def get_real_path(self, path: str = ".") -> str:
        """Resolve a path to its absolute location on the device."""
        return (await self.file_system_operation("GetRealPath", Path=path))["RealPath"]

    async def get_attributes(self, path: str, follow_symlinks: bool = True) -> dict[str, Any]:
        """
        Get an item's attributes.

        :returns: a dict with ``fileType`` (``regular``, ``directory``, ``symbolicLink``...),
            ``size``, ``permissions``, ``uid``, ``gid``, ``inode``, ``linkCount``, ``flags`` and the
            ``creationTime``, ``modificationTime`` and ``accessTime`` timestamps, in seconds since
            2001-01-01.
        """
        response = await self.file_system_operation("GetAttributes", Path=path, FollowSymlinks=follow_symlinks)
        return json.loads(response["Attributes"])

    async def set_attributes(self, path: str, **attributes: Any) -> None:
        """
        Change an item's attributes.

        :param attributes: the attributes to change, named as `get_attributes` reports them, e.g.
            ``permissions=0o644``.
        """
        await self.file_system_operation("SetAttributes", Path=path, Attributes=json.dumps(attributes).encode())

    async def open_file(self, path: str, flags: int = os.O_RDONLY, mode: int = 0o644) -> int:
        """
        Open a file on the device.

        :param flags: ``open(2)`` flags, e.g. ``os.O_CREAT | os.O_WRONLY``.
        :param mode: permissions of the file if it gets created.
        :returns: a descriptor for `read_file`, `write_file`, `truncate_file` and `close_file`.
        """
        response = await self.file_system_operation(
            "OpenFile", Path=path, Flags=XpcInt64Type(flags), Mode=XpcUInt64Type(mode)
        )
        return response["FileDescriptor"]

    async def read_file(self, file_descriptor: int, offset: int, length: int) -> bytes:
        """Read up to ``length`` bytes at ``offset``; fewer are returned at the end of the file."""
        response = await self.file_system_operation(
            "ReadFile",
            FileDescriptor=XpcInt64Type(file_descriptor),
            Offset=XpcUInt64Type(offset),
            Length=XpcInt64Type(length),
        )
        return response["FileData"]

    async def write_file(self, file_descriptor: int, offset: int, data: bytes) -> None:
        """Write ``data`` at ``offset``."""
        await self.file_system_operation(
            "WriteFile", FileDescriptor=XpcInt64Type(file_descriptor), Offset=XpcUInt64Type(offset), FileData=data
        )

    async def truncate_file(self, file_descriptor: int, length: int) -> None:
        """Cut or extend an open file to ``length`` bytes."""
        await self.file_system_operation(
            "TruncateFile", FileDescriptor=XpcInt64Type(file_descriptor), Length=XpcInt64Type(length)
        )

    async def close_file(self, file_descriptor: int) -> None:
        """Close a descriptor returned by `open_file`."""
        await self.file_system_operation("CloseFile", FileDescriptor=XpcInt64Type(file_descriptor))

    async def get_file_contents(self, path: str) -> bytes:
        """Read a whole file through file-system operations."""
        file_descriptor = await self.open_file(path)
        try:
            contents = b""
            while True:
                chunk = await self.read_file(file_descriptor, len(contents), _FILE_CHUNK_SIZE)
                if not chunk:
                    return contents
                contents += chunk
        finally:
            await self.close_file(file_descriptor)

    async def set_file_contents(self, path: str, data: bytes, mode: int = 0o644) -> None:
        """Create or replace a file with ``data``."""
        file_descriptor = await self.open_file(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
        try:
            for offset in range(0, len(data), _FILE_CHUNK_SIZE):
                await self.write_file(file_descriptor, offset, data[offset : offset + _FILE_CHUNK_SIZE])
        finally:
            await self.close_file(file_descriptor)

    async def monitor(self, relative_paths: Optional[list[str]] = None) -> AsyncGenerator[FileChangeEvent, None]:
        """
        Watch this session's domain and yield the changes the device reports. Requires iOS 27.

        The device keeps watching until the connection closes, so use an instance of its own for
        this: other requests on the same connection would have their replies mixed with the events.

        :param relative_paths: paths to watch, relative to the domain's root. The whole domain by default.
        """
        self.rsd.require_feature(self.CTRL_SERVICE_NAME, FEATURE_MONITOR_FILE_CHANGES)
        await self.send_receive_request({
            "Cmd": "MonitorFileEvents",
            "MessageUUID": str(uuid.uuid4()).upper(),
            "MonitoringConfig": {
                "domains": [XpcUInt64Type(self.domain)],
                "domainIdentifiers": [self.identifier],
                "relativePaths": relative_paths if relative_paths is not None else ["."],
            },
            "SessionID": self.session,
        })
        while True:
            message = await self.service.receive_response()
            for event in message.get("MonitoringEvents", []):
                domain: Union[Domain, int] = event["domain"]
                if domain in Domain._value2member_map_:
                    domain = Domain(domain)
                yield FileChangeEvent(
                    event_type=event["eventType"],
                    relative_path=event["relativePath"],
                    domain=domain,
                    domain_identifier=event.get("domainIdentifier"),
                )

    async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
        response = await self.service.send_receive_request(request)
        encoded_error = response.get("EncodedError")
        if encoded_error is not None:
            localized_description = response.get("LocalizedDescription") or encoded_error.get("NSLocalizedDescription")
            if localized_description is not None:
                raise CoreDeviceError(localized_description)
            raise CoreDeviceError(encoded_error)
        return response
