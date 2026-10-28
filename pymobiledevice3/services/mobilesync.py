from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any, Optional, cast

from pymobiledevice3.exceptions import ConnectionTerminatedError, ProtocolError, PyMobileDevice3Exception
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.device_link import DeviceLink, DLMessage
from pymobiledevice3.services.lockdown_service import LockdownService

EMPTY_PARAMETER_STRING = "___EmptyParameterString___"
ENTITY_NAME_KEY = "com.apple.syncservices.RecordEntityName"

# Every data class iOS still ships a data source for (MobileSync.framework), mapped to the storage version
# the host announces; the device replies with its own. com.apple.Notes is refused ("No Data Store").
DATA_CLASS_VERSIONS = {
    "com.apple.Contacts": 106,
    "com.apple.Calendars": 107,
    "com.apple.Bookmarks": 102,
    "com.apple.MailAccounts": 102,
}


class MobileSyncError(PyMobileDevice3Exception):
    pass


class MobileSyncService(LockdownService):
    """
    Read and change the device's contacts, calendars, Safari bookmarks and mail accounts via the
    ``com.apple.mobilesync`` service, the iTunes-era sync protocol (DeviceLink transport).

    `get_all_records` only reads; `push_changes` adds, modifies or deletes records.
    """

    SERVICE_NAME = "com.apple.mobilesync"
    RSD_SERVICE_NAME = "com.apple.mobilesync.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown)
        self._device_link: Optional[DeviceLink] = None

    async def _get_device_link(self) -> DeviceLink:
        if self._device_link is None:
            await self.connect()
            assert self._service is not None
            device_link = DeviceLink(self._service, Path("."))
            await device_link.version_exchange()
            self._device_link = device_link
        return self._device_link

    async def _receive(self) -> DLMessage:
        assert self._device_link is not None
        message = await self._device_link.receive_message()
        if message[0] == "SDMessageCancelSession":
            raise MobileSyncError(f"The device cancelled the {message[1]} sync session: {message[2]}")
        return message

    async def get_all_records(self, data_class: str, data_class_version: Optional[int] = None) -> dict[str, Any]:
        """
        Fetch every record of a data class from the device.

        :param data_class: Data class to read, e.g. ``com.apple.Contacts`` (see `DATA_CLASS_VERSIONS`).
        :param data_class_version: Storage version to announce; defaults to the one in `DATA_CLASS_VERSIONS`.
        :returns: The records keyed by record identifier. Each record names its entity type under
            ``com.apple.syncservices.RecordEntityName``.
        :raises MobileSyncError: The device refused or cancelled the sync session.
        """
        async with self._session(data_class, data_class_version):
            # The device then waits for the host's changes; the session finishes without sending any.
            return await self._receive_device_changes(data_class, "SDMessageGetAllRecordsFromDevice")

    async def push_changes(
        self,
        data_class: str,
        changes: Mapping[str, Optional[Mapping[str, Any]]],
        data_class_version: Optional[int] = None,
    ) -> dict[str, str]:
        """
        Add, modify or delete records of a data class on the device.

        A key that is a device record identifier modifies that record; any other key adds a new record.
        A record names its entity type under ``com.apple.syncservices.RecordEntityName`` and uses the field
        names `get_all_records` returns.

        :param data_class: Data class to change, e.g. ``com.apple.Contacts``.
        :param changes: Records keyed by identifier; ``None`` deletes the record with that identifier.
        :param data_class_version: Storage version to announce; defaults to the one in `DATA_CLASS_VERSIONS`.
        :returns: The device identifiers of added records, keyed by the identifiers given in ``changes``.
        :raises MobileSyncError: The device refused, cancelled or failed to commit the changes.
        """
        async with self._session(data_class, data_class_version):
            # Only the device's changes since the last session are pulled, not every record.
            await self._receive_device_changes(data_class, "SDMessageGetChangesFromDevice")
            entity_names = sorted({record[ENTITY_NAME_KEY] for record in changes.values() if record is not None})
            await self.service.send_plist([
                "SDMessageProcessChanges",
                data_class,
                {
                    identifier: EMPTY_PARAMETER_STRING if record is None else dict(record)
                    for identifier, record in changes.items()
                },
                False,  # no more changes follow
                {
                    "SyncDeviceLinkEntityNamesKey": entity_names,
                    # ask the device to report the identifiers it assigns to added records
                    "SyncDeviceLinkAllRecordsOfPulledEntityTypeSentKey": True,
                },
            ])
            reply = await self._receive()
            if reply[0] != "SDMessageRemapRecordIdentifiers":
                raise ProtocolError(f"Unexpected reply to {data_class} changes: {reply}")
            return cast(dict[str, str], reply[2]) if isinstance(reply[2], dict) else {}

    @asynccontextmanager
    async def _session(self, data_class: str, data_class_version: Optional[int]) -> AsyncGenerator[None, None]:
        """
        Run one sync session of a data class: finish it on success, cancel it on an error so the connection
        can start another.
        """
        if data_class_version is None:
            data_class_version = DATA_CLASS_VERSIONS[data_class]
        await self._get_device_link()
        await self.service.send_plist([
            "SDMessageSyncDataClassWithDevice",
            data_class,
            "---",
            "pymobiledevice3",
            data_class_version,
            EMPTY_PARAMETER_STRING,
        ])
        reply = await self._receive()
        if reply[0] == "SDMessageRefuseToSyncDataClassWithComputer":
            raise MobileSyncError(f"The device refused to sync {data_class}: {reply[2]}")
        if reply[0] != "SDMessageSyncDataClassWithComputer":
            raise ProtocolError(f"Unexpected reply to a {data_class} sync request: {reply}")
        try:
            yield
        except MobileSyncError:
            # the device cancelled the session itself
            raise
        except Exception as e:
            with suppress(ConnectionTerminatedError):
                await self.service.send_plist(["SDMessageCancelSession", data_class, str(e)])
            raise
        await self.service.send_plist(["SDMessageFinishSessionOnDevice", data_class])
        reply = await self._receive()
        if reply[0] != "SDMessageDeviceFinishedSession":
            raise ProtocolError(f"Unexpected reply when finishing the {data_class} sync session: {reply}")

    async def _receive_device_changes(self, data_class: str, request: str) -> dict[str, Any]:
        """Request the device's records or changes and acknowledge them until it is ready for the host's."""
        records: dict[str, Any] = {}
        await self.service.send_plist([request, data_class])
        while True:
            message = await self._receive()
            if message[0] != "SDMessageProcessChanges":
                raise ProtocolError(f"Unexpected message while receiving {data_class} records: {message}")
            # an empty batch carries the empty-parameter string instead of a dict
            if isinstance(message[2], dict):
                records.update(cast(dict[str, Any], message[2]))
            await self.service.send_plist(["SDMessageAcknowledgeChangesFromDevice", data_class])
            # index 3 is "has more changes"
            if not message[3]:
                break
        reply = await self._receive()
        if reply[0] != "SDMessageDeviceReadyToReceiveChanges":
            raise ProtocolError(f"Unexpected message after receiving {data_class} records: {reply}")
        return records

    async def close(self) -> None:
        if self._device_link is not None and self._service is not None:
            with suppress(ConnectionTerminatedError):
                await self._device_link.disconnect()
        self._device_link = None
        await super().close()
