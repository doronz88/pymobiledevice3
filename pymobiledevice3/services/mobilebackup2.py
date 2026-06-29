#!/usr/bin/env python3
import asyncio
import plistlib
import re
import shutil
import sqlite3
import tempfile
import uuid
from asyncio import IncompleteReadError
from collections.abc import Callable, Sequence
from contextlib import asynccontextmanager, closing, suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from pyiosbackup import Backup
from pyiosbackup.keybag import Keybag, encryption_key_struct
from pyiosbackup.manifest_plist import ManifestPlist

from pymobiledevice3.exceptions import (
    AfcException,
    AfcFileNotFoundError,
    BackupFilterPasswordRequiredError,
    LockdownError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AFC_LOCK_EX, AFC_LOCK_UN, AfcError, AfcService
from pymobiledevice3.services.device_link import DeviceLink
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.services.notification_proxy import NotificationProxyService
from pymobiledevice3.services.springboard import SpringBoardServicesService

SUPPORTED_VERSIONS = [2.0, 2.1]
ITUNES_FILES = [
    "ApertureAlbumPrefs",
    "IC-Info.sidb",
    "IC-Info.sidv",
    "PhotosFolderAlbums",
    "PhotosFolderName",
    "PhotosFolderPrefs",
    "VoiceMemos.plist",
    "iPhotoAlbumPrefs",
    "iTunesApplicationIDs",
    "iTunesPrefs",
    "iTunesPrefs.plist",
]
NP_SYNC_WILL_START = "com.apple.itunes-mobdev.syncWillStart"
NP_SYNC_DID_START = "com.apple.itunes-mobdev.syncDidStart"
NP_SYNC_LOCK_REQUEST = "com.apple.itunes-mobdev.syncLockRequest"
NP_SYNC_DID_FINISH = "com.apple.itunes-mobdev.syncDidFinish"
NP_SYNC_CANCEL_REQUEST = "com.apple.itunes-client.syncCancelRequest"
NP_SYNC_SUSPEND_REQUEST = "com.apple.itunes-client.syncSuspendRequest"
NP_SYNC_RESUME_REQUEST = "com.apple.itunes-client.syncResumeRequest"
NP_BACKUP_DOMAIN_CHANGED = "com.apple.mobile.backup.domain_changed"
NP_LOCAL_AUTH_PRESENTED = "com.apple.LocalAuthentication.ui.presented"
NP_LOCAL_AUTH_DISMISSED = "com.apple.LocalAuthentication.ui.dismissed"
BACKUP_OBSERVED_NOTIFICATIONS = (
    NP_SYNC_CANCEL_REQUEST,
    NP_SYNC_SUSPEND_REQUEST,
    NP_SYNC_RESUME_REQUEST,
    NP_BACKUP_DOMAIN_CHANGED,
    NP_LOCAL_AUTH_PRESENTED,
    NP_LOCAL_AUTH_DISMISSED,
)
BACKUP_METADATA_FILES = frozenset({
    "Info.plist",
    "Manifest.plist",
    "Manifest.db",
    "Manifest.db-shm",
    "Manifest.db-wal",
    "Status.plist",
})
INCREMENTAL_BACKUP_REQUIRED_FILES = ("Manifest.plist", "Manifest.db", "Status.plist")


@dataclass(frozen=True)
class BackupSelectionRule:
    """A preset rule selecting backup files by `domain` and `relative_path` (e.g. SMS, contacts)."""

    domain: str
    relative_path: str

    def matches_device_name(self, device_name: str) -> bool:
        return device_name in {
            f"{self.domain}/{self.relative_path}",
            f"{self.domain}-{self.relative_path}",
            self.relative_path,
        } or device_name.endswith(f"/{self.relative_path}")

    def matches_manifest_entry(self, domain: str, relative_path: str) -> bool:
        return self.domain == domain and self.relative_path == relative_path


@dataclass(frozen=True)
class BackupFile:
    """Identifies a single backup file passed to a filter callback; fields are populated according to context."""

    file_id: Optional[str] = None
    domain: Optional[str] = None
    relative_path: Optional[str] = None
    file_name: Optional[str] = None
    device_name: Optional[str] = None


BackupFilterCallback = Callable[[BackupFile], bool]


BACKUP_SELECTIONS = {
    "bookmarks": (
        BackupSelectionRule("HomeDomain", "Library/Safari/Bookmarks.db"),
        BackupSelectionRule("HomeDomain", "Library/Safari/Bookmarks.db-shm"),
        BackupSelectionRule("HomeDomain", "Library/Safari/Bookmarks.db-wal"),
    ),
    "call_history": (
        BackupSelectionRule("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata"),
        BackupSelectionRule("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata-shm"),
        BackupSelectionRule("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata-wal"),
    ),
    "contacts": (
        BackupSelectionRule("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb"),
        BackupSelectionRule("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb-shm"),
        BackupSelectionRule("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb-wal"),
    ),
    "sms": (BackupSelectionRule("HomeDomain", "Library/SMS/sms.db"),),
    "whatsapp": (
        BackupSelectionRule("AppDomain-net.whatsapp.WhatsApp", "Documents/ChatStorage.sqlite"),
        BackupSelectionRule("AppDomain-net.whatsapp.WhatsApp", "Documents/ChatStorage.sqlite-shm"),
        BackupSelectionRule("AppDomain-net.whatsapp.WhatsApp", "Documents/ChatStorage.sqlite-wal"),
        BackupSelectionRule("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite"),
        BackupSelectionRule("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite-shm"),
        BackupSelectionRule("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite-wal"),
    ),
}


class Mobilebackup2Service(LockdownService):
    """
    Client for the `com.apple.mobilebackup2` service, the iTunes/Finder-style device backup protocol.

    Drives full and incremental backups, restores, and the related operations (info, list,
    extract, unback, change password, erase device) over a `DeviceLink` channel. Backups can
    be filtered to a subset of files via a filter callback, and encrypted backups are
    supported (password required for filtering and restore). The right underlying service is
    selected automatically: `SERVICE_NAME` over classic lockdown, or `RSD_SERVICE_NAME` over
    RemoteXPC/RSD.

    Inherits async context manager support from `LockdownService`; use within an
    ``async with`` block to manage the underlying connection.
    """

    SERVICE_NAME = "com.apple.mobilebackup2"
    RSD_SERVICE_NAME = "com.apple.mobilebackup2.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME, include_escrow_bag=True)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME, include_escrow_bag=True)

    async def get_will_encrypt(self) -> bool:
        """
        Report whether the device is configured to encrypt its backups.

        :returns: True if backup encryption is enabled on the device, False otherwise (including
            when the value cannot be read).
        """
        try:
            will_encrypt = await self.lockdown.get_value("com.apple.mobile.backup", "WillEncrypt")
            return bool(will_encrypt)
        except LockdownError:
            return False

    async def backup(
        self,
        full: bool = True,
        backup_directory: Union[str, Path] = ".",
        progress_callback=lambda x: None,
        filter_callback: Optional[BackupFilterCallback] = None,
        password: str = "",
        unback: bool = False,
    ) -> None:
        """
        Back up the device into `backup_directory`/<device-udid>.

        :param full: Perform a full backup, discarding any previous incremental state. A full
            backup is also forced when a filter callback is given or when incremental metadata
            is missing.
        :param backup_directory: Directory the backup is written to (a per-device subdirectory
            is created under it).
        :param progress_callback: Called as the backup progresses with the completion
            percentage as its sole argument.
        :param filter_callback: Optional predicate deciding which backup files to keep; files
            it rejects are pruned after the backup completes.
        :param password: Backup password; required when filtering an encrypted backup.
        :param unback: When True, also unpack the completed backup locally using pyiosbackup.
        :raises BackupFilterPasswordRequiredError: If a filter callback is given without a
            password while the device encrypts backups.
        """
        backup_directory = Path(backup_directory)
        device_directory = backup_directory / self.lockdown.udid
        device_directory.mkdir(exist_ok=True, mode=0o755, parents=True)
        full = self._should_do_full_backup(full, device_directory, filter_callback)

        if filter_callback is not None and not password and await self.get_will_encrypt():
            raise BackupFilterPasswordRequiredError(
                "Backup filtering requires the backup password when encryption is enabled"
            )

        async with (
            self.device_link(backup_directory, filter_callback=filter_callback, password=password) as dl,
            NotificationProxyService(self.lockdown) as notification_proxy,
            AfcService(self.lockdown) as afc,
            self._backup_lock(afc, notification_proxy),
        ):
            await self._observe_backup_notifications(notification_proxy)
            notification_task = asyncio.create_task(self._log_backup_notifications(notification_proxy))
            # Initialize Info.plist
            try:
                info_plist = await self.init_mobile_backup_factory_info(afc)
                with open(device_directory / "Info.plist", "wb") as fd:
                    plistlib.dump(info_plist, fd)

                # Initialize Status.plist file if doesn't exist.
                status_path = device_directory / "Status.plist"
                current_date = datetime.now()
                current_date = current_date.replace(tzinfo=None)
                if full or not status_path.exists():
                    with open(device_directory / "Status.plist", "wb") as fd:
                        plistlib.dump(
                            {
                                "BackupState": "new",
                                "Date": current_date,
                                "IsFullBackup": full,
                                "Version": "3.3",
                                "SnapshotState": "finished",
                                "UUID": str(uuid.uuid4()).upper(),
                            },
                            fd,
                            fmt=plistlib.FMT_BINARY,
                        )

                # Create Manifest.plist if doesn't exist.
                manifest_path = device_directory / "Manifest.plist"
                if full:
                    manifest_path.unlink(missing_ok=True)
                (device_directory / "Manifest.plist").touch()

                await dl.send_process_message({"MessageName": "Backup", "TargetIdentifier": self.lockdown.udid})
                await dl.dl_loop(progress_callback)
                if filter_callback is not None:
                    self.prune_backup_directory(device_directory, filter_callback, password=password)
                if unback:
                    self.unback_with_pyiosbackup(device_directory, password=password)
            finally:
                notification_task.cancel()
                with suppress(asyncio.CancelledError):
                    await notification_task

    @classmethod
    def _should_do_full_backup(
        cls,
        full: bool,
        device_directory: Path,
        filter_callback: Optional[BackupFilterCallback] = None,
    ) -> bool:
        return full or filter_callback is not None or not cls._has_incremental_backup_metadata(device_directory)

    @staticmethod
    def _has_incremental_backup_metadata(device_directory: Path) -> bool:
        return all(
            (device_directory / filename).is_file() and (device_directory / filename).stat().st_size > 0
            for filename in INCREMENTAL_BACKUP_REQUIRED_FILES
        )

    async def _observe_backup_notifications(self, notification_proxy: NotificationProxyService) -> None:
        for notification in BACKUP_OBSERVED_NOTIFICATIONS:
            await notification_proxy.notify_register_dispatch(notification)

    async def _log_backup_notifications(self, notification_proxy: NotificationProxyService) -> None:
        async for event in notification_proxy.receive_notification():
            self._log_backup_notification(event)

    def _log_backup_notification(self, event: dict) -> None:
        name = event.get("Name")
        if name == NP_LOCAL_AUTH_PRESENTED:
            self.logger.warning("Please enter the device passcode to continue the backup")
        elif name == NP_LOCAL_AUTH_DISMISSED:
            self.logger.info("Device passcode prompt dismissed")
        elif name == NP_SYNC_CANCEL_REQUEST:
            self.logger.warning("User has cancelled the backup process on the device")
        else:
            self.logger.debug("Received backup notification: %s", event)

    async def restore(
        self,
        backup_directory=".",
        system: bool = False,
        reboot: bool = True,
        copy: bool = True,
        settings: bool = True,
        remove: bool = False,
        password: str = "",
        source: str = "",
        progress_callback=lambda x: None,
        skip_apps: bool = False,
    ):
        """
        Restore a previously created backup to the device.

        :param backup_directory: Path of the backup directory.
        :param system: Whether to restore system files.
        :param reboot: Reboot the device when done.
        :param copy: Create a copy of the backup folder before restoring.
        :param settings: Restore device settings.
        :param remove: Remove items on the device that aren't part of the restore.
        :param password: Password of the backup; required if the backup is encrypted.
        :param source: Identifier of the device whose backup is restored; defaults to the
            connected device's UDID.
        :param progress_callback: Called as the restore progresses with the completion
            percentage as its sole argument.
        :param skip_apps: Do not trigger re-installation of apps after the restore.
        """
        backup_directory = Path(backup_directory)
        source = source if source else self.lockdown.udid
        self._assert_backup_exists(backup_directory, source)

        async with (
            self.device_link(backup_directory) as dl,
            NotificationProxyService(self.lockdown) as notification_proxy,
            AfcService(self.lockdown) as afc,
            self._backup_lock(afc, notification_proxy),
        ):
            manifest_plist_path = backup_directory / source / "Manifest.plist"
            with open(manifest_plist_path, "rb") as fd:
                manifest = plistlib.load(fd)
            is_encrypted = manifest.get("IsEncrypted", False)
            options = {
                "RestoreShouldReboot": reboot,
                "RestoreDontCopyBackup": not copy,
                "RestorePreserveSettings": settings,
                "RestoreSystemFiles": system,
                "RemoveItemsNotRestored": remove,
            }
            if is_encrypted:
                if password:
                    options["Password"] = password
                else:
                    self.logger.error("Backup is encrypted, please supply password.")
                    return
            await dl.send_process_message({
                "MessageName": "Restore",
                "TargetIdentifier": self.lockdown.udid,
                "SourceIdentifier": source,
                "Options": options,
            })

            if not skip_apps:
                # Write /iTunesRestore/RestoreApplications.plist so that the device will start
                # restoring applications once the rest of the restore process is finished
                info_plist_path = backup_directory / source / "Info.plist"
                applications = plistlib.loads(info_plist_path.read_bytes()).get("Applications")
                if applications is not None:
                    await afc.makedirs("/iTunesRestore")
                    await afc.set_file_contents(
                        "/iTunesRestore/RestoreApplications.plist", plistlib.dumps(applications)
                    )

            await dl.dl_loop(progress_callback)

    async def info(self, backup_directory=".", source: str = "") -> str:
        """
        Get information about a backup.

        :param backup_directory: Path of the backup directory.
        :param source: Identifier of the device to get info about; defaults to the connected
            device's UDID.
        :returns: Information about the backup, as returned by the device.
        """
        backup_dir = Path(backup_directory)
        self._assert_backup_exists(backup_dir, source if source else self.lockdown.udid)
        async with self.device_link(backup_dir) as dl:
            message = {"MessageName": "Info", "TargetIdentifier": self.lockdown.udid}
            if source:
                message["SourceIdentifier"] = source
            await dl.send_process_message(message)
            result = await dl.dl_loop()
        return result

    async def list(self, backup_directory=".", source: str = "") -> str:
        """
        List the files in the last backup.

        :param backup_directory: Path of the backup directory.
        :param source: Identifier of the device to list; defaults to the connected device's UDID.
        :returns: The files and per-file metadata in CSV format.
        """
        backup_dir = Path(backup_directory)
        source = source if source else self.lockdown.udid
        self._assert_backup_exists(backup_dir, source)
        async with self.device_link(backup_dir) as dl:
            await dl.send_process_message({
                "MessageName": "List",
                "TargetIdentifier": self.lockdown.udid,
                "SourceIdentifier": source,
            })
            result = await dl.dl_loop()
        return result

    async def unback(self, backup_directory=".", password: str = "", source: str = "") -> None:
        """
        Unpack a complete backup into its original device file hierarchy.

        :param backup_directory: Path of the backup directory.
        :param password: Password of the backup; required if the backup is encrypted.
        :param source: Identifier of the device whose backup is unpacked; defaults to the
            connected device's UDID.
        """
        backup_dir = Path(backup_directory)
        self._assert_backup_exists(backup_dir, source if source else self.lockdown.udid)
        async with self.device_link(backup_dir) as dl:
            message = {"MessageName": "Unback", "TargetIdentifier": self.lockdown.udid}
            if source:
                message["SourceIdentifier"] = source
            if password:
                message["Password"] = password
            await dl.send_process_message(message)
            await dl.dl_loop()

    @staticmethod
    def unback_with_pyiosbackup(device_directory: Path, password: str = "") -> Path:
        """
        Unpack a local backup directory using pyiosbackup, on the host without the device.

        The output is written to a sibling directory named ``<device_directory>.unback``,
        replacing it if it already exists.

        :param device_directory: Path of the per-device backup directory to unpack.
        :param password: Password of the backup; required if the backup is encrypted.
        :returns: Path of the directory the backup was unpacked into.
        """
        output_directory = device_directory.with_name(f"{device_directory.name}.unback")
        if output_directory.exists():
            shutil.rmtree(output_directory)
        output_directory.mkdir(parents=True)
        Backup.from_path(device_directory, password).unback(output_directory)
        return output_directory

    async def extract(
        self, domain_name: str, relative_path: str, backup_directory=".", password: str = "", source: str = ""
    ) -> None:
        """
        Extract a single file from a previous backup.

        :param domain_name: The file's domain, e.g. SystemPreferencesDomain or HomeDomain.
        :param relative_path: Path of the file within the domain.
        :param backup_directory: Path of the backup directory.
        :param password: Password of the backup; required if the backup is encrypted.
        :param source: Identifier of the device to extract from; defaults to the connected
            device's UDID.
        """
        backup_dir = Path(backup_directory)
        self._assert_backup_exists(backup_dir, source if source else self.lockdown.udid)
        async with self.device_link(backup_dir) as dl:
            message = {
                "MessageName": "Extract",
                "TargetIdentifier": self.lockdown.udid,
                "DomainName": domain_name,
                "RelativePath": relative_path,
            }
            if source:
                message["SourceIdentifier"] = source
            if password:
                message["Password"] = password
            await dl.send_process_message(message)
            await dl.dl_loop()

    async def change_password(self, backup_directory=".", old: str = "", new: str = "") -> None:
        """
        Change, enable, or disable the device's backup encryption password.

        :param backup_directory: Path of the backup directory.
        :param old: Previous password. Omit when enabling backup encryption.
        :param new: New password. Omit when disabling backup encryption.
        """
        async with self.device_link(Path(backup_directory)) as dl:
            message = {"MessageName": "ChangePassword", "TargetIdentifier": self.lockdown.udid}
            if old:
                message["OldPassword"] = old
            if new:
                message["NewPassword"] = new
            await dl.send_process_message(message)
            await dl.dl_loop()

    async def erase_device(self, backup_directory=".") -> None:
        """
        Erase the device, restoring it to factory state.

        :param backup_directory: Path of the backup directory used for the device link channel.
        """
        with suppress(IncompleteReadError):
            async with self.device_link(Path(backup_directory)) as dl:
                await dl.send_process_message({"MessageName": "EraseDevice", "TargetIdentifier": self.lockdown.udid})
                await dl.dl_loop()

    async def version_exchange(self, dl: DeviceLink, local_versions=None) -> None:
        """
        Exchange protocol versions with the device and assert it supports one of ours.

        :param dl: An initialized device link channel.
        :param local_versions: Protocol versions supported by the host; defaults to
            `SUPPORTED_VERSIONS`.
        """
        if local_versions is None:
            local_versions = SUPPORTED_VERSIONS
        await dl.send_process_message({
            "MessageName": "Hello",
            "SupportedProtocolVersions": local_versions,
        })
        reply = await dl.receive_message()
        assert reply[0] == "DLMessageProcessMessage" and reply[1]["ErrorCode"] == 0
        assert reply[1]["ProtocolVersion"] in local_versions

    async def init_mobile_backup_factory_info(self, afc: AfcService):
        """
        Build the Info.plist dictionary describing the device for a new backup.

        Collects device identity values, the list of installed user apps (with their SINF and
        iTunes metadata where available), and the iTunes control files needed to make the
        backup restorable.

        :param afc: An open AFC service used to read the device's iTunes control files.
        :returns: The assembled Info.plist contents as a dictionary.
        """
        async with InstallationProxyService(self.lockdown) as ip, SpringBoardServicesService(self.lockdown) as sbs:
            root_node = self.lockdown.all_values
            itunes_settings = self.lockdown.all_values.get("com.apple.iTunes", {})
            min_itunes_version = self.lockdown.all_values.get("com.apple.mobile.iTunes", {}).get("MinITunesVersion")
            if min_itunes_version is None:
                # iPadOS may not contain this value. See:
                # https://github.com/doronz88/pymobiledevice3/issues/1332
                min_itunes_version = "10.0.1"
            app_dict = {}
            installed_apps = []
            apps = await ip.browse(
                options={"ApplicationType": "User"},
                attributes=["CFBundleIdentifier", "ApplicationSINF", "iTunesMetadata"],
            )
            for app in apps:
                bundle_id = app["CFBundleIdentifier"]
                if bundle_id:
                    installed_apps.append(bundle_id)
                    if app.get("iTunesMetadata", False) and app.get("ApplicationSINF", False):
                        app_dict[bundle_id] = {
                            "ApplicationSINF": app["ApplicationSINF"],
                            "iTunesMetadata": app["iTunesMetadata"],
                            "PlaceholderIcon": await sbs.get_icon_pngdata(bundle_id),
                        }

            files = {}
            for file in ITUNES_FILES:
                try:
                    data_buf = await afc.get_file_contents("/iTunes_Control/iTunes/" + file)
                except AfcFileNotFoundError:
                    pass
                else:
                    files[file] = data_buf

            ret = {
                "iTunes Version": min_itunes_version if min_itunes_version else "10.0.1",
                "iTunes Files": files,
                "Unique Identifier": self.lockdown.udid.upper(),
                "Target Type": "Device",
                "Target Identifier": root_node["UniqueDeviceID"],
                "Serial Number": root_node["SerialNumber"],
                "Product Version": root_node["ProductVersion"],
                "Product Type": root_node["ProductType"],
                "Installed Applications": installed_apps,
                "GUID": uuid.uuid4().bytes,
                "Display Name": root_node["DeviceName"],
                "Device Name": root_node["DeviceName"],
                "Build Version": root_node["BuildVersion"],
                "Applications": app_dict,
            }

            if "IntegratedCircuitCardIdentity" in root_node:
                ret["ICCID"] = root_node["IntegratedCircuitCardIdentity"]
            if "InternationalMobileEquipmentIdentity" in root_node:
                ret["IMEI"] = root_node["InternationalMobileEquipmentIdentity"]
            if "MobileEquipmentIdentifier" in root_node:
                ret["MEID"] = root_node["MobileEquipmentIdentifier"]
            if "PhoneNumber" in root_node:
                ret["Phone Number"] = root_node["PhoneNumber"]

            try:
                data_buf = await afc.get_file_contents("/Books/iBooksData2.plist")
            except AfcFileNotFoundError:
                pass
            else:
                ret["iBooks Data 2"] = data_buf
            if itunes_settings:
                ret["iTunes Settings"] = itunes_settings
            return ret

    @asynccontextmanager
    async def _backup_lock(self, afc, notification_proxy):
        await notification_proxy.notify_post(NP_SYNC_WILL_START)
        lockfile = await afc.fopen("/com.apple.itunes.lock_sync", "r+")
        if lockfile:
            await notification_proxy.notify_post(NP_SYNC_LOCK_REQUEST)
            for _ in range(50):
                try:
                    await afc.lock(lockfile, AFC_LOCK_EX)
                except AfcException as e:
                    if e.status == AfcError.OP_WOULD_BLOCK:
                        await asyncio.sleep(0.2)
                    else:
                        await afc.fclose(lockfile)
                        raise
                else:
                    await notification_proxy.notify_post(NP_SYNC_DID_START)
                    break
            else:  # No break, lock failed.
                await afc.fclose(lockfile)
                raise PyMobileDevice3Exception("Failed to lock itunes sync file")
        try:
            yield
        finally:
            await afc.lock(lockfile, AFC_LOCK_UN)
            await afc.fclose(lockfile)
            await notification_proxy.notify_post(NP_SYNC_DID_FINISH)

    @staticmethod
    def _assert_backup_exists(backup_directory: Path, identifier: str):
        device_directory = backup_directory / identifier
        assert (device_directory / "Info.plist").exists()
        assert (device_directory / "Manifest.plist").exists()
        assert (device_directory / "Status.plist").exists()

    @staticmethod
    def resolve_backup_selection(only: Optional[Sequence[str]]) -> tuple[BackupSelectionRule, ...]:
        """
        Map preset selection names (e.g. "sms", "contacts") to their `BackupSelectionRule` sets.

        Names are matched case-insensitively against the built-in `BACKUP_SELECTIONS` presets.

        :param only: Selection names to resolve. If None or empty, no selections are resolved.
        :returns: The combined rules for all resolved names, or an empty tuple if `only` is empty.
        :raises PyMobileDevice3Exception: If a name is not a known preset; the message lists the
            invalid name and all available presets.
        """
        if not only:
            return ()

        rules = []
        for selection_name in only:
            preset = BACKUP_SELECTIONS.get(selection_name.lower())
            if preset is None:
                available = ", ".join(sorted(BACKUP_SELECTIONS))
                raise PyMobileDevice3Exception(
                    f"Unsupported backup selection: {selection_name}. Available: {available}"
                )
            rules.extend(preset)
        return tuple(rules)

    @staticmethod
    def should_preserve_backup_file(
        file_name: str, device_name: str, filter_callback: Optional[BackupFilterCallback]
    ) -> bool:
        """
        Decide whether a backup file should be preserved.

        Known backup metadata files (`BACKUP_METADATA_FILES`) are always preserved. With no
        filter callback every file is preserved; otherwise the callback decides.

        :param file_name: The file name (with or without path) to evaluate.
        :param device_name: The device-side name associated with the backup file.
        :param filter_callback: Optional predicate taking a `BackupFile` and returning whether
            to preserve it.
        :returns: True if the file should be preserved, False otherwise.
        """
        if Path(file_name).name in BACKUP_METADATA_FILES:
            return True
        if filter_callback is None:
            return True
        return filter_callback(BackupFile(file_name=file_name, device_name=device_name))

    @classmethod
    def selection_filter_callback(cls, rules: Sequence[BackupSelectionRule]) -> BackupFilterCallback:
        """
        Build a filter callback that keeps files matching any of the given selection rules.

        The returned callback matches device-name entries via `BackupSelectionRule.matches_device_name`
        and manifest entries via `BackupSelectionRule.matches_manifest_entry`.

        :param rules: The `BackupSelectionRule` objects a file must match to be kept.
        :returns: A `BackupFilterCallback` returning True for files matching any rule.
        """
        selected_rules = tuple(rules)

        def _filter(backup_file: BackupFile) -> bool:
            if backup_file.device_name is not None:
                return any(rule.matches_device_name(backup_file.device_name) for rule in selected_rules)
            if backup_file.domain is not None and backup_file.relative_path is not None:
                return any(
                    rule.matches_manifest_entry(backup_file.domain, backup_file.relative_path)
                    for rule in selected_rules
                )
            return False

        return _filter

    @staticmethod
    def regex_filter_callback(patterns: Sequence[str]) -> BackupFilterCallback:
        """
        Build a filter callback that keeps files whose path matches any of the given regexes.

        Patterns are searched (not fully matched) against the file's device name and against
        its domain/relative-path combinations.

        :param patterns: Regular expression patterns used to match backup files.
        :returns: A `BackupFilterCallback` returning True for files matching any pattern.
        """
        compiled_patterns = tuple(re.compile(pattern) for pattern in patterns)

        def _filter(backup_file: BackupFile) -> bool:
            candidates = []
            if backup_file.device_name is not None:
                candidates.append(backup_file.device_name)
            if backup_file.domain is not None and backup_file.relative_path is not None:
                candidates.extend((
                    f"{backup_file.domain}/{backup_file.relative_path}",
                    f"{backup_file.domain}-{backup_file.relative_path}",
                    backup_file.relative_path,
                ))
            return any(pattern.search(candidate) for candidate in candidates for pattern in compiled_patterns)

        return _filter

    @staticmethod
    def combine_filter_callbacks(*callbacks: Optional[BackupFilterCallback]) -> Optional[BackupFilterCallback]:
        """
        Combine several filter callbacks into one that keeps a file if any of them keeps it.

        None entries are ignored.

        :param callbacks: Optional `BackupFilterCallback` functions to combine.
        :returns: A combined `BackupFilterCallback`, or None if no non-None callbacks are given.
        """
        active_callbacks = tuple(callback for callback in callbacks if callback is not None)
        if not active_callbacks:
            return None

        def _filter(backup_file: BackupFile) -> bool:
            return any(callback(backup_file) for callback in active_callbacks)

        return _filter

    @classmethod
    def prune_backup_directory(
        cls, device_directory: Path, filter_callback: Optional[BackupFilterCallback], password: str = ""
    ) -> None:
        """
        Delete on-disk backup files rejected by the filter, keeping metadata and allowed files.

        First prunes the manifest to the set of allowed file IDs, then removes any stored
        files (and now-empty hash-prefix directories) not in that set. Backup metadata files
        are always kept.

        :param device_directory: Path of the per-device backup directory to prune.
        :param filter_callback: Predicate selecting which files to keep; if None, nothing is pruned.
        :param password: Backup password; required when the backup is encrypted.
        """
        if filter_callback is None:
            return

        allowed_file_ids = cls.prune_backup_manifest(device_directory, filter_callback, password=password)
        allowed_prefixes = {file_id[:2] for file_id in allowed_file_ids}
        for path in list(device_directory.iterdir()):
            if path.name in BACKUP_METADATA_FILES:
                continue
            if path.is_dir():
                if path.name not in allowed_prefixes:
                    shutil.rmtree(path)
                    continue
                for nested in list(path.iterdir()):
                    if nested.name not in allowed_file_ids:
                        if nested.is_dir():
                            shutil.rmtree(nested)
                        else:
                            nested.unlink(missing_ok=True)
                if not any(path.iterdir()):
                    path.rmdir()
            else:
                if path.name not in allowed_file_ids:
                    path.unlink(missing_ok=True)

    @classmethod
    def prune_backup_manifest(
        cls, device_directory: Path, filter_callback: Optional[BackupFilterCallback], password: str = ""
    ) -> set[str]:
        """
        Prune Manifest.db to the files the filter keeps and return their file IDs.

        For encrypted backups the manifest is transparently decrypted, pruned, and re-encrypted
        in place using the password-derived key.

        :param device_directory: Path of the per-device backup directory.
        :param filter_callback: Predicate selecting which files to keep; if None, nothing is kept.
        :param password: Backup password; required when the backup is encrypted.
        :returns: The set of file IDs that were kept.
        :raises BackupFilterPasswordRequiredError: If the backup is encrypted and no password is given.
        """
        manifest_db_path = device_directory / "Manifest.db"
        if not cls._is_encrypted_backup(device_directory):
            return cls._prune_manifest_db(manifest_db_path, filter_callback)

        with tempfile.NamedTemporaryFile(suffix=".sqlite3") as decrypted_manifest:
            decrypted_manifest_path = Path(decrypted_manifest.name)
            manifest_key = cls._decrypt_backup_manifest_db(device_directory, password, decrypted_manifest_path)
            allowed_file_ids = cls._prune_manifest_db(decrypted_manifest_path, filter_callback)
            cls._encrypt_backup_manifest_db(decrypted_manifest_path, manifest_db_path, manifest_key)
            return allowed_file_ids

    @staticmethod
    def _prune_manifest_db(manifest_db_path: Path, filter_callback: Optional[BackupFilterCallback]) -> set[str]:
        if not manifest_db_path.exists() or filter_callback is None:
            return set()

        with closing(sqlite3.connect(manifest_db_path)) as connection:
            rows = connection.execute("SELECT fileID, domain, relativePath FROM Files").fetchall()
            allowed_file_ids = {
                file_id
                for file_id, domain, relative_path in rows
                if filter_callback(BackupFile(file_id=file_id, domain=domain, relative_path=relative_path))
            }
            delete_params = [
                (domain, relative_path) for file_id, domain, relative_path in rows if file_id not in allowed_file_ids
            ]
            if delete_params:
                connection.executemany(
                    "DELETE FROM Files WHERE domain = ? AND relativePath = ?",
                    delete_params,
                )
            connection.commit()

        return allowed_file_ids

    @staticmethod
    def _is_encrypted_backup(device_directory: Path) -> bool:
        manifest_plist_path = Mobilebackup2Service._backup_manifest_plist_path(device_directory)
        if manifest_plist_path is None:
            return False
        return bool(plistlib.loads(manifest_plist_path.read_bytes()).get("IsEncrypted", False))

    @staticmethod
    def _backup_manifest_plist_path(device_directory: Path) -> Optional[Path]:
        for manifest_plist_path in (
            device_directory / "Manifest.plist",
            device_directory / "Snapshot" / "Manifest.plist",
        ):
            if manifest_plist_path.exists() and manifest_plist_path.stat().st_size > 0:
                return manifest_plist_path
        return None

    @staticmethod
    def _decrypt_backup_manifest_db(device_directory: Path, password: str, decrypted_manifest_path: Path) -> bytes:
        if not password:
            raise BackupFilterPasswordRequiredError(
                "Backup filtering requires the backup password when encryption is enabled"
            )

        manifest_plist_path = Mobilebackup2Service._backup_manifest_plist_path(device_directory)
        if manifest_plist_path is None:
            raise PyMobileDevice3Exception("Encrypted backup Manifest.plist was not received before Manifest.db")

        manifest = ManifestPlist.from_path(manifest_plist_path)
        keybag = Keybag.from_manifest(manifest, password)
        manifest_db = device_directory / "Manifest.db"
        decrypted_manifest_path.write_bytes(keybag.decrypt(manifest_db.read_bytes(), manifest.manifest_key))

        parsed_key = encryption_key_struct.parse(manifest.manifest_key)
        return aes_key_unwrap(keybag.get_key(parsed_key.class_), parsed_key.key)

    @staticmethod
    def _encrypt_backup_manifest_db(decrypted_manifest_path: Path, manifest_db_path: Path, manifest_key: bytes) -> None:
        plaintext = decrypted_manifest_path.read_bytes()
        if len(plaintext) % (algorithms.AES.block_size // 8):
            raise PyMobileDevice3Exception("Decrypted backup Manifest.db is not AES block aligned")

        cipher = Cipher(algorithms.AES(manifest_key), modes.CBC(b"\x00" * 16))
        encryptor = cipher.encryptor()
        manifest_db_path.write_bytes(encryptor.update(plaintext) + encryptor.finalize())

    @asynccontextmanager
    async def device_link(
        self, backup_directory, filter_callback: Optional[BackupFilterCallback] = None, password: str = ""
    ):
        """
        Async context manager yielding a connected `DeviceLink` for backup operations.

        Performs the device-link and mobilebackup2 version exchanges on entry and disconnects
        on exit. The given filter callback governs which incoming files are written to disk.

        :param backup_directory: Directory the device link reads from and writes to.
        :param filter_callback: Optional predicate controlling which files are preserved.
        :param password: Backup password (unused here directly; passed through by callers).
        """
        dl = DeviceLink(
            self.service,
            backup_directory,
            preserve_file=lambda file_name, device_name: self.should_preserve_backup_file(
                file_name, device_name, filter_callback
            ),
        )
        await dl.version_exchange()
        await self.version_exchange(dl)
        try:
            yield dl
        finally:
            await dl.disconnect()
