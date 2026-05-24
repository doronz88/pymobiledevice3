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
BACKUP_METADATA_FILES = frozenset({
    "Info.plist",
    "Manifest.plist",
    "Manifest.db",
    "Manifest.db-shm",
    "Manifest.db-wal",
    "Status.plist",
})


@dataclass(frozen=True)
class BackupSelectionRule:
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
    SERVICE_NAME = "com.apple.mobilebackup2"
    RSD_SERVICE_NAME = "com.apple.mobilebackup2.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME, include_escrow_bag=True)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME, include_escrow_bag=True)

    async def get_will_encrypt(self) -> bool:
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
        Backup a device.
        :param full: Whether to do a full backup. If full is True, any previous backup attempts will be discarded.
        :param backup_directory: Directory to write backup to.
        :param progress_callback: Function to be called as the backup progresses.
        :param filter_callback: Callback deciding whether to keep a backup file.
        :param password: Password of the backup if it is encrypted.
        :param unback: Also unpack the completed backup locally using pyiosbackup.
        The function shall receive the percentage as a parameter.
        """
        full = full or filter_callback is not None
        backup_directory = Path(backup_directory)
        device_directory = backup_directory / self.lockdown.udid
        device_directory.mkdir(exist_ok=True, mode=0o755, parents=True)

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
            # Initialize Info.plist
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
        Restore a previous backup to the device.
        :param backup_directory: Path of the backup directory.
        :param system: Whether to restore system files.
        :param reboot: Reboot the device when done.
        :param copy: Create a copy of backup folder before restoring.
        :param settings: Restore device settings.
        :param remove: Remove items which aren't being restored.
        :param password: Password of the backup if it is encrypted.
        :param source: Identifier of device to restore its backup.
        :param progress_callback: Function to be called as the backup progresses.
        :param skip_apps: Do not trigger re-installation of apps after restore.
        The function shall receive the current percentage of the progress as a parameter.
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
        :param source: Identifier of device to get info about its backup.
        :return: Information about a backup.
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
        :param source: Identifier of device to list its backup data.
        :return: List of files and additional data about each file, all in a CSV format.
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
        Unpack a complete backup to its device hierarchy.
        :param backup_directory: Path of the backup directory.
        :param password: Password of the backup if it is encrypted.
        :param source: Identifier of device to unpack its backup.
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
        Extract a file from a previous backup.
        :param domain_name: File's domain name, e.g., SystemPreferencesDomain or HomeDomain.
        :param relative_path: File path.
        :param backup_directory: Path of the backup directory.
        :param password: Password of the last backup if it is encrypted.
        :param source: Identifier of device to extract file from its backup.
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
        Change backup password.
        :param backup_directory: Backups directory.
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
        Erase the device.
        """
        with suppress(IncompleteReadError):
            async with self.device_link(Path(backup_directory)) as dl:
                await dl.send_process_message({"MessageName": "EraseDevice", "TargetIdentifier": self.lockdown.udid})
                await dl.dl_loop()

    async def version_exchange(self, dl: DeviceLink, local_versions=None) -> None:
        """
        Exchange versions with the device and assert that the device supports our version of the protocol.
        :param dl: Initialized device link.
        :param local_versions: versions supported by us.
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
        Resolves and maps a list of backup selection names to their corresponding backup selection rules.

        Given a sequence of selection names, this method retrieves the associated rules from a predefined
        mapping. If no input is provided, an empty tuple is returned. If one or more invalid selection
        names are given, an exception is raised specifying the invalid name and listing all available
        options.

        :param only: A sequence of backup selection names to resolve. This determines which
            predefined backup rules will be applied. If None or an empty list is supplied,
            no backup selections will be resolved.
        :type only: Optional[Sequence[str]]

        :return: A tuple of backup selection rules derived from the input sequence. Each valid
            name in the input is resolved into its corresponding set of rules and returned
            as a tuple.
        :rtype: tuple[BackupSelectionRule, ...]

        :raises PyMobileDevice3Exception: If an unsupported backup selection name is provided
            in the input. The error message includes the invalid name and a list of valid
            selection names.
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
        Determines whether a backup file should be preserved based on its name, the device it belongs
        to, and an optional filter callback. This method checks if the file is a metadata file from
        known backup metadata files, returning True if it matches. If a filter callback is provided,
        it will use the callback to decide preservation for other files.

        :param file_name: The name (with or without path) of the file to evaluate.
        :param device_name: The name of the device associated with the backup file.
        :param filter_callback: An optional callable used to apply custom filtering logic to
                                decide preservation. It should take a BackupFile instance as an
                                argument and return a boolean indicating whether the file should
                                be preserved.
        :return: A boolean value indicating whether the backup file should be preserved.
        """
        if Path(file_name).name in BACKUP_METADATA_FILES:
            return True
        if filter_callback is None:
            return True
        return filter_callback(BackupFile(file_name=file_name, device_name=device_name))

    @classmethod
    def selection_filter_callback(cls, rules: Sequence[BackupSelectionRule]) -> BackupFilterCallback:
        """
        Creates a callback function to filter backup files based on provided selection rules.

        The generated callback function examines backup files and determines whether they
        should be included based on the provided `BackupSelectionRule` rules. The rules are
        evaluated in sequence, and the callback returns a boolean indicating whether a file
        matches any of the rules.

        :param rules: The sequence of `BackupSelectionRule` objects used to determine which
            backup files should be included.
        :type rules: Sequence[BackupSelectionRule]

        :return: A callback function (`BackupFilterCallback`) that returns `True` for files
            matching any of the provided rules and `False` otherwise.
        :rtype: BackupFilterCallback
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
        Filters backup files using specified regular expression patterns.

        This method creates a callback function that applies regular expression
        filters to backup files. The function determines whether a given backup file
        matches any of the provided patterns.

        :param patterns: A sequence of regular expression patterns used to filter
            backup files.
        :type patterns: Sequence[str]
        :return: A callback function that takes a `BackupFile` object and returns a
            boolean value indicating if the file matches any of the patterns.
        :rtype: BackupFilterCallback
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
        Combines multiple backup filter callbacks into a single callback. The returned callback will
        execute each of the given callbacks with the provided `BackupFile` instance. If any of the
        callbacks return `True`, the combined callback will return `True`. If no callbacks are provided,
        `None` is returned.

        :param callbacks: Variable number of optional `BackupFilterCallback` functions to combine.
            A `BackupFilterCallback` is a callable that takes a `BackupFile` instance as input and returns
            a boolean indicating whether the backup file passes the filter.
        :return: A combined `BackupFilterCallback` or `None` if no valid callbacks are provided.
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
