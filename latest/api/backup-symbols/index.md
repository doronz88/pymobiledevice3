# Backup, symbols & location

Device backup/restore, dyld shared-cache symbol fetching, and GPS simulation.

## pymobiledevice3.services.mobilebackup2.Mobilebackup2Service

Bases: `LockdownService`

Client for the `com.apple.mobilebackup2` service, the iTunes/Finder-style device backup protocol.

Drives full and incremental backups, restores, and the related operations (info, list, extract, unback, change password, erase device) over a `DeviceLink` channel. Backups can be filtered to a subset of files via a filter callback, and encrypted backups are supported (a password is required when patching an encrypted manifest or restoring an encrypted backup). The right underlying service is selected automatically: `SERVICE_NAME` over classic lockdown, or `RSD_SERVICE_NAME` over RemoteXPC/RSD.

Inherits async context manager support from `LockdownService`; use within an `async with` block to manage the underlying connection.

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
class Mobilebackup2Service(LockdownService):
    """
    Client for the `com.apple.mobilebackup2` service, the iTunes/Finder-style device backup protocol.

    Drives full and incremental backups, restores, and the related operations (info, list,
    extract, unback, change password, erase device) over a `DeviceLink` channel. Backups can
    be filtered to a subset of files via a filter callback, and encrypted backups are
    supported (a password is required when patching an encrypted manifest or restoring an
    encrypted backup). The right underlying service is selected automatically: `SERVICE_NAME`
    over classic lockdown, or `RSD_SERVICE_NAME` over RemoteXPC/RSD.

    Inherits async context manager support from `LockdownService`; use within an
    ``async with`` block to manage the underlying connection.
    """

    SERVICE_NAME = "com.apple.mobilebackup2"
    RSD_SERVICE_NAME = "com.apple.mobilebackup2.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown, include_escrow_bag=True)

    @property
    def _udid(self) -> str:
        udid = self.lockdown.udid
        if udid is None:
            raise NotConnectedError("The device UDID is unknown; connect to the device first.")
        return validate_device_filename(udid)

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
        progress_callback: ProgressCallback = lambda x: None,
        filter_callback: Optional[BackupFilterCallback] = None,
        password: str = "",
        unback: bool = False,
        patch_manifest: bool = False,
    ) -> None:
        """
        Back up the device into `backup_directory`/<device-udid>.

        :param full: Perform a full backup, discarding any previous incremental state. A full
            backup is also forced when incremental metadata is missing.
        :param backup_directory: Directory the backup is written to (a per-device subdirectory
            is created under it).
        :param progress_callback: Called as the backup progresses with the completion
            percentage as its sole argument.
        :param filter_callback: Optional predicate deciding which backup payloads to keep. The
            rejected payload bytes are drained but not stored.
        :param patch_manifest: Remove entries for rejected payloads from Manifest.db. This forces
            a full backup and requires the password when backup encryption is enabled.
        :param password: Backup password, used when patching or unpacking an encrypted backup.
        :param unback: When True, also unpack the completed backup locally using pyiosbackup.
        :raises BackupFilterPasswordRequiredError: If manifest patching is requested without a
            password while the device encrypts backups.
        """
        backup_directory = Path(backup_directory)
        device_directory = backup_directory / self._udid
        device_directory.mkdir(exist_ok=True, mode=0o755, parents=True)
        patch_manifest = patch_manifest and filter_callback is not None
        full = self._should_do_full_backup(full, device_directory, patch_manifest)

        if patch_manifest and not password and await self.get_will_encrypt():
            raise BackupFilterPasswordRequiredError(
                "Patching an encrypted backup manifest requires the backup password"
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
                current_date = datetime.now(timezone.utc).replace(tzinfo=None)
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
                try:
                    await dl.dl_loop(progress_callback)
                finally:
                    dl.cleanup_discarded_files()
                if patch_manifest:
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
        patch_manifest: bool = False,
    ) -> bool:
        return full or patch_manifest or not cls._has_incremental_backup_metadata(device_directory)

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

    def _log_backup_notification(self, event: dict[str, Any]) -> None:
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
        backup_directory: Union[str, Path] = ".",
        system: bool = False,
        reboot: bool = True,
        copy: bool = True,
        settings: bool = True,
        remove: bool = False,
        password: str = "",
        source: str = "",
        progress_callback: ProgressCallback = lambda x: None,
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
        source = source if source else self._udid
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
            options: dict[str, Union[bool, str]] = {
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

            applications = None
            if not skip_apps:
                info_plist_path = backup_directory / source / "Info.plist"
                applications = plistlib.loads(info_plist_path.read_bytes()).get("Applications")
            await self._request_app_reinstall(afc, applications)

            await dl.dl_loop(progress_callback)

    @staticmethod
    async def _request_app_reinstall(afc: AfcService, applications: Optional[dict[str, Any]]) -> None:
        """
        Tell the device which apps to re-create from the App Store once the restore finishes.

        The device turns every app listed in `RESTORE_APPLICATIONS_PATH` into an App Store restore,
        even one that is already installed: until that download completes, SpringBoard refuses to
        launch it ("being updated"). The device never deletes the file after a restore, so when
        there is nothing to request, a copy left by an earlier restore is removed instead.

        :param afc: AFC connection to the device's media partition.
        :param applications: The backup's ``Info.plist`` ``Applications`` dictionary, or None to
            request no app re-installation.
        """
        if applications is None:
            if await afc.exists(RESTORE_APPLICATIONS_PATH):
                await afc.rm_single(RESTORE_APPLICATIONS_PATH)
            return
        await afc.makedirs(posixpath.dirname(RESTORE_APPLICATIONS_PATH))
        await afc.set_file_contents(RESTORE_APPLICATIONS_PATH, plistlib.dumps(applications))

    async def info(self, backup_directory: Union[str, Path] = ".", source: str = "") -> str:
        """
        Get information about a backup.

        :param backup_directory: Path of the backup directory.
        :param source: Identifier of the device to get info about; defaults to the connected
            device's UDID.
        :returns: Information about the backup, as returned by the device.
        """
        backup_dir = Path(backup_directory)
        self._assert_backup_exists(backup_dir, source if source else self._udid)
        async with self.device_link(backup_dir) as dl:
            message: dict[str, Any] = {"MessageName": "Info", "TargetIdentifier": self.lockdown.udid}
            if source:
                message["SourceIdentifier"] = source
            await dl.send_process_message(message)
            result = await dl.dl_loop()
        return result

    async def list(self, backup_directory: Union[str, Path] = ".", source: str = "") -> str:
        """
        List the files in the last backup.

        :param backup_directory: Path of the backup directory.
        :param source: Identifier of the device to list; defaults to the connected device's UDID.
        :returns: The files and per-file metadata in CSV format.
        """
        backup_dir = Path(backup_directory)
        source = source if source else self._udid
        self._assert_backup_exists(backup_dir, source)
        async with self.device_link(backup_dir) as dl:
            await dl.send_process_message({
                "MessageName": "List",
                "TargetIdentifier": self.lockdown.udid,
                "SourceIdentifier": source,
            })
            result = await dl.dl_loop()
        return result

    async def unback(self, backup_directory: Union[str, Path] = ".", password: str = "", source: str = "") -> None:
        """
        Unpack a complete backup into its original device file hierarchy.

        :param backup_directory: Path of the backup directory.
        :param password: Password of the backup; required if the backup is encrypted.
        :param source: Identifier of the device whose backup is unpacked; defaults to the
            connected device's UDID.
        """
        backup_dir = Path(backup_directory)
        self._assert_backup_exists(backup_dir, source if source else self._udid)
        async with self.device_link(backup_dir) as dl:
            message: dict[str, Any] = {"MessageName": "Unback", "TargetIdentifier": self.lockdown.udid}
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
        Backup.from_path(device_directory, password).unback(str(output_directory))
        return output_directory

    async def extract(
        self,
        domain_name: str,
        relative_path: str,
        backup_directory: Union[str, Path] = ".",
        password: str = "",
        source: str = "",
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
        self._assert_backup_exists(backup_dir, source if source else self._udid)
        async with self.device_link(backup_dir) as dl:
            message: dict[str, Any] = {
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

    async def change_password(self, backup_directory: Union[str, Path] = ".", old: str = "", new: str = "") -> None:
        """
        Change, enable, or disable the device's backup encryption password.

        :param backup_directory: Path of the backup directory.
        :param old: Previous password. Omit when enabling backup encryption.
        :param new: New password. Omit when disabling backup encryption.
        """
        async with self.device_link(Path(backup_directory)) as dl:
            message: dict[str, Any] = {"MessageName": "ChangePassword", "TargetIdentifier": self.lockdown.udid}
            if old:
                message["OldPassword"] = old
            if new:
                message["NewPassword"] = new
            await dl.send_process_message(message)
            await dl.dl_loop()

    async def set_cloud_backup(self, enabled: bool) -> None:
        """
        Turn iCloud Backup on or off.

        The device refuses with ``MBErrorDomain/1`` when no iCloud account is signed in.

        :param enabled: True to turn iCloud Backup on, False to turn it off.
        """
        # no files are exchanged, but the device link needs a root directory
        with tempfile.TemporaryDirectory() as root:
            async with self.device_link(Path(root)) as dl:
                await dl.send_process_message({
                    "MessageName": "EnableCloudBackup",
                    "TargetIdentifier": self.lockdown.udid,
                    "CloudBackupState": enabled,
                })
                await dl.dl_loop()

    async def erase_device(self, backup_directory: Union[str, Path] = ".") -> None:
        """
        Erase the device, restoring it to factory state.

        The device drops the link once it starts erasing; that termination is suppressed so the
        call returns cleanly.

        :param backup_directory: Path of the backup directory used for the device link channel.
        """
        async with self.device_link(Path(backup_directory)) as dl:
            await dl.send_process_message({"MessageName": "EraseDevice", "TargetIdentifier": self.lockdown.udid})
            with suppress(ConnectionTerminatedError):
                await dl.dl_loop()

    async def version_exchange(self, dl: DeviceLink, local_versions: Optional[Sequence[float]] = None) -> None:
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

    async def init_mobile_backup_factory_info(self, afc: AfcService) -> dict[str, Any]:
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
            installed_apps: list[Any] = []
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

            ret: dict[str, Any] = {
                "iTunes Version": min_itunes_version if min_itunes_version else "10.0.1",
                "iTunes Files": files,
                "Unique Identifier": self._udid.upper(),
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
    async def _backup_lock(self, afc: AfcService, notification_proxy: NotificationProxyService):
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
                raise PyMobileDevice3Exception(
                    "Could not lock the device's sync lock file; another sync or backup may be running."
                )
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

        rules: list[BackupSelectionRule] = []
        for selection_name in only:
            try:
                selection = BackupSelection(selection_name.lower())
            except ValueError:
                available = ", ".join(sorted(BACKUP_SELECTIONS))
                raise PyMobileDevice3Exception(
                    f"Unsupported backup selection: {selection_name}. Available: {available}"
                ) from None
            rules.extend(selection.rules())
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
            candidates: list[str] = []
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
            raise ProtocolError("The device sent the encrypted backup's Manifest.db before its Manifest.plist.")

        manifest = ManifestPlist.from_path(manifest_plist_path)
        keybag = Keybag.from_manifest(manifest, password)
        manifest_db = device_directory / "Manifest.db"
        decrypted_manifest_path.write_bytes(keybag.decrypt(manifest_db.read_bytes(), manifest.manifest_key))

        # ManifestKey is a little-endian uint32 protection class followed by the wrapped key.
        reader = ByteReader(manifest.manifest_key)
        protection_class = reader.unpack_one(U32_LE)
        return aes_key_unwrap(cast(Any, keybag).get_key(protection_class), reader.read_all())

    @staticmethod
    def _encrypt_backup_manifest_db(decrypted_manifest_path: Path, manifest_db_path: Path, manifest_key: bytes) -> None:
        plaintext = decrypted_manifest_path.read_bytes()
        algorithm = algorithms.AES(manifest_key)
        if len(plaintext) % (algorithm.block_size // 8):
            raise PyMobileDevice3Exception(
                "The decrypted backup Manifest.db has an invalid size: it is not a whole number of AES blocks."
            )

        cipher = Cipher(algorithm, modes.CBC(b"\x00" * 16))
        encryptor = cipher.encryptor()
        manifest_db_path.write_bytes(encryptor.update(plaintext) + encryptor.finalize())

    @asynccontextmanager
    async def device_link(
        self, backup_directory: Path, filter_callback: Optional[BackupFilterCallback] = None, password: str = ""
    ):
        """
        Async context manager yielding a connected `DeviceLink` for backup operations.

        Performs the device-link and mobilebackup2 version exchanges on entry and disconnects
        on exit. The given filter callback governs which incoming files are written to disk.

        :param backup_directory: Directory the device link reads from and writes to.
        :param filter_callback: Optional predicate controlling which files are preserved.
        :param password: Backup password (unused here directly; passed through by callers).
        """
        await self.connect()
        assert self._service is not None
        dl = DeviceLink(
            self._service,
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
            # The device may already have dropped the link (often the reason we are exiting), and
            # a failed DLMessageDisconnect must not replace the error that ended the session.
            with suppress(ConnectionTerminatedError):
                await dl.disconnect()
```

### get_will_encrypt

```
get_will_encrypt() -> bool
```

Report whether the device is configured to encrypt its backups.

Returns:

| Type   | Description                                                                                                    |
| ------ | -------------------------------------------------------------------------------------------------------------- |
| `bool` | True if backup encryption is enabled on the device, False otherwise (including when the value cannot be read). |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
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
```

### backup

```
backup(full: bool = True, backup_directory: Union[str, Path] = '.', progress_callback: ProgressCallback = lambda x: None, filter_callback: Optional[BackupFilterCallback] = None, password: str = '', unback: bool = False, patch_manifest: bool = False) -> None
```

Back up the device into `backup_directory`/.

Parameters:

| Name                | Type                             | Description                                                                                                                                   | Default          |
| ------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- |
| `full`              | `bool`                           | Perform a full backup, discarding any previous incremental state. A full backup is also forced when incremental metadata is missing.          | `True`           |
| `backup_directory`  | `Union[str, Path]`               | Directory the backup is written to (a per-device subdirectory is created under it).                                                           | `'.'`            |
| `progress_callback` | `ProgressCallback`               | Called as the backup progresses with the completion percentage as its sole argument.                                                          | `lambda x: None` |
| `filter_callback`   | `Optional[BackupFilterCallback]` | Optional predicate deciding which backup payloads to keep. The rejected payload bytes are drained but not stored.                             | `None`           |
| `patch_manifest`    | `bool`                           | Remove entries for rejected payloads from Manifest.db. This forces a full backup and requires the password when backup encryption is enabled. | `False`          |
| `password`          | `str`                            | Backup password, used when patching or unpacking an encrypted backup.                                                                         | `''`             |
| `unback`            | `bool`                           | When True, also unpack the completed backup locally using pyiosbackup.                                                                        | `False`          |

Raises:

| Type                                | Description                                                                             |
| ----------------------------------- | --------------------------------------------------------------------------------------- |
| `BackupFilterPasswordRequiredError` | If manifest patching is requested without a password while the device encrypts backups. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def backup(
    self,
    full: bool = True,
    backup_directory: Union[str, Path] = ".",
    progress_callback: ProgressCallback = lambda x: None,
    filter_callback: Optional[BackupFilterCallback] = None,
    password: str = "",
    unback: bool = False,
    patch_manifest: bool = False,
) -> None:
    """
    Back up the device into `backup_directory`/<device-udid>.

    :param full: Perform a full backup, discarding any previous incremental state. A full
        backup is also forced when incremental metadata is missing.
    :param backup_directory: Directory the backup is written to (a per-device subdirectory
        is created under it).
    :param progress_callback: Called as the backup progresses with the completion
        percentage as its sole argument.
    :param filter_callback: Optional predicate deciding which backup payloads to keep. The
        rejected payload bytes are drained but not stored.
    :param patch_manifest: Remove entries for rejected payloads from Manifest.db. This forces
        a full backup and requires the password when backup encryption is enabled.
    :param password: Backup password, used when patching or unpacking an encrypted backup.
    :param unback: When True, also unpack the completed backup locally using pyiosbackup.
    :raises BackupFilterPasswordRequiredError: If manifest patching is requested without a
        password while the device encrypts backups.
    """
    backup_directory = Path(backup_directory)
    device_directory = backup_directory / self._udid
    device_directory.mkdir(exist_ok=True, mode=0o755, parents=True)
    patch_manifest = patch_manifest and filter_callback is not None
    full = self._should_do_full_backup(full, device_directory, patch_manifest)

    if patch_manifest and not password and await self.get_will_encrypt():
        raise BackupFilterPasswordRequiredError(
            "Patching an encrypted backup manifest requires the backup password"
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
            current_date = datetime.now(timezone.utc).replace(tzinfo=None)
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
            try:
                await dl.dl_loop(progress_callback)
            finally:
                dl.cleanup_discarded_files()
            if patch_manifest:
                self.prune_backup_directory(device_directory, filter_callback, password=password)
            if unback:
                self.unback_with_pyiosbackup(device_directory, password=password)
        finally:
            notification_task.cancel()
            with suppress(asyncio.CancelledError):
                await notification_task
```

### restore

```
restore(backup_directory: Union[str, Path] = '.', system: bool = False, reboot: bool = True, copy: bool = True, settings: bool = True, remove: bool = False, password: str = '', source: str = '', progress_callback: ProgressCallback = lambda x: None, skip_apps: bool = False)
```

Restore a previously created backup to the device.

Parameters:

| Name                | Type               | Description                                                                                 | Default          |
| ------------------- | ------------------ | ------------------------------------------------------------------------------------------- | ---------------- |
| `backup_directory`  | `Union[str, Path]` | Path of the backup directory.                                                               | `'.'`            |
| `system`            | `bool`             | Whether to restore system files.                                                            | `False`          |
| `reboot`            | `bool`             | Reboot the device when done.                                                                | `True`           |
| `copy`              | `bool`             | Create a copy of the backup folder before restoring.                                        | `True`           |
| `settings`          | `bool`             | Restore device settings.                                                                    | `True`           |
| `remove`            | `bool`             | Remove items on the device that aren't part of the restore.                                 | `False`          |
| `password`          | `str`              | Password of the backup; required if the backup is encrypted.                                | `''`             |
| `source`            | `str`              | Identifier of the device whose backup is restored; defaults to the connected device's UDID. | `''`             |
| `progress_callback` | `ProgressCallback` | Called as the restore progresses with the completion percentage as its sole argument.       | `lambda x: None` |
| `skip_apps`         | `bool`             | Do not trigger re-installation of apps after the restore.                                   | `False`          |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def restore(
    self,
    backup_directory: Union[str, Path] = ".",
    system: bool = False,
    reboot: bool = True,
    copy: bool = True,
    settings: bool = True,
    remove: bool = False,
    password: str = "",
    source: str = "",
    progress_callback: ProgressCallback = lambda x: None,
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
    source = source if source else self._udid
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
        options: dict[str, Union[bool, str]] = {
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

        applications = None
        if not skip_apps:
            info_plist_path = backup_directory / source / "Info.plist"
            applications = plistlib.loads(info_plist_path.read_bytes()).get("Applications")
        await self._request_app_reinstall(afc, applications)

        await dl.dl_loop(progress_callback)
```

### info

```
info(backup_directory: Union[str, Path] = '.', source: str = '') -> str
```

Get information about a backup.

Parameters:

| Name               | Type               | Description                                                                          | Default |
| ------------------ | ------------------ | ------------------------------------------------------------------------------------ | ------- |
| `backup_directory` | `Union[str, Path]` | Path of the backup directory.                                                        | `'.'`   |
| `source`           | `str`              | Identifier of the device to get info about; defaults to the connected device's UDID. | `''`    |

Returns:

| Type  | Description                                              |
| ----- | -------------------------------------------------------- |
| `str` | Information about the backup, as returned by the device. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def info(self, backup_directory: Union[str, Path] = ".", source: str = "") -> str:
    """
    Get information about a backup.

    :param backup_directory: Path of the backup directory.
    :param source: Identifier of the device to get info about; defaults to the connected
        device's UDID.
    :returns: Information about the backup, as returned by the device.
    """
    backup_dir = Path(backup_directory)
    self._assert_backup_exists(backup_dir, source if source else self._udid)
    async with self.device_link(backup_dir) as dl:
        message: dict[str, Any] = {"MessageName": "Info", "TargetIdentifier": self.lockdown.udid}
        if source:
            message["SourceIdentifier"] = source
        await dl.send_process_message(message)
        result = await dl.dl_loop()
    return result
```

### list

```
list(backup_directory: Union[str, Path] = '.', source: str = '') -> str
```

List the files in the last backup.

Parameters:

| Name               | Type               | Description                                                                | Default |
| ------------------ | ------------------ | -------------------------------------------------------------------------- | ------- |
| `backup_directory` | `Union[str, Path]` | Path of the backup directory.                                              | `'.'`   |
| `source`           | `str`              | Identifier of the device to list; defaults to the connected device's UDID. | `''`    |

Returns:

| Type  | Description                                    |
| ----- | ---------------------------------------------- |
| `str` | The files and per-file metadata in CSV format. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def list(self, backup_directory: Union[str, Path] = ".", source: str = "") -> str:
    """
    List the files in the last backup.

    :param backup_directory: Path of the backup directory.
    :param source: Identifier of the device to list; defaults to the connected device's UDID.
    :returns: The files and per-file metadata in CSV format.
    """
    backup_dir = Path(backup_directory)
    source = source if source else self._udid
    self._assert_backup_exists(backup_dir, source)
    async with self.device_link(backup_dir) as dl:
        await dl.send_process_message({
            "MessageName": "List",
            "TargetIdentifier": self.lockdown.udid,
            "SourceIdentifier": source,
        })
        result = await dl.dl_loop()
    return result
```

### unback

```
unback(backup_directory: Union[str, Path] = '.', password: str = '', source: str = '') -> None
```

Unpack a complete backup into its original device file hierarchy.

Parameters:

| Name               | Type               | Description                                                                                 | Default |
| ------------------ | ------------------ | ------------------------------------------------------------------------------------------- | ------- |
| `backup_directory` | `Union[str, Path]` | Path of the backup directory.                                                               | `'.'`   |
| `password`         | `str`              | Password of the backup; required if the backup is encrypted.                                | `''`    |
| `source`           | `str`              | Identifier of the device whose backup is unpacked; defaults to the connected device's UDID. | `''`    |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def unback(self, backup_directory: Union[str, Path] = ".", password: str = "", source: str = "") -> None:
    """
    Unpack a complete backup into its original device file hierarchy.

    :param backup_directory: Path of the backup directory.
    :param password: Password of the backup; required if the backup is encrypted.
    :param source: Identifier of the device whose backup is unpacked; defaults to the
        connected device's UDID.
    """
    backup_dir = Path(backup_directory)
    self._assert_backup_exists(backup_dir, source if source else self._udid)
    async with self.device_link(backup_dir) as dl:
        message: dict[str, Any] = {"MessageName": "Unback", "TargetIdentifier": self.lockdown.udid}
        if source:
            message["SourceIdentifier"] = source
        if password:
            message["Password"] = password
        await dl.send_process_message(message)
        await dl.dl_loop()
```

### unback_with_pyiosbackup

```
unback_with_pyiosbackup(device_directory: Path, password: str = '') -> Path
```

Unpack a local backup directory using pyiosbackup, on the host without the device.

The output is written to a sibling directory named `<device_directory>.unback`, replacing it if it already exists.

Parameters:

| Name               | Type   | Description                                                  | Default    |
| ------------------ | ------ | ------------------------------------------------------------ | ---------- |
| `device_directory` | `Path` | Path of the per-device backup directory to unpack.           | *required* |
| `password`         | `str`  | Password of the backup; required if the backup is encrypted. | `''`       |

Returns:

| Type   | Description                                         |
| ------ | --------------------------------------------------- |
| `Path` | Path of the directory the backup was unpacked into. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
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
    Backup.from_path(device_directory, password).unback(str(output_directory))
    return output_directory
```

### extract

```
extract(domain_name: str, relative_path: str, backup_directory: Union[str, Path] = '.', password: str = '', source: str = '') -> None
```

Extract a single file from a previous backup.

Parameters:

| Name               | Type               | Description                                                                        | Default    |
| ------------------ | ------------------ | ---------------------------------------------------------------------------------- | ---------- |
| `domain_name`      | `str`              | The file's domain, e.g. SystemPreferencesDomain or HomeDomain.                     | *required* |
| `relative_path`    | `str`              | Path of the file within the domain.                                                | *required* |
| `backup_directory` | `Union[str, Path]` | Path of the backup directory.                                                      | `'.'`      |
| `password`         | `str`              | Password of the backup; required if the backup is encrypted.                       | `''`       |
| `source`           | `str`              | Identifier of the device to extract from; defaults to the connected device's UDID. | `''`       |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def extract(
    self,
    domain_name: str,
    relative_path: str,
    backup_directory: Union[str, Path] = ".",
    password: str = "",
    source: str = "",
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
    self._assert_backup_exists(backup_dir, source if source else self._udid)
    async with self.device_link(backup_dir) as dl:
        message: dict[str, Any] = {
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
```

### change_password

```
change_password(backup_directory: Union[str, Path] = '.', old: str = '', new: str = '') -> None
```

Change, enable, or disable the device's backup encryption password.

Parameters:

| Name               | Type               | Description                                              | Default |
| ------------------ | ------------------ | -------------------------------------------------------- | ------- |
| `backup_directory` | `Union[str, Path]` | Path of the backup directory.                            | `'.'`   |
| `old`              | `str`              | Previous password. Omit when enabling backup encryption. | `''`    |
| `new`              | `str`              | New password. Omit when disabling backup encryption.     | `''`    |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def change_password(self, backup_directory: Union[str, Path] = ".", old: str = "", new: str = "") -> None:
    """
    Change, enable, or disable the device's backup encryption password.

    :param backup_directory: Path of the backup directory.
    :param old: Previous password. Omit when enabling backup encryption.
    :param new: New password. Omit when disabling backup encryption.
    """
    async with self.device_link(Path(backup_directory)) as dl:
        message: dict[str, Any] = {"MessageName": "ChangePassword", "TargetIdentifier": self.lockdown.udid}
        if old:
            message["OldPassword"] = old
        if new:
            message["NewPassword"] = new
        await dl.send_process_message(message)
        await dl.dl_loop()
```

### set_cloud_backup

```
set_cloud_backup(enabled: bool) -> None
```

Turn iCloud Backup on or off.

The device refuses with `MBErrorDomain/1` when no iCloud account is signed in.

Parameters:

| Name      | Type   | Description                                          | Default    |
| --------- | ------ | ---------------------------------------------------- | ---------- |
| `enabled` | `bool` | True to turn iCloud Backup on, False to turn it off. | *required* |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def set_cloud_backup(self, enabled: bool) -> None:
    """
    Turn iCloud Backup on or off.

    The device refuses with ``MBErrorDomain/1`` when no iCloud account is signed in.

    :param enabled: True to turn iCloud Backup on, False to turn it off.
    """
    # no files are exchanged, but the device link needs a root directory
    with tempfile.TemporaryDirectory() as root:
        async with self.device_link(Path(root)) as dl:
            await dl.send_process_message({
                "MessageName": "EnableCloudBackup",
                "TargetIdentifier": self.lockdown.udid,
                "CloudBackupState": enabled,
            })
            await dl.dl_loop()
```

### erase_device

```
erase_device(backup_directory: Union[str, Path] = '.') -> None
```

Erase the device, restoring it to factory state.

The device drops the link once it starts erasing; that termination is suppressed so the call returns cleanly.

Parameters:

| Name               | Type               | Description                                                    | Default |
| ------------------ | ------------------ | -------------------------------------------------------------- | ------- |
| `backup_directory` | `Union[str, Path]` | Path of the backup directory used for the device link channel. | `'.'`   |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def erase_device(self, backup_directory: Union[str, Path] = ".") -> None:
    """
    Erase the device, restoring it to factory state.

    The device drops the link once it starts erasing; that termination is suppressed so the
    call returns cleanly.

    :param backup_directory: Path of the backup directory used for the device link channel.
    """
    async with self.device_link(Path(backup_directory)) as dl:
        await dl.send_process_message({"MessageName": "EraseDevice", "TargetIdentifier": self.lockdown.udid})
        with suppress(ConnectionTerminatedError):
            await dl.dl_loop()
```

### version_exchange

```
version_exchange(dl: DeviceLink, local_versions: Optional[Sequence[float]] = None) -> None
```

Exchange protocol versions with the device and assert it supports one of ours.

Parameters:

| Name             | Type                        | Description                                                              | Default    |
| ---------------- | --------------------------- | ------------------------------------------------------------------------ | ---------- |
| `dl`             | `DeviceLink`                | An initialized device link channel.                                      | *required* |
| `local_versions` | `Optional[Sequence[float]]` | Protocol versions supported by the host; defaults to SUPPORTED_VERSIONS. | `None`     |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def version_exchange(self, dl: DeviceLink, local_versions: Optional[Sequence[float]] = None) -> None:
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
```

### init_mobile_backup_factory_info

```
init_mobile_backup_factory_info(afc: AfcService) -> dict[str, Any]
```

Build the Info.plist dictionary describing the device for a new backup.

Collects device identity values, the list of installed user apps (with their SINF and iTunes metadata where available), and the iTunes control files needed to make the backup restorable.

Parameters:

| Name  | Type         | Description                                                         | Default    |
| ----- | ------------ | ------------------------------------------------------------------- | ---------- |
| `afc` | `AfcService` | An open AFC service used to read the device's iTunes control files. | *required* |

Returns:

| Type             | Description                                        |
| ---------------- | -------------------------------------------------- |
| `dict[str, Any]` | The assembled Info.plist contents as a dictionary. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
async def init_mobile_backup_factory_info(self, afc: AfcService) -> dict[str, Any]:
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
        installed_apps: list[Any] = []
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

        ret: dict[str, Any] = {
            "iTunes Version": min_itunes_version if min_itunes_version else "10.0.1",
            "iTunes Files": files,
            "Unique Identifier": self._udid.upper(),
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
```

### resolve_backup_selection

```
resolve_backup_selection(only: Optional[Sequence[str]]) -> tuple[BackupSelectionRule, ...]
```

Map preset selection names (e.g. "sms", "contacts") to their `BackupSelectionRule` sets.

Names are matched case-insensitively against the built-in `BACKUP_SELECTIONS` presets.

Parameters:

| Name   | Type                      | Description                                                               | Default    |
| ------ | ------------------------- | ------------------------------------------------------------------------- | ---------- |
| `only` | `Optional[Sequence[str]]` | Selection names to resolve. If None or empty, no selections are resolved. | *required* |

Returns:

| Type                              | Description                                                                    |
| --------------------------------- | ------------------------------------------------------------------------------ |
| `tuple[BackupSelectionRule, ...]` | The combined rules for all resolved names, or an empty tuple if only is empty. |

Raises:

| Type                       | Description                                                                                    |
| -------------------------- | ---------------------------------------------------------------------------------------------- |
| `PyMobileDevice3Exception` | If a name is not a known preset; the message lists the invalid name and all available presets. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
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

    rules: list[BackupSelectionRule] = []
    for selection_name in only:
        try:
            selection = BackupSelection(selection_name.lower())
        except ValueError:
            available = ", ".join(sorted(BACKUP_SELECTIONS))
            raise PyMobileDevice3Exception(
                f"Unsupported backup selection: {selection_name}. Available: {available}"
            ) from None
        rules.extend(selection.rules())
    return tuple(rules)
```

### should_preserve_backup_file

```
should_preserve_backup_file(file_name: str, device_name: str, filter_callback: Optional[BackupFilterCallback]) -> bool
```

Decide whether a backup file should be preserved.

Known backup metadata files (`BACKUP_METADATA_FILES`) are always preserved. With no filter callback every file is preserved; otherwise the callback decides.

Parameters:

| Name              | Type                             | Description                                                                  | Default    |
| ----------------- | -------------------------------- | ---------------------------------------------------------------------------- | ---------- |
| `file_name`       | `str`                            | The file name (with or without path) to evaluate.                            | *required* |
| `device_name`     | `str`                            | The device-side name associated with the backup file.                        | *required* |
| `filter_callback` | `Optional[BackupFilterCallback]` | Optional predicate taking a BackupFile and returning whether to preserve it. | *required* |

Returns:

| Type   | Description                                            |
| ------ | ------------------------------------------------------ |
| `bool` | True if the file should be preserved, False otherwise. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
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
```

### selection_filter_callback

```
selection_filter_callback(rules: Sequence[BackupSelectionRule]) -> BackupFilterCallback
```

Build a filter callback that keeps files matching any of the given selection rules.

The returned callback matches device-name entries via `BackupSelectionRule.matches_device_name` and manifest entries via `BackupSelectionRule.matches_manifest_entry`.

Parameters:

| Name    | Type                            | Description                                                   | Default    |
| ------- | ------------------------------- | ------------------------------------------------------------- | ---------- |
| `rules` | `Sequence[BackupSelectionRule]` | The BackupSelectionRule objects a file must match to be kept. | *required* |

Returns:

| Type                   | Description                                                        |
| ---------------------- | ------------------------------------------------------------------ |
| `BackupFilterCallback` | A BackupFilterCallback returning True for files matching any rule. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
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
```

### regex_filter_callback

```
regex_filter_callback(patterns: Sequence[str]) -> BackupFilterCallback
```

Build a filter callback that keeps files whose path matches any of the given regexes.

Patterns are searched (not fully matched) against the file's device name and against its domain/relative-path combinations.

Parameters:

| Name       | Type            | Description                                             | Default    |
| ---------- | --------------- | ------------------------------------------------------- | ---------- |
| `patterns` | `Sequence[str]` | Regular expression patterns used to match backup files. | *required* |

Returns:

| Type                   | Description                                                           |
| ---------------------- | --------------------------------------------------------------------- |
| `BackupFilterCallback` | A BackupFilterCallback returning True for files matching any pattern. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
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
        candidates: list[str] = []
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
```

### combine_filter_callbacks

```
combine_filter_callbacks(*callbacks: Optional[BackupFilterCallback]) -> Optional[BackupFilterCallback]
```

Combine several filter callbacks into one that keeps a file if any of them keeps it.

None entries are ignored.

Parameters:

| Name        | Type                             | Description                                         | Default |
| ----------- | -------------------------------- | --------------------------------------------------- | ------- |
| `callbacks` | `Optional[BackupFilterCallback]` | Optional BackupFilterCallback functions to combine. | `()`    |

Returns:

| Type                             | Description                                                                  |
| -------------------------------- | ---------------------------------------------------------------------------- |
| `Optional[BackupFilterCallback]` | A combined BackupFilterCallback, or None if no non-None callbacks are given. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
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
```

### prune_backup_directory

```
prune_backup_directory(device_directory: Path, filter_callback: Optional[BackupFilterCallback], password: str = '') -> None
```

Delete on-disk backup files rejected by the filter, keeping metadata and allowed files.

First prunes the manifest to the set of allowed file IDs, then removes any stored files (and now-empty hash-prefix directories) not in that set. Backup metadata files are always kept.

Parameters:

| Name               | Type                             | Description                                                          | Default    |
| ------------------ | -------------------------------- | -------------------------------------------------------------------- | ---------- |
| `device_directory` | `Path`                           | Path of the per-device backup directory to prune.                    | *required* |
| `filter_callback`  | `Optional[BackupFilterCallback]` | Predicate selecting which files to keep; if None, nothing is pruned. | *required* |
| `password`         | `str`                            | Backup password; required when the backup is encrypted.              | `''`       |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
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
```

### prune_backup_manifest

```
prune_backup_manifest(device_directory: Path, filter_callback: Optional[BackupFilterCallback], password: str = '') -> set[str]
```

Prune Manifest.db to the files the filter keeps and return their file IDs.

For encrypted backups the manifest is transparently decrypted, pruned, and re-encrypted in place using the password-derived key.

Parameters:

| Name               | Type                             | Description                                                        | Default    |
| ------------------ | -------------------------------- | ------------------------------------------------------------------ | ---------- |
| `device_directory` | `Path`                           | Path of the per-device backup directory.                           | *required* |
| `filter_callback`  | `Optional[BackupFilterCallback]` | Predicate selecting which files to keep; if None, nothing is kept. | *required* |
| `password`         | `str`                            | Backup password; required when the backup is encrypted.            | `''`       |

Returns:

| Type       | Description                         |
| ---------- | ----------------------------------- |
| `set[str]` | The set of file IDs that were kept. |

Raises:

| Type                                | Description                                          |
| ----------------------------------- | ---------------------------------------------------- |
| `BackupFilterPasswordRequiredError` | If the backup is encrypted and no password is given. |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
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
```

### device_link

```
device_link(backup_directory: Path, filter_callback: Optional[BackupFilterCallback] = None, password: str = '')
```

Async context manager yielding a connected `DeviceLink` for backup operations.

Performs the device-link and mobilebackup2 version exchanges on entry and disconnects on exit. The given filter callback governs which incoming files are written to disk.

Parameters:

| Name               | Type                             | Description                                                        | Default    |
| ------------------ | -------------------------------- | ------------------------------------------------------------------ | ---------- |
| `backup_directory` | `Path`                           | Directory the device link reads from and writes to.                | *required* |
| `filter_callback`  | `Optional[BackupFilterCallback]` | Optional predicate controlling which files are preserved.          | `None`     |
| `password`         | `str`                            | Backup password (unused here directly; passed through by callers). | `''`       |

Source code in `pymobiledevice3/services/mobilebackup2.py`

```
@asynccontextmanager
async def device_link(
    self, backup_directory: Path, filter_callback: Optional[BackupFilterCallback] = None, password: str = ""
):
    """
    Async context manager yielding a connected `DeviceLink` for backup operations.

    Performs the device-link and mobilebackup2 version exchanges on entry and disconnects
    on exit. The given filter callback governs which incoming files are written to disk.

    :param backup_directory: Directory the device link reads from and writes to.
    :param filter_callback: Optional predicate controlling which files are preserved.
    :param password: Backup password (unused here directly; passed through by callers).
    """
    await self.connect()
    assert self._service is not None
    dl = DeviceLink(
        self._service,
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
        # The device may already have dropped the link (often the reason we are exiting), and
        # a failed DLMessageDisconnect must not replace the error that ended the session.
        with suppress(ConnectionTerminatedError):
            await dl.disconnect()
```

## pymobiledevice3.services.dtfetchsymbols.DtFetchSymbols

Client for the `com.apple.dt.fetchsymbols` developer service.

Lists and downloads the device's shared cache (DSC) symbol files, used by debuggers to symbolicate addresses without a copy of the device's binaries on the host. A fresh lockdown developer service connection is opened for each command.

Source code in `pymobiledevice3/services/dtfetchsymbols.py`

```
class DtFetchSymbols:
    """
    Client for the `com.apple.dt.fetchsymbols` developer service.

    Lists and downloads the device's shared cache (DSC) symbol files, used by debuggers
    to symbolicate addresses without a copy of the device's binaries on the host. A fresh
    lockdown developer service connection is opened for each command.
    """

    SERVICE_NAME = "com.apple.dt.fetchsymbols"
    MAX_CHUNK = 1024 * 1024 * 10  # 10MB
    CMD_LIST_FILES_PLIST = struct.pack(">I", 0x30303030)
    CMD_GET_FILE = struct.pack(">I", 1)

    def __init__(self, lockdown: LockdownServiceProvider):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

    async def list_files(self) -> list[str]:
        """
        List the symbol files available on the device.

        :returns: File names, indexed in the same order the index passed to `get_file` refers to.
        """
        service = await self._start_command(self.CMD_LIST_FILES_PLIST)
        files = (await service.recv_plist()).get("files")
        await service.close()
        if files is None:
            raise ProtocolError("The device's symbol file list reply did not include any files.")
        return typing.cast(list[str], files)

    async def get_file(self, fileno: int, stream: typing.IO[bytes], max_bytes: typing.Optional[int] = None):
        """
        Download a single symbol file and write it into the given stream.

        :param fileno: Index of the file to fetch, as returned by `list_files`.
        :param stream: Writable binary stream the file contents are written to in chunks.
        :param max_bytes: Optional cap on the number of bytes to read; when None the whole
            file is downloaded.
        """
        service = await self._start_command(self.CMD_GET_FILE)
        await service.sendall(struct.pack(">I", fileno))

        size = struct.unpack(">Q", await service.recvall(8))[0]
        self.logger.debug(f"file size: {size}")

        limit = size if max_bytes is None else min(size, max_bytes)
        received = 0
        while received < limit:
            chunk_size = min(limit - received, self.MAX_CHUNK)
            buf = await service.recvall(chunk_size)
            stream.write(buf)
            received += len(buf)
        await service.close()

    async def _start_command(self, cmd: bytes):
        service = await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        await service.sendall(cmd)

        # receive same command as an ack
        if cmd != await service.recvall(len(cmd)):
            raise ProtocolError("The device did not acknowledge the symbol fetch command.")

        return service
```

### list_files

```
list_files() -> list[str]
```

List the symbol files available on the device.

Returns:

| Type        | Description                                                                   |
| ----------- | ----------------------------------------------------------------------------- |
| `list[str]` | File names, indexed in the same order the index passed to get_file refers to. |

Source code in `pymobiledevice3/services/dtfetchsymbols.py`

```
async def list_files(self) -> list[str]:
    """
    List the symbol files available on the device.

    :returns: File names, indexed in the same order the index passed to `get_file` refers to.
    """
    service = await self._start_command(self.CMD_LIST_FILES_PLIST)
    files = (await service.recv_plist()).get("files")
    await service.close()
    if files is None:
        raise ProtocolError("The device's symbol file list reply did not include any files.")
    return typing.cast(list[str], files)
```

### get_file

```
get_file(fileno: int, stream: IO[bytes], max_bytes: Optional[int] = None)
```

Download a single symbol file and write it into the given stream.

Parameters:

| Name        | Type            | Description                                                                          | Default    |
| ----------- | --------------- | ------------------------------------------------------------------------------------ | ---------- |
| `fileno`    | `int`           | Index of the file to fetch, as returned by list_files.                               | *required* |
| `stream`    | `IO[bytes]`     | Writable binary stream the file contents are written to in chunks.                   | *required* |
| `max_bytes` | `Optional[int]` | Optional cap on the number of bytes to read; when None the whole file is downloaded. | `None`     |

Source code in `pymobiledevice3/services/dtfetchsymbols.py`

```
async def get_file(self, fileno: int, stream: typing.IO[bytes], max_bytes: typing.Optional[int] = None):
    """
    Download a single symbol file and write it into the given stream.

    :param fileno: Index of the file to fetch, as returned by `list_files`.
    :param stream: Writable binary stream the file contents are written to in chunks.
    :param max_bytes: Optional cap on the number of bytes to read; when None the whole
        file is downloaded.
    """
    service = await self._start_command(self.CMD_GET_FILE)
    await service.sendall(struct.pack(">I", fileno))

    size = struct.unpack(">Q", await service.recvall(8))[0]
    self.logger.debug(f"file size: {size}")

    limit = size if max_bytes is None else min(size, max_bytes)
    received = 0
    while received < limit:
        chunk_size = min(limit - received, self.MAX_CHUNK)
        buf = await service.recvall(chunk_size)
        stream.write(buf)
        received += len(buf)
    await service.close()
```

## pymobiledevice3.services.remote_fetch_symbols.RemoteFetchSymbolsService

Bases: `RemoteService`

Client for the `com.apple.dt.remoteFetchSymbols` RemoteXPC service (RSD/CoreDevice).

Lists the device's dyld shared cache (DSC) files and downloads them to the host, preserving their on-device directory layout. Downloads run concurrently across up to `MAX_CONCURRENT_DOWNLOADS` workers.

Inherits async context manager support from `RemoteService`; use within an `async with` block to manage the underlying connection.

Source code in `pymobiledevice3/services/remote_fetch_symbols.py`

```
class RemoteFetchSymbolsService(RemoteService):
    """
    Client for the `com.apple.dt.remoteFetchSymbols` RemoteXPC service (RSD/CoreDevice).

    Lists the device's dyld shared cache (DSC) files and downloads them to the host,
    preserving their on-device directory layout. Downloads run concurrently across up to
    `MAX_CONCURRENT_DOWNLOADS` workers.

    Inherits async context manager support from `RemoteService`; use within an
    ``async with`` block to manage the underlying connection.
    """

    SERVICE_NAME = "com.apple.dt.remoteFetchSymbols"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def get_dsc_file_list(self) -> list[DSCFile]:
        """
        Query the device for the list of available DSC files.

        :returns: One `DSCFile` per advertised file, each carrying its on-device path and
            expected byte length.
        :raises DeviceFeatureNotSupportedError: if the device does not advertise the DSC
            fetching capability.
        """
        self.rsd.require_feature(self.SERVICE_NAME, FEATURE_DSC_FILES)
        files: list[DSCFile] = []
        response = await self.service.send_receive_request({
            "XPCDictionary_sideChannel": uuid.uuid4(),
            "DSCFilePaths": [],
        })
        file_count = response["DSCFilePaths"]
        for _i in range(file_count):
            response = await self.service.receive_response()
            response = response["DSCFilePaths"]
            file_transfer = response["fileTransfer"]
            expected_length = file_transfer["expectedLength"]
            file_path = response["filePath"]
            files.append(DSCFile(file_path=file_path, file_size=expected_length))
        return files

    async def download(self, out: Path, force: bool = True) -> None:
        """
        Download all DSC files into a local directory, reproducing their device paths.

        Each file is written under `out` at its device-relative path (the leading "/" is
        stripped), and progress is shown via a progress bar.

        :param out: Destination directory; intermediate parent directories are created as needed.
        :param force: Download files which already exist in `out` with the size the device reports,
            instead of keeping them.
        """
        files = await self.get_dsc_file_list()
        file_indexes: asyncio.Queue[int] = asyncio.Queue()
        total = 0
        for i, file in enumerate(files):
            if not force:
                out_file = resolve_device_path(out, file.file_path.removeprefix("/"))
                if out_file.is_file() and out_file.stat().st_size == file.file_size:
                    logger.info(f"Keeping the already downloaded {out_file}")
                    continue
            file_indexes.put_nowait(i)
            total += file.file_size
        if file_indexes.empty():
            return

        with ProgressBar(total=total, desc="dyld_shared_cache", unit=BYTES_UNIT) as pb:
            workers = [self._download_files(files, file_indexes, out, pb) for _ in files[:MAX_CONCURRENT_DOWNLOADS]]
            await asyncio.gather(*workers)

    async def _download_files(
        self, files: list[DSCFile], file_indexes: asyncio.Queue[int], out: Path, pb: ProgressBar
    ) -> None:
        while True:
            try:
                i = file_indexes.get_nowait()
            except asyncio.QueueEmpty:
                return

            file = files[i]
            out_file = resolve_device_path(out, file.file_path.removeprefix("/"))
            out_file.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file, "wb") as f:
                async for chunk in self.service.iter_file_chunks(file.file_size, file_idx=i):
                    f.write(chunk)
                    pb.update(len(chunk))
```

### get_dsc_file_list

```
get_dsc_file_list() -> list[DSCFile]
```

Query the device for the list of available DSC files.

Returns:

| Type            | Description                                                                                 |
| --------------- | ------------------------------------------------------------------------------------------- |
| `list[DSCFile]` | One DSCFile per advertised file, each carrying its on-device path and expected byte length. |

Raises:

| Type                             | Description                                                   |
| -------------------------------- | ------------------------------------------------------------- |
| `DeviceFeatureNotSupportedError` | if the device does not advertise the DSC fetching capability. |

Source code in `pymobiledevice3/services/remote_fetch_symbols.py`

```
async def get_dsc_file_list(self) -> list[DSCFile]:
    """
    Query the device for the list of available DSC files.

    :returns: One `DSCFile` per advertised file, each carrying its on-device path and
        expected byte length.
    :raises DeviceFeatureNotSupportedError: if the device does not advertise the DSC
        fetching capability.
    """
    self.rsd.require_feature(self.SERVICE_NAME, FEATURE_DSC_FILES)
    files: list[DSCFile] = []
    response = await self.service.send_receive_request({
        "XPCDictionary_sideChannel": uuid.uuid4(),
        "DSCFilePaths": [],
    })
    file_count = response["DSCFilePaths"]
    for _i in range(file_count):
        response = await self.service.receive_response()
        response = response["DSCFilePaths"]
        file_transfer = response["fileTransfer"]
        expected_length = file_transfer["expectedLength"]
        file_path = response["filePath"]
        files.append(DSCFile(file_path=file_path, file_size=expected_length))
    return files
```

### download

```
download(out: Path, force: bool = True) -> None
```

Download all DSC files into a local directory, reproducing their device paths.

Each file is written under `out` at its device-relative path (the leading "/" is stripped), and progress is shown via a progress bar.

Parameters:

| Name    | Type   | Description                                                                                          | Default    |
| ------- | ------ | ---------------------------------------------------------------------------------------------------- | ---------- |
| `out`   | `Path` | Destination directory; intermediate parent directories are created as needed.                        | *required* |
| `force` | `bool` | Download files which already exist in out with the size the device reports, instead of keeping them. | `True`     |

Source code in `pymobiledevice3/services/remote_fetch_symbols.py`

```
async def download(self, out: Path, force: bool = True) -> None:
    """
    Download all DSC files into a local directory, reproducing their device paths.

    Each file is written under `out` at its device-relative path (the leading "/" is
    stripped), and progress is shown via a progress bar.

    :param out: Destination directory; intermediate parent directories are created as needed.
    :param force: Download files which already exist in `out` with the size the device reports,
        instead of keeping them.
    """
    files = await self.get_dsc_file_list()
    file_indexes: asyncio.Queue[int] = asyncio.Queue()
    total = 0
    for i, file in enumerate(files):
        if not force:
            out_file = resolve_device_path(out, file.file_path.removeprefix("/"))
            if out_file.is_file() and out_file.stat().st_size == file.file_size:
                logger.info(f"Keeping the already downloaded {out_file}")
                continue
        file_indexes.put_nowait(i)
        total += file.file_size
    if file_indexes.empty():
        return

    with ProgressBar(total=total, desc="dyld_shared_cache", unit=BYTES_UNIT) as pb:
        workers = [self._download_files(files, file_indexes, out, pb) for _ in files[:MAX_CONCURRENT_DOWNLOADS]]
        await asyncio.gather(*workers)
```

## pymobiledevice3.services.simulate_location.DtSimulateLocation

Bases: `LockdownService`, `LocationSimulationBase`

Client for the `com.apple.dt.simulatelocation` developer service.

Overrides the device's reported GPS location with a fixed coordinate, or clears any previously set override. A fresh lockdown developer service connection is opened for each command.

Source code in `pymobiledevice3/services/simulate_location.py`

```
class DtSimulateLocation(LockdownService, LocationSimulationBase):
    """
    Client for the `com.apple.dt.simulatelocation` developer service.

    Overrides the device's reported GPS location with a fixed coordinate, or clears any
    previously set override. A fresh lockdown developer service connection is opened for
    each command.
    """

    SERVICE_NAME = "com.apple.dt.simulatelocation"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        LockdownService.__init__(self, lockdown, self.SERVICE_NAME)
        LocationSimulationBase.__init__(self)

    async def clear(self) -> None:
        """Stop simulating a location and restore the device's real location."""
        async with await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME) as service:
            await service.sendall(struct.pack(">I", 1))

    async def set(self, latitude: float, longitude: float) -> None:
        """
        Start simulating the given location.

        :param latitude: Latitude in decimal degrees.
        :param longitude: Longitude in decimal degrees.
        """
        encoded_latitude = str(latitude).encode()
        encoded_longitude = str(longitude).encode()
        async with await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME) as service:
            await service.sendall(struct.pack(">I", 0))
            await service.sendall(struct.pack(">I", len(encoded_latitude)) + encoded_latitude)
            await service.sendall(struct.pack(">I", len(encoded_longitude)) + encoded_longitude)
```

### clear

```
clear() -> None
```

Stop simulating a location and restore the device's real location.

Source code in `pymobiledevice3/services/simulate_location.py`

```
async def clear(self) -> None:
    """Stop simulating a location and restore the device's real location."""
    async with await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME) as service:
        await service.sendall(struct.pack(">I", 1))
```

### set

```
set(latitude: float, longitude: float) -> None
```

Start simulating the given location.

Parameters:

| Name        | Type    | Description                   | Default    |
| ----------- | ------- | ----------------------------- | ---------- |
| `latitude`  | `float` | Latitude in decimal degrees.  | *required* |
| `longitude` | `float` | Longitude in decimal degrees. | *required* |

Source code in `pymobiledevice3/services/simulate_location.py`

```
async def set(self, latitude: float, longitude: float) -> None:
    """
    Start simulating the given location.

    :param latitude: Latitude in decimal degrees.
    :param longitude: Longitude in decimal degrees.
    """
    encoded_latitude = str(latitude).encode()
    encoded_longitude = str(longitude).encode()
    async with await self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME) as service:
        await service.sendall(struct.pack(">I", 0))
        await service.sendall(struct.pack(">I", len(encoded_latitude)) + encoded_latitude)
        await service.sendall(struct.pack(">I", len(encoded_longitude)) + encoded_longitude)
```
