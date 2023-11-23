#!/usr/bin/env python3
import plistlib
import time
import uuid
from contextlib import contextmanager, suppress
from datetime import datetime
from pathlib import Path

from pymobiledevice3.exceptions import AfcException, AfcFileNotFoundError, ConnectionTerminatedError, LockdownError, \
    PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AFC_LOCK_EX, AFC_LOCK_UN, AfcService, afc_error_t
from pymobiledevice3.services.device_link import DeviceLink
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.services.notification_proxy import NotificationProxyService
from pymobiledevice3.services.springboard import SpringBoardServicesService

SUPPORTED_VERSIONS = [2.0, 2.1]
ITUNES_FILES = [
    'ApertureAlbumPrefs', 'IC-Info.sidb', 'IC-Info.sidv', 'PhotosFolderAlbums', 'PhotosFolderName',
    'PhotosFolderPrefs', 'VoiceMemos.plist', 'iPhotoAlbumPrefs', 'iTunesApplicationIDs', 'iTunesPrefs',
    'iTunesPrefs.plist'
]
NP_SYNC_WILL_START = 'com.apple.itunes-mobdev.syncWillStart'
NP_SYNC_DID_START = 'com.apple.itunes-mobdev.syncDidStart'
NP_SYNC_LOCK_REQUEST = 'com.apple.itunes-mobdev.syncLockRequest'
NP_SYNC_DID_FINISH = 'com.apple.itunes-mobdev.syncDidFinish'


class Mobilebackup2Service(LockdownService):
    SERVICE_NAME = 'com.apple.mobilebackup2'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME, include_escrow_bag=True)

    @property
    def will_encrypt(self):
        try:
            return self.lockdown.get_value('com.apple.mobile.backup', 'WillEncrypt')
        except LockdownError:
            return False

    def backup(self, full: bool = True, backup_directory='.', progress_callback=lambda x: None) -> None:
        """
        Backup a device.
        :param full: Whether to do a full backup. If full is True, any previous backup attempts will be discarded.
        :param backup_directory: Directory to write backup to.
        :param progress_callback: Function to be called as the backup progresses.
        The function shall receive the percentage as a parameter.
        """
        backup_directory = Path(backup_directory)
        device_directory = backup_directory / self.lockdown.udid
        device_directory.mkdir(exist_ok=True, mode=0o755, parents=True)

        with self.device_link(backup_directory) as dl, \
                NotificationProxyService(self.lockdown) as notification_proxy, \
                AfcService(self.lockdown) as afc:
            with self._backup_lock(afc, notification_proxy):
                # Initialize Info.plist
                info_plist = self.init_mobile_backup_factory_info(afc)
                with open(device_directory / 'Info.plist', 'wb') as fd:
                    plistlib.dump(info_plist, fd)

                # Initialize Status.plist file if doesn't exist.
                status_path = device_directory / 'Status.plist'
                current_date = datetime.now()
                current_date = current_date.replace(tzinfo=None)
                if full or not status_path.exists():
                    with open(device_directory / 'Status.plist', 'wb') as fd:
                        plistlib.dump({
                            'BackupState': 'new',
                            'Date': current_date,
                            'IsFullBackup': full,
                            'Version': '3.3',
                            'SnapshotState': 'finished',
                            'UUID': str(uuid.uuid4()).upper(),
                        }, fd, fmt=plistlib.FMT_BINARY)

                # Create Manifest.plist if doesn't exist.
                manifest_path = device_directory / 'Manifest.plist'
                if full:
                    manifest_path.unlink(missing_ok=True)
                (device_directory / 'Manifest.plist').touch()

                dl.send_process_message({'MessageName': 'Backup', 'TargetIdentifier': self.lockdown.udid})
                dl.dl_loop(progress_callback)

    def restore(self, backup_directory='.', system: bool = False, reboot: bool = True, copy: bool = True,
                settings: bool = True, remove: bool = False, password: str = '', source: str = '',
                progress_callback=lambda x: None):
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
        The function shall receive the current percentage of the progress as a parameter.
        """
        backup_directory = Path(backup_directory)
        source = source if source else self.lockdown.udid
        self._assert_backup_exists(backup_directory, source)

        with self.device_link(backup_directory) as dl, \
                NotificationProxyService(self.lockdown) as notification_proxy, \
                AfcService(self.lockdown) as afc:
            with self._backup_lock(afc, notification_proxy):
                manifest_plist_path = backup_directory / source / 'Manifest.plist'
                with open(manifest_plist_path, 'rb') as fd:
                    manifest = plistlib.load(fd)
                is_encrypted = manifest.get('IsEncrypted', False)
                options = {
                    'RestoreShouldReboot': reboot,
                    'RestoreDontCopyBackup': copy,
                    'RestorePreserveSettings': settings,
                    'RestoreSystemFiles': system,
                    'RemoveItemsNotRestored': remove,
                }
                if is_encrypted:
                    if password:
                        options['Password'] = password
                    else:
                        self.logger.error('Backup is encrypted, please supply password.')
                        return
                dl.send_process_message({
                    'MessageName': 'Restore',
                    'TargetIdentifier': self.lockdown.udid,
                    'SourceIdentifier': source,
                    'Options': options,
                })
                dl.dl_loop(progress_callback)

    def info(self, backup_directory='.', source: str = '') -> str:
        """
        Get information about a backup.
        :param backup_directory: Path of the backup directory.
        :param source: Identifier of device to get info about its backup.
        :return: Information about a backup.
        """
        backup_dir = Path(backup_directory)
        self._assert_backup_exists(backup_dir, source if source else self.lockdown.udid)
        with self.device_link(backup_dir) as dl:
            message = {'MessageName': 'Info', 'TargetIdentifier': self.lockdown.udid}
            if source:
                message['SourceIdentifier'] = source
            dl.send_process_message(message)
            result = dl.dl_loop()
        return result

    def list(self, backup_directory='.', source: str = '') -> str:
        """
        List the files in the last backup.
        :param backup_directory: Path of the backup directory.
        :param source: Identifier of device to list its backup data.
        :return: List of files and additional data about each file, all in a CSV format.
        """
        backup_dir = Path(backup_directory)
        source = source if source else self.lockdown.udid
        self._assert_backup_exists(backup_dir, source)
        with self.device_link(backup_dir) as dl:
            dl.send_process_message({
                'MessageName': 'List', 'TargetIdentifier': self.lockdown.udid, 'SourceIdentifier': source,
            })
            result = dl.dl_loop()
        return result

    def unback(self, backup_directory='.', password: str = '', source: str = '') -> None:
        """
        Unpack a complete backup to its device hierarchy.
        :param backup_directory: Path of the backup directory.
        :param password: Password of the backup if it is encrypted.
        :param source: Identifier of device to unpack its backup.
        """
        backup_dir = Path(backup_directory)
        self._assert_backup_exists(backup_dir, source if source else self.lockdown.udid)
        with self.device_link(backup_dir) as dl:
            message = {'MessageName': 'Unback', 'TargetIdentifier': self.lockdown.udid}
            if source:
                message['SourceIdentifier'] = source
            if password:
                message['Password'] = password
            dl.send_process_message(message)
            dl.dl_loop()

    def extract(self, domain_name: str, relative_path: str, backup_directory='.', password: str = '',
                source: str = '') -> None:
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
        with self.device_link(backup_dir) as dl:
            message = {
                'MessageName': 'Extract', 'TargetIdentifier': self.lockdown.udid, 'DomainName': domain_name,
                'RelativePath': relative_path
            }
            if source:
                message['SourceIdentifier'] = source
            if password:
                message['Password'] = password
            dl.send_process_message(message)
            dl.dl_loop()

    def change_password(self, backup_directory='.', old: str = '', new: str = '') -> None:
        """
        Change backup password.
        :param backup_directory: Backups directory.
        :param old: Previous password. Omit when enabling backup encryption.
        :param new: New password. Omit when disabling backup encryption.
        """
        with self.device_link(Path(backup_directory)) as dl:
            message = {'MessageName': 'ChangePassword', 'TargetIdentifier': self.lockdown.udid}
            if old:
                message['OldPassword'] = old
            if new:
                message['NewPassword'] = new
            dl.send_process_message(message)
            dl.dl_loop()

    def erase_device(self, backup_directory='.') -> None:
        """
        Erase the device.
        """
        with suppress(ConnectionTerminatedError):
            with self.device_link(Path(backup_directory)) as dl:
                dl.send_process_message({'MessageName': 'EraseDevice', 'TargetIdentifier': self.lockdown.udid})
                dl.dl_loop()

    def version_exchange(self, dl: DeviceLink, local_versions=None) -> None:
        """
        Exchange versions with the device and assert that the device supports our version of the protocol.
        :param dl: Initialized device link.
        :param local_versions: versions supported by us.
        """
        if local_versions is None:
            local_versions = SUPPORTED_VERSIONS
        dl.send_process_message({
            'MessageName': 'Hello',
            'SupportedProtocolVersions': local_versions,
        })
        reply = dl.receive_message()
        assert reply[0] == 'DLMessageProcessMessage' and reply[1]['ErrorCode'] == 0
        assert reply[1]['ProtocolVersion'] in local_versions

    def init_mobile_backup_factory_info(self, afc: AfcService):
        with InstallationProxyService(self.lockdown) as ip, SpringBoardServicesService(self.lockdown) as sbs:
            root_node = self.lockdown.get_value()
            itunes_settings = self.lockdown.get_value(domain='com.apple.iTunes')
            min_itunes_version = self.lockdown.get_value('com.apple.mobile.iTunes', 'MinITunesVersion')
            app_dict = {}
            installed_apps = []
            apps = ip.browse(options={'ApplicationType': 'User'},
                             attributes=['CFBundleIdentifier', 'ApplicationSINF', 'iTunesMetadata'])
            for app in apps:
                bundle_id = app['CFBundleIdentifier']
                if bundle_id:
                    installed_apps.append(bundle_id)
                    if app.get('iTunesMetadata', False) and app.get('ApplicationSINF', False):
                        app_dict[bundle_id] = {
                            'ApplicationSINF': app['ApplicationSINF'],
                            'iTunesMetadata': app['iTunesMetadata'],
                            'PlaceholderIcon': sbs.get_icon_pngdata(bundle_id),
                        }

            files = {}
            for file in ITUNES_FILES:
                try:
                    data_buf = afc.get_file_contents('/iTunes_Control/iTunes/' + file)
                except AfcFileNotFoundError:
                    pass
                else:
                    files[file] = data_buf

            ret = {
                'iTunes Version': min_itunes_version if min_itunes_version else '10.0.1',
                'iTunes Files': files,
                'Unique Identifier': self.lockdown.udid.upper(),
                'Target Type': 'Device',
                'Target Identifier': root_node['UniqueDeviceID'],
                'Serial Number': root_node['SerialNumber'],
                'Product Version': root_node['ProductVersion'],
                'Product Type': root_node['ProductType'],
                'Installed Applications': installed_apps,
                'GUID': uuid.uuid4().bytes,
                'Display Name': root_node['DeviceName'],
                'Device Name': root_node['DeviceName'],
                'Build Version': root_node['BuildVersion'],
                'Applications': app_dict,
            }

            if 'IntegratedCircuitCardIdentity' in root_node:
                ret['ICCID'] = root_node['IntegratedCircuitCardIdentity']
            if 'InternationalMobileEquipmentIdentity' in root_node:
                ret['IMEI'] = root_node['InternationalMobileEquipmentIdentity']
            if 'MobileEquipmentIdentifier' in root_node:
                ret['MEID'] = root_node['MobileEquipmentIdentifier']
            if 'PhoneNumber' in root_node:
                ret['Phone Number'] = root_node['PhoneNumber']

            try:
                data_buf = afc.get_file_contents('/Books/iBooksData2.plist')
            except AfcFileNotFoundError:
                pass
            else:
                ret['iBooks Data 2'] = data_buf
            if itunes_settings:
                ret['iTunes Settings'] = itunes_settings
            return ret

    @contextmanager
    def _backup_lock(self, afc, notification_proxy):
        notification_proxy.notify_post(NP_SYNC_WILL_START)
        lockfile = afc.fopen('/com.apple.itunes.lock_sync', 'r+')
        if lockfile:
            notification_proxy.notify_post(NP_SYNC_LOCK_REQUEST)
            for _ in range(50):
                try:
                    afc.lock(lockfile, AFC_LOCK_EX)
                except AfcException as e:
                    if e.status == afc_error_t.OP_WOULD_BLOCK:
                        time.sleep(0.2)
                    else:
                        afc.fclose(lockfile)
                        raise
                else:
                    notification_proxy.notify_post(NP_SYNC_DID_START)
                    break
            else:  # No break, lock failed.
                afc.fclose(lockfile)
                raise PyMobileDevice3Exception('Failed to lock itunes sync file')
        try:
            yield
        finally:
            afc.lock(lockfile, AFC_LOCK_UN)
            afc.fclose(lockfile)
            notification_proxy.notify_post(NP_SYNC_DID_FINISH)

    @staticmethod
    def _assert_backup_exists(backup_directory: Path, identifier: str):
        device_directory = backup_directory / identifier
        assert (device_directory / 'Info.plist').exists()
        assert (device_directory / 'Manifest.plist').exists()
        assert (device_directory / 'Status.plist').exists()

    @contextmanager
    def device_link(self, backup_directory):
        dl = DeviceLink(self.service, backup_directory)
        dl.version_exchange()
        self.version_exchange(dl)
        try:
            yield dl
        finally:
            dl.disconnect()
