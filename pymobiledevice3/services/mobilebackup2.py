#!/usr/bin/env python3
import logging
from pathlib import Path
import time
import uuid
import plistlib
from datetime import datetime
from contextlib import contextmanager

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.exceptions import PyMobileDevice3Exception, AfcFileNotFoundError, AfcException
from pymobiledevice3.services.afc import AfcService, AFC_LOCK_EX, afc_error_t, AFC_LOCK_UN
from pymobiledevice3.services.device_link import DeviceLink
from pymobiledevice3.services.installation_proxy import InstallationProxyService
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


class Mobilebackup2Service:
    SERVICE_NAME = 'com.apple.mobilebackup2'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.SERVICE_NAME)

    def backup(self, full=True, backup_directory=Path('.'), progress_callback=lambda x: None):
        backup_directory = Path(backup_directory)
        device_directory = backup_directory / self.lockdown.identifier
        device_directory.mkdir(exist_ok=True, mode=0o755, parents=True)

        with self.device_link(backup_directory) as dl:
            notification_proxy = NotificationProxyService(self.lockdown)
            afc = AfcService(self.lockdown)

            with self._backup_lock(afc, notification_proxy):
                # Initialize Info.plist
                info_plist = self.init_mobile_backup_factory_info(afc)
                with open(device_directory / 'Info.plist', 'wb') as fd:
                    plistlib.dump(info_plist, fd)

                # Initialize Status.plist file if doesn't exist.
                status_path = device_directory / 'Status.plist'
                if full or not status_path.exists():
                    with open(device_directory / 'Status.plist', 'wb') as fd:
                        plistlib.dump({
                            'BackupState': 'new',
                            'Date': datetime.utcnow(),
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

                dl.send_process_message({'MessageName': 'Backup', 'TargetIdentifier': self.lockdown.identifier})
                dl.dl_loop(progress_callback)

    def restore(self, backup_directory=Path('.'), system=False, reboot=True, copy=True, settings=True, remove=False,
                password='', progress_callback=lambda x: None):
        backup_directory = Path(backup_directory)
        device_directory = backup_directory / self.lockdown.identifier
        assert device_directory.exists()

        with self.device_link(backup_directory) as dl:
            notification_proxy = NotificationProxyService(self.lockdown)
            afc = AfcService(self.lockdown)

            with self._backup_lock(afc, notification_proxy):
                assert (device_directory / 'Info.plist').exists()
                manifest_plist_path = device_directory / 'Manifest.plist'
                assert manifest_plist_path.exists()
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
                    'TargetIdentifier': self.lockdown.identifier,
                    'SourceIdentifier': self.lockdown.identifier,
                    'Options': options,
                })
                dl.dl_loop(progress_callback)

    def info(self, backup_directory=Path('.')):
        with self.device_link(Path(backup_directory)) as dl:
            dl.send_process_message({'MessageName': 'Info', 'TargetIdentifier': self.lockdown.identifier})
            result = dl.dl_loop()
        return result

    def list(self, backup_directory=Path('.')):
        with self.device_link(Path(backup_directory)) as dl:
            dl.send_process_message({
                'MessageName': 'List', 'TargetIdentifier': self.lockdown.identifier,
                'SourceIdentifier': self.lockdown.identifier
            })
            result = dl.dl_loop()
        return result

    def unback(self, backup_directory=Path('.'), password=''):
        device_directory = Path(backup_directory) / self.lockdown.identifier
        assert (device_directory / 'Info.plist').exists()
        assert (device_directory / 'Manifest.plist').exists()
        with self.device_link(Path(backup_directory)) as dl:
            message = {'MessageName': 'Unback', 'TargetIdentifier': self.lockdown.identifier}
            if password:
                message['Password'] = password
            dl.send_process_message(message)
            result = dl.dl_loop()
        return result

    def extract(self, domain_name, relative_path, backup_directory=Path('.'), password=''):
        device_directory = backup_directory / self.lockdown.identifier
        assert (device_directory / 'Info.plist').exists()
        assert (device_directory / 'Manifest.plist').exists()
        with self.device_link(Path(backup_directory)) as dl:
            message = {
                'MessageName': 'Extract', 'TargetIdentifier': self.lockdown.identifier, 'DomainName': domain_name,
                'RelativePath': relative_path
            }
            if password:
                message['Password'] = password
            dl.send_process_message(message)
            result = dl.dl_loop()
        return result

    def change_password(self, backup_directory=Path('.'), old='', new=''):
        with self.device_link(Path(backup_directory)) as dl:
            message = {'MessageName': 'ChangePassword', 'TargetIdentifier': self.lockdown.identifier}
            if old:
                message['OldPassword'] = old
            if new:
                message['NewPassword'] = new
            dl.send_process_message(message)
            dl.dl_loop()

    def erase_device(self, backup_directory=Path('.')):
        with self.device_link(Path(backup_directory)) as dl:
            dl.send_process_message({'MessageName': 'EraseDevice', 'TargetIdentifier': self.lockdown.identifier})
            dl.dl_loop()

    def version_exchange(self, dl: DeviceLink, local_versions=None):
        if local_versions is None:
            local_versions = SUPPORTED_VERSIONS
        dl.send_process_message({
            'MessageName': 'Hello',
            'SupportedProtocolVersions': local_versions,
        })
        reply = dl.receive_message()
        assert reply[0] == 'DLMessageProcessMessage' and reply[1]['ErrorCode'] == 0
        assert reply[1]['ProtocolVersion'] in SUPPORTED_VERSIONS

    def init_mobile_backup_factory_info(self, afc: AfcService):
        ip = InstallationProxyService(self.lockdown)
        sbs = SpringBoardServicesService(self.lockdown)

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
            'Unique Identifier': self.lockdown.identifier.upper(),
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

    @contextmanager
    def device_link(self, backup_directory):
        dl = DeviceLink(self.service, backup_directory)
        dl.version_exchange()
        self.version_exchange(dl)
        try:
            yield dl
        finally:
            dl.disconnect()
