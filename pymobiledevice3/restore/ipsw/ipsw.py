import plistlib
import zipfile
from contextlib import contextmanager
from io import BytesIO

from pymobiledevice3.exceptions import PyMobileDevice3Exception


class BuildIdentity:
    def __init__(self, build_identity: dict):
        self._build_identity_dict = build_identity
        self.device_class = self._build_identity_dict['Info']['DeviceClass'].lower()
        self.restore_behavior = self._build_identity_dict['Info'].get('RestoreBehavior')

    def get_component_path(self, component: str):
        return self._build_identity_dict['Manifest'][component]['Info']['Path']


class BuildManifest:
    def __init__(self, manifest: bytes):
        self._manifest = plistlib.loads(manifest)
        self._parse_build_identities()

    def _parse_build_identities(self):
        self._build_identities = []
        for build_identity in self._manifest['BuildIdentities']:
            self._build_identities.append(BuildIdentity(build_identity))

    def get_build_identity(self, device_class: str, restore_behavior: str):
        for build_identity in self._build_identities:
            if build_identity.device_class == device_class and build_identity.restore_behavior == restore_behavior:
                return build_identity
        raise PyMobileDevice3Exception('failed to find the correct BuildIdentity from the BuildManifest')


class IPSW:
    def __init__(self, file: BytesIO):
        self._archive = zipfile.ZipFile(file)
        self.build_manifest = BuildManifest(self._archive.read('BuildManifest.plist'))

    def get_component_data(self, build_identity: BuildIdentity, component: str):
        component_path = build_identity.get_component_path(component)
        return self.get_data_from_path(component_path)

    def get_data_from_path(self, path: str):
        return self._archive.read(path)

    @contextmanager
    def open_path(self, path: str):
        file = self._archive.open(path)
        try:
            yield file
        finally:
            file.close()

    def get_global_manifest(self, macos_variant: str, device_class: str):
        manifest_path = f'Firmware/Manifests/restore/{macos_variant}/apticket.{device_class}.im4m'
        return self.get_data_from_path(manifest_path)

    def get_restore_version_plist(self):
        return self.get_data_from_path('RestoreVersion.plist')

    def get_system_version_plist(self):
        return self.get_data_from_path('SystemVersion.plist')

    def get_firmware(self, firmware_path: str):
        return Firmware(firmware_path, self)


class Firmware:
    def __init__(self, firmware_path: str, ipsw: IPSW):
        self._ipsw = ipsw
        self._firmware_path = firmware_path
        self._manifest_data = self._ipsw.get_data_from_path(self.get_relative_path('manifest'))
        self._firmware_files = {}
        for filename in self._manifest_data.splitlines():
            filename = filename.strip()
            component_name = self.get_component_name(filename)
            self._firmware_files[component_name] = f'{firmware_path}/{filename}'

    def get_relative_path(self, path: str):
        return f'{self._firmware_path}/{path}'

    def get_files(self):
        return self._firmware_files

    @staticmethod
    def get_component_name(filename):
        names = {
            'LLB': 'LLB',
            'iBoot': 'iBoot',
            'DeviceTree': 'DeviceTree',
            'applelogo': 'AppleLogo',
            'liquiddetect': 'Liquid',
            'lowpowermode': 'LowPowerWallet0',
            'recoverymode': 'RecoveryMode',
            'batterylow0': 'BatteryLow0',
            'batterylow1': 'BatteryLow1',
            'glyphcharging': 'BatteryCharging',
            'glyphplugin': 'BatteryPlugin',
            'batterycharging0': 'BatteryCharging0',
            'batterycharging1': 'BatteryCharging1',
            'batteryfull': 'BatteryFull',
            'needservice': 'NeedService',
            'SCAB': 'SCAB',
            'sep-firmware': 'RestoreSEP',
        }
        return names.get(filename)
