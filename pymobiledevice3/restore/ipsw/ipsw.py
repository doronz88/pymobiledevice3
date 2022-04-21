import zipfile
from contextlib import contextmanager
from io import BytesIO

from cached_property import cached_property
from pymobiledevice3.restore.ipsw.build_manifest import BuildManifest
from pymobiledevice3.restore.ipsw.firmware import Firmware


class IPSW:
    def __init__(self, file: BytesIO):
        self._archive = zipfile.ZipFile(file)
        self.build_manifest = BuildManifest(self, self._archive.read('BuildManifest.plist'))

    @cached_property
    def restore_version(self):
        return self.read('RestoreVersion.plist')

    @cached_property
    def system_version(self):
        return self.read('SystemVersion.plist')

    @contextmanager
    def open_path(self, path: str):
        file = self._archive.open(path)
        try:
            yield file
        finally:
            file.close()

    def read(self, path: str):
        return self._archive.read(path)

    def get_global_manifest(self, macos_variant: str, device_class: str):
        manifest_path = f'Firmware/Manifests/restore/{macos_variant}/apticket.{device_class}.im4m'
        return self.read(manifest_path)

    def get_firmware(self, firmware_path: str):
        return Firmware(firmware_path, self)
