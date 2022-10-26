import logging
import zipfile
from contextlib import contextmanager

from cached_property import cached_property
from construct import Const, Default, PaddedString, Struct

from pymobiledevice3.restore.ipsw.build_manifest import BuildManifest
from pymobiledevice3.restore.ipsw.firmware import Firmware

cpio_odc_header = Struct(
    'c_magic' / Const('070707', PaddedString(6, 'utf8')),
    'c_dev' / Default(PaddedString(6, 'utf8'), '0' * 6, ),
    'c_ino' / PaddedString(6, 'utf8'),
    'c_mode' / PaddedString(6, 'utf8'),
    'c_uid' / Default(PaddedString(6, 'utf8'), '0' * 6),
    'c_gid' / Default(PaddedString(6, 'utf8'), '0' * 6),
    'c_nlink' / PaddedString(6, 'utf8'),
    'c_rdev' / Default(PaddedString(6, 'utf8'), '0' * 6),
    'c_mtime' / Default(PaddedString(11, 'utf8'), '0' * 11),
    'c_namesize' / PaddedString(6, 'utf8'),
    'c_filesize' / Default(PaddedString(11, 'utf8'), '0' * 11),
)


class IPSW:
    def __init__(self, archive: zipfile.ZipFile):
        self._archive = archive
        self.logger = logging.getLogger(__file__)
        self.build_manifest = BuildManifest(self, self._archive.read('BuildManifest.plist'))

    @cached_property
    def restore_version(self):
        return self.read('RestoreVersion.plist')

    @cached_property
    def system_version(self):
        return self.read('SystemVersion.plist')

    @cached_property
    def filelist(self):
        return self._archive.filelist

    @contextmanager
    def open_path(self, path: str):
        file = self._archive.open(path)
        try:
            yield file
        finally:
            file.close()

    @property
    def bootability(self):
        result = b''
        prefix = 'BootabilityBundle/Restore/Bootability/'
        inode = 1
        nlink = 1

        for e in self.filelist:
            if e.filename == 'BootabilityBundle/Restore/Firmware/Bootability.dmg.trustcache':
                subpath = 'Bootability.trustcache'
            elif not e.filename.startswith(prefix):
                continue
            else:
                subpath = e.filename[len(prefix):]

            self.logger.debug(f'BootabilityBundle: adding {subpath}')

            filename = subpath
            filename = f'{filename}\0'.encode()
            mode = e.external_attr >> 16
            result += cpio_odc_header.build({
                'c_ino': f'{inode:06o}', 'c_nlink': f'{nlink:06o}', 'c_mode': f'{mode:06o}',
                'c_namesize': f'{len(filename):06o}', 'c_filesize': f'{e.file_size:011o}'})
            inode += 1
            result += filename
            if not e.file_size:
                continue

            with self.open_path(e.filename) as f:
                result += f.read()

        filename = b'TRAILER!!!\0'
        inode = 0
        mode = 0
        result += cpio_odc_header.build(
            {'c_ino': f'{inode:06o}', 'c_mode': f'{mode:06o}', 'c_nlink': f'{nlink:06o}',
             'c_namesize': f'{len(filename):06o}'}) + filename
        return result

    def read(self, path: str):
        return self._archive.read(path)

    def get_global_manifest(self, macos_variant: str, device_class: str):
        manifest_path = f'Firmware/Manifests/restore/{macos_variant}/apticket.{device_class}.im4m'
        return self.read(manifest_path)

    def get_firmware(self, firmware_path: str):
        return Firmware(firmware_path, self)
