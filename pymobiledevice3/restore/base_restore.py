import logging
import typing
from enum import Enum
from io import BytesIO

from pymobiledevice3.exceptions import NoSuchBuildIdentityError, PyMobileDevice3Exception
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.ipsw.ipsw import IPSW
from pymobiledevice3.restore.tss import TSSResponse

RESTORE_VARIANT_ERASE_INSTALL = 'Erase Install (IPSW)'
RESTORE_VARIANT_UPGRADE_INSTALL = 'Upgrade Install (IPSW)'
RESTORE_VARIANT_MACOS_RECOVERY_OS = 'macOS Customer'


class Behavior(Enum):
    Update = 'Update'
    Erase = 'Erase'


class BaseRestore:
    def __init__(self, ipsw: BytesIO, device: Device, tss: typing.Mapping = None,
                 behavior: Behavior = Behavior.Update, logger=None):
        self.logger = logging.getLogger(self.__class__.__name__) if logger is None else logger
        self.ipsw = IPSW(ipsw)
        self.device = device
        self.tss = TSSResponse(tss) if tss is not None else None

        if not self.device.is_image4_supported:
            raise NotImplementedError('is_image4_supported is False')

        self.logger.info(f'connected device: <ecid: {self.device.ecid} hardware_model: {self.device.hardware_model} '
                         f'image4-support: {self.device.is_image4_supported}>')

        self.logger.debug('scanning BuildManifest.plist for the correct BuildIdentity')

        variant = {
            Behavior.Update: RESTORE_VARIANT_UPGRADE_INSTALL,
            Behavior.Erase: RESTORE_VARIANT_ERASE_INSTALL,
        }[behavior]

        try:
            self.build_identity = self.ipsw.build_manifest.get_build_identity(self.device.hardware_model,
                                                                              restore_behavior=behavior.value,
                                                                              variant=variant)
        except NoSuchBuildIdentityError:
            if behavior == Behavior.Update:
                self.build_identity = self.ipsw.build_manifest.get_build_identity(self.device.hardware_model,
                                                                                  restore_behavior=behavior.value)
            else:
                raise

        self.macos_variant = None
        try:
            self.macos_variant = self.ipsw.build_manifest.get_build_identity(
                self.device.hardware_model,
                variant=RESTORE_VARIANT_MACOS_RECOVERY_OS)
            self.logger.info('Performing macOS restore')
        except NoSuchBuildIdentityError:
            pass

        build_info = self.build_identity.get('Info')
        if build_info is None:
            raise PyMobileDevice3Exception('build identity does not contain an "Info" element')

        device_class = build_info.get('DeviceClass')
        if device_class is None:
            raise PyMobileDevice3Exception('build identity does not contain an "DeviceClass" element')
