import asyncio
import logging
from enum import Enum
from typing import Optional
from zipfile import ZipFile

from ipsw_parser.exceptions import NoSuchBuildIdentityError
from ipsw_parser.ipsw import IPSW

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.img4 import stitch_component
from pymobiledevice3.restore.tss import TSSResponse

RESTORE_VARIANT_ERASE_INSTALL = 'Erase Install (IPSW)'
RESTORE_VARIANT_UPGRADE_INSTALL = 'Upgrade Install (IPSW)'
RESTORE_VARIANT_MACOS_RECOVERY_OS = 'macOS Customer'


class Behavior(Enum):
    Update = 'Update'
    Erase = 'Erase'


class BaseRestore:
    def __init__(self, ipsw: ZipFile, device: Device, tss: Optional[dict] = None,
                 behavior: Behavior = Behavior.Update) -> None:
        self.ipsw = IPSW(ipsw)
        self.device = device
        self.tss = TSSResponse(tss) if tss is not None else None

        if not self.device.is_image4_supported:
            raise NotImplementedError('is_image4_supported is False')

        self.logger.info(f'connected device: {self.device}')

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

    @property
    def logger(self) -> logging.Logger:
        return logging.getLogger(f'{asyncio.current_task().get_name()}-{self.__class__.__module__}')

    def get_personalized_data(self, component_name: str, data: Optional[bytes] = None,
                              tss: Optional[TSSResponse] = None, path: Optional[str] = None) -> bytes:
        return stitch_component(component_name,
                                self.build_identity.get_component(component_name, tss=tss, data=data, path=path).data,
                                tss,
                                self.build_identity,
                                self.device.ap_parameters)

    def populate_tss_request_from_manifest(self, parameters: dict, additional_keys: Optional[list[str]] = None) -> None:
        """ equivalent to idevicerestore:tss_parameters_add_from_manifest """
        key_list = ['ApBoardID', 'ApChipID']
        if additional_keys is None:
            key_list += ['UniqueBuildID', 'Ap,OSLongVersion', 'Ap,OSReleaseType', 'Ap,ProductType', 'Ap,SDKPlatform',
                         'Ap,SikaFuse', 'Ap,Target', 'Ap,TargetType', 'ApBoardID', 'ApChipID',
                         'ApSecurityDomain', 'BMU,BoardID', 'BMU,ChipID', 'BbChipID', 'BbProvisioningManifestKeyHash',
                         'BbActivationManifestKeyHash', 'BbCalibrationManifestKeyHash', 'Ap,ProductMarketingVersion',
                         'BbFactoryActivationManifestKeyHash', 'BbFDRSecurityKeyHash', 'BbSkeyId', 'SE,ChipID',
                         'Savage,ChipID', 'Savage,PatchEpoch', 'Yonkers,BoardID', 'Yonkers,ChipID',
                         'Yonkers,PatchEpoch', 'Rap,BoardID', 'Rap,ChipID', 'Rap,SecurityDomain', 'Baobab,BoardID',
                         'Baobab,ChipID', 'Baobab,ManifestEpoch', 'Baobab,SecurityDomain', 'eUICC,ChipID',
                         'PearlCertificationRootPub', 'Timer,BoardID,1', 'Timer,BoardID,2', 'Timer,ChipID,1',
                         'Timer,ChipID,2', 'Timer,SecurityDomain,1', 'Timer,SecurityDomain,2', 'Manifest',
                         'NeRDEpoch',
                         ]
        else:
            key_list += additional_keys

        for k in key_list:
            try:
                v = self.build_identity[k]
                if isinstance(v, str) and v.startswith('0x'):
                    v = int(v, 16)
                parameters[k] = v
            except KeyError:
                pass

        if additional_keys is None:
            # special treat for RequiresUIDMode
            info = self.build_identity.get('Info')
            if info is None:
                return
            requires_uid_mode = info.get('RequiresUIDMode')
            if requires_uid_mode is not None:
                parameters['RequiresUIDMode'] = requires_uid_mode
