from collections import UserDict
from typing import List, Mapping

from cached_property import cached_property
from pymobiledevice3.restore.ipsw.component import Component


class BuildIdentity(UserDict):
    def __init__(self, build_manifest, data):
        super().__init__(data)
        self.build_manifest = build_manifest

    @cached_property
    def device_class(self):
        return self['Info']['DeviceClass'].lower()

    @cached_property
    def restore_behavior(self):
        return self['Info'].get('RestoreBehavior')

    @cached_property
    def variant(self):
        return self['Info'].get('Variant')

    @cached_property
    def macos_variant(self):
        return self['Info'].get('MacOSVariant')

    @cached_property
    def manifest(self):
        return self['Manifest']

    @cached_property
    def minimum_system_partition(self):
        return self['Info'].get('MinimumSystemPartition')

    def get_component_path(self, component: str):
        return self.manifest[component]['Info']['Path']

    def has_component(self, name: str):
        return name in self.manifest

    def get_component(self, name: str, **args) -> Component:
        return Component(self, name, **args)

    def populate_tss_request_parameters(self, parameters: Mapping, additional_keys: List[str] = None):
        """ equivalent to idevicerestore:tss_parameters_add_from_manifest """
        key_list = ['ApBoardID', 'ApChipID']
        if additional_keys is None:
            key_list += ['UniqueBuildID', 'Ap,OSLongVersion', 'ApChipID', 'ApBoardID', 'ApSecurityDomain',
                         'BMU,BoardID', 'BMU,ChipID', 'BbChipID', 'BbProvisioningManifestKeyHash',
                         'BbActivationManifestKeyHash', 'BbCalibrationManifestKeyHash',
                         'BbFactoryActivationManifestKeyHash', 'BbFDRSecurityKeyHash', 'BbSkeyId', 'SE,ChipID',
                         'Savage,ChipID', 'Savage,PatchEpoch', 'Yonkers,BoardID', 'Yonkers,ChipID',
                         'Yonkers,PatchEpoch', 'Rap,BoardID', 'Rap,ChipID', 'Rap,SecurityDomain', 'Baobab,BoardID',
                         'Baobab,ChipID', 'Baobab,ManifestEpoch', 'Baobab,SecurityDomain', 'eUICC,ChipID',
                         'PearlCertificationRootPub', 'NeRDEpoch', 'Timer,BoardID,1', 'Timer,BoardID,2',
                         'Timer,ChipID,1', 'Timer,ChipID,2', 'Timer,SecurityDomain,1', 'Timer,SecurityDomain,2',
                         'Manifest', ]
        else:
            key_list += additional_keys

        for k in key_list:
            try:
                v = self[k]
                if isinstance(v, str) and v.startswith('0x'):
                    v = int(v, 16)
                parameters[k] = v
            except KeyError:
                pass

        requires_uid_mode = self['Info'].get('RequiresUIDMode')
        if requires_uid_mode is not None:
            parameters['RequiresUIDMode'] = requires_uid_mode
