from typing import List, Mapping, Optional

from pymobiledevice3.exceptions import PyMobileDevice3Exception, ConnectionFailedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService

MobileGestaltKeys = ['BasebandKeyHashInformation',
                     'BasebandFirmwareManifestData',
                     'DieId',
                     'SerialNumber',
                     'UniqueChipID',
                     'WifiAddress',
                     'CPUArchitecture',
                     'BluetoothAddress',
                     'EthernetMacAddress',
                     'FirmwareVersion',
                     'MLBSerialNumber',
                     'ModelNumber',
                     'RegionInfo',
                     'RegionCode',
                     'DeviceClass',
                     'ProductType',
                     'DeviceName',
                     'UserAssignedDeviceName',
                     'HWModelStr',
                     'SigningFuse',
                     'SoftwareBehavior',
                     'SupportedKeyboards',
                     'BuildVersion',
                     'ProductVersion',
                     'ReleaseType',
                     'InternalBuild',
                     'CarrierInstallCapability',
                     'IsUIBuild',
                     'InternationalMobileEquipmentIdentity',
                     'MobileEquipmentIdentifier',
                     'DeviceColor',
                     'HasBaseband',
                     'SupportedDeviceFamilies',
                     'SoftwareBundleVersion',
                     'SDIOManufacturerTuple',
                     'SDIOProductInfo',
                     'UniqueDeviceID',
                     'InverseDeviceID',
                     'ChipID',
                     'PartitionType',
                     'ProximitySensorCalibration',
                     'CompassCalibration',
                     'WirelessBoardSnum',
                     'BasebandBoardSnum',
                     'HardwarePlatform',
                     'RequiredBatteryLevelForSoftwareUpdate',
                     'IsThereEnoughBatteryLevelForSoftwareUpdate',
                     'BasebandRegionSKU',
                     'encrypted-data-partition',
                     'SysCfg',
                     'DiagData',
                     'SIMTrayStatus',
                     'CarrierBundleInfoArray',
                     'AllDeviceCapabilities',
                     'wi-fi',
                     'SBAllowSensitiveUI',
                     'green-tea',
                     'not-green-tea',
                     'AllowYouTube',
                     'AllowYouTubePlugin',
                     'SBCanForceDebuggingInfo',
                     'AppleInternalInstallCapability',
                     'HasAllFeaturesCapability',
                     'ScreenDimensions',
                     'IsSimulator',
                     'BasebandSerialNumber',
                     'BasebandChipId',
                     'BasebandCertId',
                     'BasebandSkeyId',
                     'BasebandFirmwareVersion',
                     'cellular-data',
                     'contains-cellular-radio',
                     'RegionalBehaviorGoogleMail',
                     'RegionalBehaviorVolumeLimit',
                     'RegionalBehaviorShutterClick',
                     'RegionalBehaviorNTSC',
                     'RegionalBehaviorNoWiFi',
                     'RegionalBehaviorChinaBrick',
                     'RegionalBehaviorNoVOIP',
                     'RegionalBehaviorAll',
                     'ApNonce']


class DiagnosticsService(BaseService):
    """
    Provides an API to:
    * Query MobileGestalt & IORegistry keys.
    * Reboot, shutdown or put the device in sleep mode.
    """
    SERVICE_NAME_NEW = 'com.apple.mobile.diagnostics_relay'
    SERVICE_NAME_OLD = 'com.apple.iosdiagnostics.relay'

    def __init__(self, lockdown: LockdownClient):
        try:
            service = lockdown.start_service(self.SERVICE_NAME_NEW)
            service_name = self.SERVICE_NAME_NEW
        except ConnectionFailedError:
            service = lockdown.start_service(self.SERVICE_NAME_OLD)
            service_name = self.SERVICE_NAME_OLD

        super().__init__(lockdown, service_name, service=service)

    def mobilegestalt(self, keys: List[str] = None) -> Mapping:
        if keys is None or len(keys) == 0:
            keys = MobileGestaltKeys
        resp = self.service.send_recv_plist({'Request': 'MobileGestalt', 'MobileGestaltKeys': keys})

        if (resp['Status'] != 'Success') or (resp['Diagnostics']['MobileGestalt']['Status'] != 'Success'):
            raise PyMobileDevice3Exception('failed to query MobileGestalt')

        resp['Diagnostics']['MobileGestalt'].pop('Status')

        return resp['Diagnostics']['MobileGestalt']

    def action(self, action: str) -> Optional[Mapping]:
        response = self.service.send_recv_plist({'Request': action})
        if response['Status'] != 'Success':
            raise PyMobileDevice3Exception(f'failed to perform action: {action}')
        return response.get('Diagnostics')

    def restart(self):
        self.action('Restart')

    def shutdown(self):
        self.action('Shutdown')

    def sleep(self):
        self.action('Sleep')

    def info(self, diag_type: str = 'All') -> Mapping:
        return self.action(diag_type)

    def ioregistry(self, plane: str = None, name: str = None, ioclass: str = None):
        d = {}

        if plane:
            d['CurrentPlane'] = plane

        if name:
            d['EntryName'] = name

        if ioclass:
            d['EntryClass'] = ioclass

        d['Request'] = 'IORegistry'

        response = self.service.send_recv_plist(d)
        if response.get('Status') != 'Success':
            raise PyMobileDevice3Exception(f'got invalid response: {response}')

        dd = response.get('Diagnostics')
        if dd:
            return dd.get('IORegistry')
        return None

    def get_battery(self) -> Mapping:
        return self.ioregistry(ioclass='IOPMPowerSource')
