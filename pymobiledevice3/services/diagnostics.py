from pymobiledevice3.exceptions import PyMobileDevice3Exception, ConnectionFailedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService

Requests = """Goodbye
All
GasGauge
WiFi
Shutdown
Restart
MobileGestalt
Sleep
NAND
IORegistry
Obliterate
"""

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
        self.packet_num = 0

    def mobilegestalt(self, keys=None):
        if keys is None or len(keys) == 0:
            keys = MobileGestaltKeys
        self.service.send_plist({'Request': 'MobileGestalt',
                                 'MobileGestaltKeys': keys})

        res = self.service.recv_plist()
        d = res.get('Diagnostics')
        if d:
            return d.get('MobileGestalt')
        return None

    def action(self, action):
        self.service.send_plist({'Request': action})
        response = self.service.recv_plist()
        if response.get('Status', None) is None:
            raise PyMobileDevice3Exception(f'got invalid response: {response}')

    def restart(self):
        self.action('Restart')

    def shutdown(self):
        self.action('Shutdown')

    def sleep(self):
        self.action('Sleep')

    def info(self, diag_type='All'):
        self.service.send_plist({'Request': diag_type})
        res = self.service.recv_plist()
        if res:
            return res.get('Diagnostics')
        return None

    def ioregistry(self, plane=None, name=None, ioclass=None):
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

    def get_battery(self):
        return self.ioregistry(ioclass='IOPMPowerSource')
