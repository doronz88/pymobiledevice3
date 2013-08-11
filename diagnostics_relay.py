from lockdown import LockdownClient
from pprint import pprint
import plistlib

"""
com.apple.mobile.diagnostics_relay
Request
    Goodbye
    All
    GasGauge
    WiFi
    Shutdown
    Restart
    MobileGestalt    {"MobileGestaltKeys": []}
    Sleep
    NAND
    IORegistry    {"Request": "IORegistry", "CurrentPlane": "", "EntryName": "","EntryClass":""}
    Obliterate
"""

"""
BasebandKeyHashInformation
BasebandFirmwareManifestData
"""
MobileGestaltKeys = """DieId
SerialNumber
UniqueChipID
WifiAddress
CPUArchitecture
BluetoothAddress
EthernetMacAddress
FirmwareVersion
MLBSerialNumber
ModelNumber
RegionInfo
RegionCode
DeviceClass
ProductType
DeviceName
UserAssignedDeviceName
HWModelStr
SigningFuse
SoftwareBehavior
SupportedKeyboards
BuildVersion
ProductVersion
ReleaseType
InternalBuild
CarrierInstallCapability
IsUIBuild
InternationalMobileEquipmentIdentity
MobileEquipmentIdentifier
DeviceColor
HasBaseband
SupportedDeviceFamilies
SoftwareBundleVersion
SDIOManufacturerTuple
SDIOProductInfo
UniqueDeviceID
InverseDeviceID
ChipID
PartitionType
ProximitySensorCalibration
CompassCalibration
WirelessBoardSnum
BasebandBoardSnum
HardwarePlatform
RequiredBatteryLevelForSoftwareUpdate
IsThereEnoughBatteryLevelForSoftwareUpdate
BasebandRegionSKU
encrypted-data-partition
SysCfg
DiagData
SIMTrayStatus
CarrierBundleInfoArray
AllDeviceCapabilities
wi-fi
SBAllowSensitiveUI
green-tea
not-green-tea
AllowYouTube
AllowYouTubePlugin
SBCanForceDebuggingInfo
AppleInternalInstallCapability
HasAllFeaturesCapability
ScreenDimensions
IsSimulator
BasebandSerialNumber
BasebandChipId
BasebandCertId
BasebandSkeyId
BasebandFirmwareVersion
cellular-data
contains-cellular-radio
RegionalBehaviorGoogleMail
RegionalBehaviorVolumeLimit
RegionalBehaviorShutterClick
RegionalBehaviorNTSC
RegionalBehaviorNoWiFi
RegionalBehaviorChinaBrick
RegionalBehaviorNoVOIP
RegionalBehaviorAll
ApNonce"""

class DIAGClient(object):
    def __init__(self, lockdown=None, serviceName="com.apple.mobile.diagnostics_relay"):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()

        self.service = self.lockdown.startService(serviceName)
        self.packet_num = 0

    def stop_session(self):
        print "Disconecting..."
        self.service.close()

    def query_mobilegestalt(self, MobileGestalt = MobileGestaltKeys.split("\n")):
        self.service.sendPlist({"Request": "MobileGestalt", "MobileGestaltKeys": MobileGestalt})
        res = self.service.recvPlist()
        #pprint(res)
        if res.has_key("Diagnostics"):
            return res;
        return None

    def action(self, action="Shutdown", flags=None):	
        self.service.sendPlist({"Request": action, })
        res = self.service.recvPlist()
        #pprint(res)
        return res    

    def restart(self):
        return self.action("Restart")


    def shutdown(self):
        return self.action("Shutdown")

    def diagnostics(self, diagType="All"):
        self.service.sendPlist({"Request": diagType})
        res = self.service.recvPlist()
        pprint(res)
        if res.has_key("Diagnostics"):
            return res;
        return None
            
    def ioregistry_entry(self, name=None, ioclass=None):
        req = {}
        req["Request"] = "IORegistry"
        if (name):
            req["EntryName"] = name

        if (ioclass):
            req["EntryClass"] = ioclass
        
        self.service.sendPlist(req)
        res = self.service.recvPlist()
        pprint(res)
        if res.has_key("Diagnostics"):
            return res;
        return None
  
    def ioregistry_plane(self, plane):
        req = {}
        req["Request"] = "IORegistry"
        req["CurrentPlane"] = ioclass
        self.service.sendPlist(req)
        res = self.service.recvPlist()
        pprint(res)
        if res.has_key("Diagnostics"):
            return res;
        return None


if __name__ == "__main__":
    lockdown = LockdownClient()
    ProductVersion = lockdown.getValue("", "ProductVersion")
    assert ProductVersion[0] >= "4"

    diag = DIAGClient()
    diag.diagnostics()
    diag.query_mobilegestalt()
    diag.restart()
