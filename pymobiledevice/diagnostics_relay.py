#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# $Id$
#
# Copyright (c) 2012-2014 "dark[-at-]gotohack.org"
#
# This file is part of pymobiledevice
#
# pymobiledevice is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#


from pymobiledevice.lockdown import LockdownClient
from pprint import pprint
import plistlib
from optparse import OptionParser

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
        print("Disconecting...")
        self.service.close()


    def query_mobilegestalt(self, MobileGestalt=MobileGestaltKeys.split("\n")):
        self.service.sendPlist({"Request": "MobileGestalt",
                                "MobileGestaltKeys": MobileGestalt})

        res = self.service.recvPlist()
        d = res.get("Diagnostics")
        if d:
            return d.get("MobileGestalt")
        return None


    def action(self, action="Shutdown", flags=None):
        self.service.sendPlist({"Request": action })
        res = self.service.recvPlist()
        return res.get("Diagnostics")


    def restart(self):
        return self.action("Restart")


    def shutdown(self):
        return self.action("Shutdown")


    def diagnostics(self, diagType="All"):
        self.service.sendPlist({"Request": diagType})
        res = self.service.recvPlist()
        if res:
            return res.get("Diagnostics")
        return None


    def ioregistry_entry(self, name=None, ioclass=None):
        d = {}
        if name:
            d["EntryName"] = name

        if ioclass:
            d["EntryClass"] = ioclass

        d["Request"] = "IORegistry"

        self.service.sendPlist(d)
        res = self.service.recvPlist()
        pprint(res)
        if res:
            return res.get("Diagnostics")
        return None


    def ioregistry_plane(self, plane=""):
        d = {}
        if plane:
            d["CurrentPlane"] = plane

        else:
            d["CurrentPlane"] = ""
        d["Request"] = "IORegistry"

        self.service.sendPlist(d)
        res = self.service.recvPlist()
        dd = res.get("Diagnostics")
        if dd:
            return dd.get("IORegistry")
        return None


if __name__ == "__main__":

    parser = OptionParser(usage="%prog")
    parser.add_option("-c", "--cmd", dest="cmd", default=False,
                  help="Launch diagnostic command", type="string")
    parser.add_option("-m", "--mobilegestalt", dest="mobilegestalt_key", default=False,
                  help="Request mobilegestalt key", type="string")
    parser.add_option("-i", "--ioclass", dest="ioclass", default=False,
                  help="Request ioclass", type="string")
    parser.add_option("-n", "--ioname", dest="ioname", default=False,
                  help="Request ionqme", type="string")

    (options, args) = parser.parse_args()

    diag = DIAGClient()
    if not options.cmd:
        res = diag.diagnostics()

    elif options.cmd == "IORegistry":
        res = diag.ioregistry_plane()

    elif  options.cmd == "MobileGestalt":

        if not options.mobilegestalt_key or options.mobilegestalt_key not in MobileGestaltKeys.split("\n"):
            res = diag.query_mobilegestalt()

        else:
            res = diag.query_mobilegestalt([options.mobilegestalt_key])

    else:
        res = diag.action(options.cmd)

    if res:
        for k in res.keys():
            print(" %s \t: %s" % (k,res[k]))

