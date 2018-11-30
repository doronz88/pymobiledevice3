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
from pymobiledevice.afc import AFCClient, AFCShell
from optparse import OptionParser
import os
import warnings

warnings.warn(
"""The libraries upon which this program depends will soon be deprecated in
favor of the house_arrest.py and installation_proxy.py libraries.
See those files for example program written using the new libraries."""
)


def house_arrest(lockdown, applicationId):
    try:
        mis = lockdown.startService("com.apple.mobile.house_arrest")
    except:
        lockdown = LockdownClient()
        mis = lockdown.startService("com.apple.mobile.house_arrest")

    if mis == None:
        return
    mis.sendPlist({"Command": "VendDocuments", "Identifier": applicationId})
    res = mis.recvPlist()
    if res.get("Error"):
        print("Unable to Lookup the selected application: You probably trying to access to a system app...")
        return None
    return AFCClient(lockdown, service=mis)

def house_arrest_shell(lockdown, applicationId):
    afc =  house_arrest(lockdown, applicationId)
    if afc: AFCShell(client=afc).cmdloop()

"""
"Install"
"Upgrade"
"Uninstall"
"Lookup"
"Browse"
"Archive"
"Restore"
"RemoveArchive"
"LookupArchives"
"CheckCapabilitiesMatch"

installd
if stat("/var/mobile/tdmtanf") => "TDMTANF Bypass" => SignerIdentity bypass
"""

def mobile_install(lockdown,ipaPath):
    #Start afc service & upload ipa
    afc = AFCClient(lockdown)
    afc.set_file_contents("/" + os.path.basename(ipaPath), open(ipaPath,'rb').read())
    mci = lockdown.startService("com.apple.mobile.installation_proxy")
    #print mci.sendPlist({"Command":"Archive","ApplicationIdentifier": "com.joystickgenerals.STActionPig"})
    mci.sendPlist({"Command":"Install",
                         #"ApplicationIdentifier": "com.gotohack.JBChecker",
                         "PackagePath": os.path.basename(ipaPath)})
    while True:
        z =  mci.recvPlist()
        if not z:
            break
        completion = z.get('PercentComplete')
        if completion:
            print('Installing, %s: %s %% Complete' % (ipaPath, z['PercentComplete']))
        if z.get('Status') == 'Complete':
            print("Installation %s\n" % z['Status'])
            break

def list_apps(lockdown):
    mci = lockdown.startService("com.apple.mobile.installation_proxy")
    mci.sendPlist({"Command":"Lookup"})
    res = mci.recvPlist()
    for app in res["LookupResult"].values():
        if app.get("ApplicationType") != "System":
            print(app["CFBundleIdentifier"], "=>", app.get("Container"))
        else:
            print(app["CFBundleIdentifier"], "=> N/A")


def get_apps_BundleID(lockdown,appType="User"):
    appList = []
    mci = lockdown.startService("com.apple.mobile.installation_proxy")
    mci.sendPlist({"Command":"Lookup"})
    res = mci.recvPlist()
    for app in res["LookupResult"].values():
        if app.get("ApplicationType")  == appType:
            appList.append(app["CFBundleIdentifier"])
        #else: #FIXME
        #    appList.append(app["CFBundleIdentifier"])
    mci.close()
    #pprint(appList)
    return appList


if __name__ == "__main__":
    parser = OptionParser(usage="%prog")
    parser.add_option("-l", "--list", dest="list", action="store_true", default=False,
                  help="List installed applications (non system apps)")
    parser.add_option("-a", "--app", dest="app", action="store", default=None,
                  metavar="APPID", help="Access application files with AFC")
    parser.add_option("-i", "--install", dest="installapp", action="store", default=None,
                  metavar="FILE", help="Install an application package")

    (options, args) = parser.parse_args()
    if options.list:
        lockdown = LockdownClient()
        list_apps(lockdown)
    elif options.app:
        lockdown = LockdownClient()
        house_arrest_shell(lockdown, options.app)
    elif options.installapp:
        lockdown = LockdownClient()
        mobile_install(lockdown, options.installapp)
    else:
        parser.print_help()

