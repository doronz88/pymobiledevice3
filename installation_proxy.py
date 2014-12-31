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

from lockdown import LockdownClient
from pprint import pprint
from afc import AFCClient, AFCShell
from optparse import OptionParser
from house_arrest import house_arrest
from util import read_file, write_file, hexdump, readPlist, parsePlist
from biplist import writePlist,  Data
from image_mounter import ImgMntClient
import tempfile
import os
from time import sleep

class installation_proxy:
    def __init__(self,lockdown=None):
        self.AFCClients = {}
        self.lockdown = lockdown
        self.files = {}

        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()

	self.mci = self.lockdown.startService("com.apple.mobile.installation_proxy")

    def mobile_uninstall(self,bundleID):
        
        self.mci.sendPlist({"Command":"Uninstall",
                            "ApplicationIdentifier": bundleID})
        while True:
            z =  self.mci.recvPlist()
            if not z:
                break
            completion = z.get('PercentComplete')
            if completion:
                print 'Unistalling, %s: %s %% Complete' % (bundleID, z['PercentComplete'])
            if z.get('Status') == 'Complete':
                print "Uninstallation %s\n" % z['Status']
                break


    def mobile_install(self,ipaPath):
        return mobile_install_or_upgrade(ipaPath,cmd="Install")


    def mobile_upgrade(self,ipaPath):
        return mobile_install_or_upgrade(ipaPath,cmd="Upgrade")


    def mobile_install_or_upgrade(self,ipaPath,cmd="Install"):
        #Start afc service & upload ipa
        afc = AFCClient(self.lockdown)
        afc.set_file_contents("/" + os.path.basename(ipaPath), open(ipaPath,'rb').read())
        self.mci.sendPlist({"Command":"Install",
                            "PackagePath": os.path.basename(ipaPath)})
        while True:
            z =  self.mci.recvPlist()
            if not z:
                break
            completion = z.get('PercentComplete')
            if completion:
                print 'Installing, %s: %s %% Complete' % (ipaPath, z['PercentComplete'])
            if z.get('Status') == 'Complete':
                print "Installation %s\n" % z['Status']
                break

    #TODO:
    #   - List archived applications.
    #   - Archive an application on the device.
    #   - Restore a previously archived application on the device.
    #   - Removes a previously archived application from the device.


    def search_path_for_bid(self,BundleID):
        path = None
        for a in self.get_apps(appTypes=["User","System"]):
            if a.get('CFBundleIdentifier') == BundleID:
                path = a.get('Path')+'/'+a.get('CFBundleExecutable')
        return path


    def get_apps(self,appTypes=["User"]):
        apps = []
        #Return detailled app list
        self.mci.sendPlist({"Command":"Lookup"})
        res = self.mci.recvPlist()
        for app in res["LookupResult"].values():
            if app.get("ApplicationType") in appTypes :
                apps.append(app)
        return apps

    def get_info_plist_path(self,bid):
        files = self.list_all_app_files(bid)
        for f in files:
            if os.path.basename(f['path']) == "Info.plist":#FIXME
                return f['path']

    def get_info_plist(self,bid,path=None):
        afc = house_arrest(self.lockdown, bid)
        if path ==  None:
            path = self.get_info_plist_path(bid)
        data =  parsePlist(afc.get_file_contents(path))
        return data


    def list_apps(self, appType=["User"]):
        #print installed apps
        for app in self.get_apps(appType):
            if app.get("ApplicationType") != "System":
                print app["CFBundleIdentifier"], "=>", app.get("Container")
            else:
                print app["CFBundleIdentifier"], "=>", app.get("Path")


    def get_apps_BundleID(self,appTypes=["User"]):
        bundleIDList = []
        for app in self.get_apps():
            if app.get("ApplicationType")  == appTypes:
	            bundleIDList.append(app["CFBundleIdentifier"])
        return bundleIDList


    def list_all_app_files(self,bid):
        #List all files of an application
        #Only works with "User installed application"
        afc = house_arrest(self.lockdown, bid)
        files=afc.dir_walk('/')
        return files



if __name__ == "__main__":
    parser = OptionParser(usage="%prog -a  applicationId")
    parser.add_option("-a", "--application", dest="applicationId", default=False,
                  help="Application ID <com.apple.iBooks>", type="string")
    parser.add_option("-c", "--command", dest="cmd", default=False,
                  help="House_Arrest commands (VendContainer, VendDocuments): ", type="string")

    (options, args) = parser.parse_args()
    #TODO
    instpxy = installation_proxy()
    print instpxy.list_apps(["User","System"])


