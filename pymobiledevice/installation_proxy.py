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
from optparse import OptionParser
import os
from pymobiledevice.afc import AFCClient


client_options = {
    "SkipUninstall" : False,
    "ApplicationSINF" : False,
    "iTunesMetadata" : False,
    "ReturnAttributes" : False
}



class installation_proxy(object):

    def __init__(self,lockdown=None):

        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()

        self.service = self.lockdown.startService("com.apple.mobile.installation_proxy")


    def watch_completion(self,handler=None,*args):
        while True:
            z =  self.service.recvPlist()
            if not z:
                break
            completion = z.get("PercentComplete")
            if completion:
                if handler:
                    print("calling handler")
                    handler(completion,*args)
                print("%s %% Complete" % z.get("PercentComplete"))
            if z.get("Status") == "Complete":
                return z.get("Status")
        return "Error"

    def send_cmd_for_bid(self,bundleID, cmd="Archive", options=None, handler=None, *args):
        cmd = {"Command": cmd, "ApplicationIdentifier": bundleID }
        if options:
            cmd.update(options)
        self.service.sendPlist(cmd)
        print("%s : %s\n" % (cmd, self.watch_completion(handler, *args)))


    def uninstall(self,bundleID, options=None, handler=None, *args):
        self.send_cmd_for_bid(bundleID, "Uninstall", options, handler, args)

    def install_or_upgrade(self, ipaPath, cmd="Install", options=None, handler=None, *args):
        afc = AFCClient(self.lockdown)
        afc.set_file_contents("/" + os.path.basename(ipaPath), open(ipaPath,"rb").read())
        cmd = {"Command":cmd, "PackagePath": os.path.basename(ipaPath)}
        if options:
            cmd.update(options)
        self.service.sendPlist(cmd)
        print("%s : %s\n" % (cmd, self.watch_completion(handler, args)))


    def install(self,ipaPath, options=None, handler=None, *args):
        return self.install_or_upgrade(ipaPath, "Install", client_options, handler, args)


    def upgrade(self,ipaPath, options=None, handler=None, *args):
        return self.install_or_upgrade(ipaPath, "Upgrade", client_options, handler, args)


    def apps_info(self):
        self.service.sendPlist({"Command": "Lookup"})
        return self.service.recvPlist().get('LookupResult')


    def archive(self,bundleID, options=None, handler=None, *args):
        self.send_cmd_for_bid(bundleID, "Archive", options, handler, args)


    def restore_archive(self,bundleID, options=None, handler=None, *args):
        self.send_cmd_for_bid(bundleID, "Restore", client_options, handler, args)


    def remove_archive(self,bundleID, options={}, handler=None, *args):
        self.send_cmd_for_bid(bundleID, "RemoveArchive", options, handler, args)


    def archives_info(self):
        return self.service.sendRequest({"Command": "LookupArchive"}).get("LookupResult")


    def search_path_for_bid(self, bid):
        path = None
        for a in self.get_apps(appTypes=["User","System"]):
            if a.get("CFBundleIdentifier") == bid:
                path = a.get("Path")+"/"+a.get("CFBundleExecutable")
        return path


    def get_apps(self,appTypes=["User"]):
        return [app for app in self.apps_info().values()
                if app.get("ApplicationType") in appTypes]


    def print_apps(self, appType=["User"]):
        for app in self.get_apps(appType):
            print(("%s : %s => %s" % (app.get("CFBundleDisplayName"),
                                      app.get("CFBundleIdentifier"),
                                      app.get("Path") if app.get("Path")
                                      else app.get("Container"))).encode('utf-8'))


    def get_apps_bid(self,appTypes=["User"]):
        return [app["CFBundleIdentifier"]
                for app in self.get_apps()
                if app.get("ApplicationType") in appTypes]


    def close(self):
        self.service.close()

    def __del__(self):
        self.close()


if __name__ == "__main__":
    parser = OptionParser(usage="%prog cmd <command options>")
    parser.add_option("-l", "--listapps",
                      default=False,
                      action="store_true",
                      help="List installed applications")
    parser.add_option("-i", "--install",
                      default=False,
                      action="store",
                      dest="install_ipapath",
                      metavar="FILE",
                      help="Install application on device")
    parser.add_option("-r", "--remove",
                      default=False,
                      action="store",
                      dest="remove_bundleid",
                      metavar="BUNDLE_ID",
                      help="Remove (uninstall) application from device")
    parser.add_option("-u", "--upgrade",
                      default=False,
                      action="store",
                      dest="upgrade_bundleid",
                      metavar="BUNDLE_ID",
                      help="Upgrade application on device")
    parser.add_option("-a", "--archive",
                      default=False,
                      action="store",
                      dest="archive_bundleid",
                      metavar="BUNDLE_ID",
                      help="Archive application on device")

    (options, args) = parser.parse_args()
    #FIXME We should handle all installation proxy commands
    if  options.listapps:
        instpxy = installation_proxy()
        instpxy.print_apps(["User","System"])
    elif  options.install_ipapath:
        instpxy = installation_proxy()
        instpxy.install(options.install_ipapath)
    elif  options.remove_bundleid:
        instpxy = installation_proxy()
        instpxy.remove(options.remove_bundleid)
    elif  options.upgrade_bundleid:
        instpxy = installation_proxy()
        instpxy.upgrade(options.upgrade_bundleid)
    elif  options.archive_bundleid:
        instpxy = installation_proxy()
        instpxy.archive(options.archive_bundleid)
    else:
        parser.error("Incorrect number of arguments")
