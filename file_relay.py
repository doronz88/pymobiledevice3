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
import zlib
import gzip
from pprint import pprint
from tempfile import mkstemp

SRCFILES = """Accounts
Baseband
Bluetooth
CrashReporter
Caches
CoreLocation
DataAccess
EmbeddedSocial
HFSMeta
Keyboard
Lockdown
MapsLogs
MobileBackup
MobileDelete
MobileInstallation
MobileNotes
Network
UserDatabases
WiFi
WirelessAutomation
Lockdown
tmp"""

class FileRelayClient(object):
    def __init__(self, lockdown=None, serviceName="com.apple.mobile.file_relay"):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()

        self.service = self.lockdown.startService(serviceName)
        self.packet_num = 0

    def stop_session(self):
        print "Disconecting..."
        self.service.close()

    def request_sources(self, sources=["UserDatabases"]):  
        print "Downloading sources ", sources
        self.service.sendPlist({"Sources":sources})
        res = self.service.recvPlist()
        if res:
            if res.has_key("Status"):
                if res["Status"] == "Acknowledged":
                    z = ""
                    while True:
                        x = self.service.recv()
                        if not x:
                            break
                        z += x
                    return z
        return None
       
if __name__ == "__main__":
    lockdown = LockdownClient()
    ProductVersion = lockdown.getValue("", "ProductVersion")
    assert ProductVersion[0] >= "4"

    fc = FileRelayClient()
    data = fc.request_sources(SRCFILES.split("\n"))
    if data:
        _,path = mkstemp(prefix="fileRelay_dump_",suffix=".dmp",dir=".")
        open(path,'wb').write(data)
        print  "Data saved to  %s " % path
