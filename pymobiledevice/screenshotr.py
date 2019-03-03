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

import os
import plistlib
import logging

from pymobiledevice.lockdown import LockdownClient

from six import PY3
from pprint import pprint
from time import gmtime, strftime
from optparse import OptionParser

class screenshotr(object):
    def __init__(self, lockdown=None, serviceName='com.apple.mobile.screenshotr', udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.lockdown = lockdown if lockdown else LockdownClient(udid=udid)
        self.service = self.lockdown.startService(serviceName)
        DLMessageVersionExchange = self.service.recvPlist()
        version_major = DLMessageVersionExchange[1]
        self.service.sendPlist(["DLMessageVersionExchange", "DLVersionsOk", version_major ])
        DLMessageDeviceReady = self.service.recvPlist()

    def stop_session(self):
        self.service.close()

    def take_screenshot(self):
        self.service.sendPlist(['DLMessageProcessMessage', {'MessageType': 'ScreenShotRequest'}])
        res = self.service.recvPlist()

        assert len(res) == 2
        assert res[0] == "DLMessageProcessMessage"

        if res[1].get('MessageType') == 'ScreenShotReply':
            if PY3:
                screen_data = res[1]['ScreenShotData']
            else:
                screen_data = res[1]['ScreenShotData'].data
            return screen_data
        return None

if __name__ == '__main__':
    parser = OptionParser(usage='%prog')
    parser.add_option("-u", "--udid",
                  default=False, action="store", dest="device_udid", metavar="DEVICE_UDID",
                  help="Device udid")
    parser.add_option('-p', '--path', dest='outDir', default=False,
            help='Output Directory (default: . )', type='string')
    (options, args) = parser.parse_args()

    outPath = '.'
    if options.outDir:
        outPath = options.outDir

    logging.basicConfig(level=logging.INFO)
    lckdn = LockdownClient(options.device_udid)
    screenshotr = screenshotr(lockdown=lckdn)
    data = screenshotr.take_screenshot()
    if data:
        filename = strftime('screenshot-%Y-%m-%d-%H-%M-%S.tif',gmtime())
        outPath = os.path.join(outPath, filename)
        print('Saving Screenshot at %s' % outPath)
        o = open(outPath,'wb')
        o.write(data)

