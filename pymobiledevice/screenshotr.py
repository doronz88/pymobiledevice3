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
from six import PY3
from time import gmtime, strftime
from optparse import OptionParser
import os

class screenshotr(object):
    def __init__(self, lockdown=None, serviceName='com.apple.mobile.screenshotr'):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()
        #Starting Screenshot service
        self.service = self.lockdown.startService(serviceName)
        
        #hand check 
        DLMessageVersionExchange = self.service.recvPlist()
        #assert len(DLMessageVersionExchange) == 2
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
    parser.add_option('-p', '--path', dest='outDir', default=False,
            help='Output Directory (default: . )', type='string')
    (options, args) = parser.parse_args()

    outPath = '.'
    if options.outDir:
        outPath = options.outDir

    screenshotr = screenshotr()    
    data = screenshotr.take_screenshot()
    if data:
        filename = strftime('screenshot-%Y-%m-%d-%H-%M-%S.tif',gmtime()) 
        outPath = os.path.join(outPath, filename)
        print('Saving Screenshot at %s' % outPath)
        o = open(outPath,'wb')
        o.write(data)