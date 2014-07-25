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
import plistlib


class NPClient(object):
    def __init__(self, lockdown=None, serviceName="com.apple.mobile.notification_proxy"):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()

        self.service = self.lockdown.startService(serviceName)

    def stop_session(self):
        print "Disconecting..."
        self.service.close()

    def post_notification(self, notification):
        #Sends a notification to the device's notification_proxy.
        self.service.sendPlist({"Command": "PostNotification",#}
                                "Name": notification})
        res = self.service.recvPlist()
        pprint(res)
        return res

    def observe_notification(self, notification):
        #Tells the device to send a notification on the specified event
        self.service.sendPlist({"Command": "ObserveNotification",#}
                                "Name": notification})
        res = self.service.recvPlist()
        pprint(res)
        return res


    def get_notification(self, notification):
        #Checks if a notification has been sent by the device
        res = self.service.recvPlist()
        pprint(res)
        return res  


if __name__ == "__main__":
    lockdown = LockdownClient()
    ProductVersion = lockdown.getValue("", "ProductVersion")
    assert ProductVersion[0] >= "4"

    np = NPClient()
    np.get_notification()
 
