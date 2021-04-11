#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# $Id$
#
# Copyright (c) 2012-2014 "dark[-at-]gotohack.org"
#
# This file is part of pymobiledevice3
#
# pymobiledevice3 is free software: you can redistribute it and/or modify
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
import logging

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.afc import AFCClient, AFCShell

from pprint import pprint
from optparse import OptionParser


class HouseArrestClient(AFCClient):
    def __init__(self, udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        lockdownClient = LockdownClient(udid)
        serviceName = "com.apple.mobile.house_arrest"
        super(HouseArrestClient, self).__init__(lockdownClient, serviceName)

    def stop_session(self):
        self.logger.info("Disconnecting...")
        self.service.close()

    def send_command(self, applicationId, cmd="VendContainer"):
        self.service.send_plist({"Command": cmd, "Identifier": applicationId})
        res = self.service.recv_plist()
        if res.get("Error"):
            self.logger.error("%s : %s", applicationId, res.get("Error"))
            return False
        else:
            return True

    def shell(self, applicationId, cmd="VendContainer"):
        res = self.send_command(applicationId, cmd)
        if res:
            AFCShell(client=self).cmdloop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARN)
    parser = OptionParser(usage="%prog -a  applicationId")
    parser.add_option("-a", "--application", dest="applicationId", default=False,
                      help="Application ID <com.apple.iBooks>", type="string")
    parser.add_option("-c", "--command", dest="cmd", default=False,
                      help="House_Arrest commands: ", type="string")

    (options, args) = parser.parse_args()
    h = HouseArrestClient()
    if options.cmd:
        h.shell(options.applicationId, cmd=options.cmd)
    else:
        h.shell(options.applicationId)
