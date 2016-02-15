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
import os

class HouseArrestAFCClient(AFCClient):

    def __init__(self, bid, sandbox="VendContainer", lockdown=None):
        self.lockdown = lockdown if lockdown else LockdownClient()
        service = self.lockdown.startService("com.apple.mobile.house_arrest") 
        res = service.sendRequest({"Command": sandbox, "Identifier": bid})
        super(HouseArrestAFCClient, self).__init__(self.lockdown, service=service)

if __name__ == "__main__":
    parser = OptionParser(usage="%prog -a  applicationId")
    parser.add_option("-a", "--application", dest="applicationId", default=False,
                  help="Application ID <com.apple.iBooks>", type="string")
    parser.add_option("-s", "--sandbox", dest="sandbox", default=False,
                  help="House_Arrest sandbox (VendContainer, VendDocuments): ", type="string")

    (options, args) = parser.parse_args()
    
    if not options.applicationId:
        parser.error("Application ID not specify")
    elif options.applicationId and options.sandbox:
        h =  HouseArrestAFCClient(options.applicationId, sandbox=options.sandbox)
        AFCShell(client=h).cmdloop()
    else:
        h =  HouseArrestAFCClient(options.applicationId)
        AFCShell(client=h).cmdloop()
    
