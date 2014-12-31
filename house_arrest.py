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

from lockdown import Lockdown
from pprint import pprint
from afc import AFC, AFCShell
from optparse import OptionParser
import os


class house_arrest(AFC):
    
    def __init__(self, lockdown=None,serviceName="com.apple.mobile.house_arrest", service=None):

        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = Lockdown()

        if service:
            self.service = service
        else:
            self.service = self.lockdown.startService(serviceName)
        self.packet_num = 0
     

    def stop_session(self):
        self.service.close()

    def send_command(self, applicationId, cmd="VendContainer"):        
        self.service.sendPlist({"Command": cmd, "Identifier": applicationId})
        res = self.service.recvPlist()

        if res.get("Error"):
            print res["Error"]
            return None

    def VendContainer(applicationId):        
        return send_command(self, applicationId, cmd="VendContainer")

    def VendDocuments(applicationId):        
 	return send_command(self, applicationId, cmd="VendDocuments")

    

if __name__ == "__main__":
    parser = OptionParser(usage="%prog -a  applicationId")
    parser.add_option("-a", "--application", dest="applicationId", default=False,
                  help="Application ID <com.apple.iBooks>", type="string")
    parser.add_option("-c", "--command", dest="cmd", default=False,
                  help="House_Arrest commands (VendContainer, VendDocuments): ", type="string")

    (options, args) = parser.parse_args()
    h =  house_arrest()
    if not options.applicationId:
	parser.error('Application ID not specify')
    elif options.applicationId and options.cmd:
	h.send_command(options.applicationId,cmd=options.cmd)
    	AFCShell(client=h).cmdloop()
    else:
	h.send_command(options.applicationId)
    	AFCShell(client=h).cmdloop()
