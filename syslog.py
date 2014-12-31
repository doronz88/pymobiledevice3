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
from datetime import datetime
from util import getHomePath
from util import hexdump
from sys import exit
from optparse import OptionParser

import re

class Syslog(object):
    def __init__(self, lockdown=None):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = Lockdown()
        self.c = self.lockdown.startService("com.apple.syslog_relay")
        if self.c:
            self.c.send("watch")
        else:
            sys.exit(1)

                  

    def watch(self,procName=None,logFile=None):
                
        while True:
            d = self.c.recv(4096)
            
            if not d:
                break

            if procName:
                procFilter = re.compile(procName,re.IGNORECASE)
                if len(d.split(" ")) > 4 and  not procFilter.search(d):
                    continue

            print d.strip("\n\x00\x00")

            if logFile:
                with open(logFile, 'a') as f:
                    f.write(d.replace("\x00", ""))

if __name__ == "__main__":
    parser = OptionParser(usage="%prog")
    parser.add_option("-p", "--process", dest="procName", default=False,
                  help="Show process log only", type="string")
    parser.add_option("-o", "--logfile", dest="logFile", default=False,
                  help="Write Logs into specified file", type="string")
    (options, args) = parser.parse_args()
    
    try:
        while True:
            try:
                syslog = Syslog()
                syslog.watch(procName=options.procName,logFile=options.logFile)
            except KeyboardInterrupt:
                print "KeyboardInterrupt caught"
                raise
            else:
                pass

    
    except (KeyboardInterrupt, SystemExit): 
        exit()
