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

import re
import logging

from pymobiledevice.lockdown import LockdownClient
from six import PY3
from sys import exit
from datetime import datetime
from util import getHomePath
from util import hexdump
from sys import exit
from optparse import OptionParser
import time

TIME_FORMAT = '%H:%M:%S'


class Syslog(object):
    '''
    View system logs
    '''
    def __init__(self, lockdown=None, udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.lockdown = lockdown if lockdown else LockdownClient(udid=udid)
        self.c = self.lockdown.startService("com.apple.syslog_relay")
        if self.c:
            self.c.send("watch")
        else:
            exit(1)

    def watch(self, watchtime=None, logFile=None, procName=None):
        '''View log
        :param watchtime: time (seconds)
        :type watchtime: int
        :param logFile: full path to the log file
        :type logFile: str
        :param procName: process name
        :type proName: str
        '''
        begin = time.strftime(TIME_FORMAT)
        while True:
            d = self.c.recv(4096)
            if PY3:
                d = d.decode('utf-8')
            if procName:
                procFilter = re.compile(procName,re.IGNORECASE)
                if len(d.split(" ")) > 4 and not procFilter.search(d):
                    continue
            s =  d.strip("\n\x00\x00")
            #self.logger.info(s)
            print(s)
            if logFile:
                with open(logFile, 'a') as f:
                    f.write(d.replace("\x00", ""))
            if watchtime:
                now = self.time_match(s[7:15])
                if now:
                    time_spend = self.time_caculate(str(begin), now)
                    if time_spend > watchtime :
                        break


    def time_match(self, str_time):
        '''
        Determine if the time format matches
        '''
        pattern = re.compile(r'\d{2}:\d{2}:\d{2}')
        match = pattern.match(str_time)
        if match:
            return str_time
        else:
            return False

    def time_caculate(self, a, b):
        '''
        Calculate the time difference between two strings
        '''
        time_a = int(a[6:8])+60*int(a[3:5])+3600*int(a[0:2])
        time_b = int(b[6:8])+60*int(b[3:5])+3600*int(b[0:2])
        time_a = int(a[6:8])+60*int(a[3:5])+3600*int(a[0:2])
        time_b = int(b[6:8])+60*int(b[3:5])+3600*int(b[0:2])
        return time_b - time_a


if __name__ == "__main__":
    parser = OptionParser(usage="%prog")
    parser.add_option("-u", "--udid",
                  default=False, action="store", dest="device_udid", metavar="DEVICE_UDID",
                  help="Device udid")
    parser.add_option("-p", "--process", dest="procName", default=False,
                  help="Show process log only", type="string")
    parser.add_option("-o", "--logfile", dest="logFile", default=False,
                  help="Write Logs into specified file", type="string")
    parser.add_option("-w", "--watch-time",
                  default=False, action="store", dest="watchtime", metavar="WATCH_TIME",
                  help="watchtime")
    (options, args) = parser.parse_args()

    try:
        try:
            logging.basicConfig(level=logging.INFO)
            lckdn = LockdownClient(options.device_udid)
            syslog = Syslog(lockdown=lckdn)
            syslog.watch(watchtime=int(options.watchtime), procName=options.procName,logFile=options.logFile)
        except KeyboardInterrupt:
            print("KeyboardInterrupt caught")
            raise
        else:
            pass


    except (KeyboardInterrupt, SystemExit):
        exit()
