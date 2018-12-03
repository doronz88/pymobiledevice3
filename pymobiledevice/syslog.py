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
from sys import exit
import re
import time

TIME_FORMAT = '%H:%M:%S'


class Syslog(object):
    '''
    查看系统日志
    '''
    def __init__(self, lockdown=None):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()
        self.c = self.lockdown.startService("com.apple.syslog_relay")
        if self.c:
            self.c.send("watch")
        else:
            exit(1)                

    def watch(self, watchtime, logFile=None, procName=None):
        '''查看日志  
        :param watchtime: 时间(秒)
        :type watchtime: int
        :param logFile: 日志文件完整路径
        :type logFile:  str
        :param procName: 进程名
        :type proName:  str
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
            s = d.strip("\n\x00\x00")
            print(s)
            if logFile:
                with open(logFile, 'a') as f:
                    f.write(d.replace("\x00", ""))            
            now = self.time_match(s[7:15])
            if now:
                time_spend = self.time_caculate(str(begin), now)
                if time_spend > watchtime :
                    break
                 
    def time_match(self, str_time):
        '''判断时间格式是否匹配 
        '''
        pattern = re.compile(r'\d{2}:\d{2}:\d{2}')
        match = pattern.match(str_time)
        if match:
            return str_time
        else:
            return False
        
    def time_caculate(self, a, b):
        '''
        计算两个字符串的时间差
        '''    
        time_a = int(a[6:8])+60*int(a[3:5])+3600*int(a[0:2])
        time_b = int(b[6:8])+60*int(b[3:5])+3600*int(b[0:2])
        return time_b - time_a
               
if __name__ == "__main__":
    syslog = Syslog()
    syslog.watch(10,'/tmp/sys.log','QQ')