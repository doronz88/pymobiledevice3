from lockdown import LockdownClient
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
            self.lockdown = LockdownClient()
        self.c = self.lockdown.startService("com.apple.syslog_relay")
        self.c.send("watch")
                  

    def watch(self,procName=None,logFile=None):
        if logFile:
            f = open(logFile,'w')
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
