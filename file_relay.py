from lockdown import LockdownClient
import zlib
import gzip
from pprint import pprint

SRCFILES = """AppleSupport
Network
UserDatabases
CrashReporter
tmp
SystemConfiguration
WiFi
VPN
Caches"""

class FileRelayClient(object):
    def __init__(self, lockdown=None, serviceName="com.apple.mobile.file_relay"):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()

        self.service = self.lockdown.startService(serviceName)
        self.packet_num = 0

    def stop_session(self):
        print "Disconecting..."
        self.service.close()

    def request_sources(self, sources=["UserDatabases"]):  
        print "Downloading sources ", sources
        self.service.sendPlist({"Sources":sources})
        res = self.service.recvPlist()
        if res:
            if res.has_key("Status"):
                if res["Status"] == "Acknowledged":
                    z = ""
                    while True:
                        x = self.service.recv()
                        if not x:
                            break
                        z += x
                    return z
        return None
       
if __name__ == "__main__":
    lockdown = LockdownClient()
    ProductVersion = lockdown.getValue("", "ProductVersion")
    assert ProductVersion[0] >= "4"

    fc = FileRelayClient()
    f = fc.request_sources(SRCFILES.split("\n"))
    #f = fc.request_sources(["SystemConfiguration"])
    if f:
        open("fileRelayTest.gz","wb").write(f)
