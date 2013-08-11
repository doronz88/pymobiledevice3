from lockdown import LockdownClient
from optparse import OptionParser
from pprint import pprint
import plistlib
from util import read_file

class MobileConfigService(object):
    def __init__(self, lockdown):
        self.lockdown = lockdown
        self.service = lockdown.startService("com.apple.mobile.MCInstall")
    
    def GetProfileList(self):
        self.service.sendPlist({"RequestType":"GetProfileList"})
        res = self.service.recvPlist()
        if res.get("Status") != "Acknowledged":
            print "GetProfileList error"
            pprint(res)
            return
        return res
    
    def InstallProfile(self, s):
        #s = plistlib.writePlistToString(payload)
        self.service.sendPlist({"RequestType":"InstallProfile", "Payload": plistlib.Data(s)})
        return self.service.recvPlist()

    def RemoveProfile(self, ident):
        profiles = self.GetProfileList()
        if not profiles:
            return
        if not profiles["ProfileMetadata"].has_key(ident):
            print "Trying to remove not installed profile %s" % ident
            return
        meta = profiles["ProfileMetadata"][ident]
        pprint(meta)
        data = plistlib.writePlistToString({"PayloadType": "Configuration",
             "PayloadIdentifier": ident,
             "PayloadUUID": meta["PayloadUUID"],
             "PayloadVersion": meta["PayloadVersion"]
         })
        self.service.sendPlist({"RequestType":"RemoveProfile", "ProfileIdentifier": plistlib.Data(data)})
        return self.service.recvPlist()

def main():
    parser = OptionParser(usage="%prog")
    parser.add_option("-l", "--list", dest="list", action="store_true",
                      default=False, help="List installed profiles")
    parser.add_option("-i", "--install", dest="install", action="store", 
                  metavar="FILE", help="Install profile")
    parser.add_option("-r", "--remove", dest="remove", action="store", 
                  metavar="IDENTIFIER", help="Remove profile")
    (options, args) = parser.parse_args()
    
    if not options.list and not options.install and not options.remove:
        parser.print_help()
        return
    lockdown = LockdownClient()
    mc = MobileConfigService(lockdown)
    
    if options.list:
        pprint(mc.GetProfileList())
    elif options.install:
        mc.InstallProfile(read_file(options.install))
    elif options.remove:
        pprint(mc.RemoveProfile(options.remove))

if __name__ == "__main__":
    main()
