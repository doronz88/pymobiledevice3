from lockdown import LockdownClient
from pprint import pprint
import plistlib
from time import gmtime, strftime
from optparse import OptionParser
import os
import plistlib

class screenshotrClient(object):
    def __init__(self, lockdown=None, serviceName='com.apple.mobile.screenshotr'):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()
        #Starting Screenshot service
        self.service = self.lockdown.startService(serviceName)
        
        #hand check 
        DLMessageVersionExchange = self.service.recvPlist()
        #assert len(DLMessageVersionExchange) == 2
        version_major = DLMessageVersionExchange[1]
        self.service.sendPlist(["DLMessageVersionExchange", "DLVersionsOk", version_major ])
        DLMessageDeviceReady = self.service.recvPlist()

    def stop_session(self):
        self.service.close()

    def take_screenshot(self):
        self.service.sendPlist(['DLMessageProcessMessage', {'MessageType': 'ScreenShotRequest'}])
        res = self.service.recvPlist()
        
        assert len(res) == 2
        assert res[0] == "DLMessageProcessMessage"

        if res[1].get('MessageType') == 'ScreenShotReply':
            data = res[1]['ScreenShotData'].data 
            return data
        return None

if __name__ == '__main__':
    parser = OptionParser(usage='%prog')
    parser.add_option('-p', '--path', dest='outDir', default=False,
            help='Output Directory (default: . )', type='string')
    (options, args) = parser.parse_args()

    outPath = '.'
    if options.outDir:
        outPath = options.outDir

    screenshotr = screenshotrClient()    
    data = screenshotr.take_screenshot()
    if data:
        filename = strftime('screenshot-%Y-%m-%d-%H-%M-%S.tif',gmtime()) 
        outPath = os.path.join(outPath, filename)
        print 'Saving Screenshot at %s' % outPath
        o = open(outPath,'wb')
        o.write(data)
 
