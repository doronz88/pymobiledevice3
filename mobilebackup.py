from construct.core import Struct
from construct.lib.container import Container
from construct.macros import String, ULInt64
from lockdown import LockdownClient
import struct
import plistlib
from pprint import pprint
import os
import datetime
from afc import AFCClient
from util import makedirs

#
# Fix plistlib.py line 364
#     def asBase64(self, maxlinelength=76):
#	if self.data != None:
#	    return _encodeBase64(self.data, maxlinelength)
#	return ""
#
#


MOBILEBACKUP_E_SUCCESS              =  0
MOBILEBACKUP_E_INVALID_ARG          = -1
MOBILEBACKUP_E_PLIST_ERROR          = -2
MOBILEBACKUP_E_MUX_ERROR            = -3
MOBILEBACKUP_E_BAD_VERSION          = -4
MOBILEBACKUP_E_REPLY_NOT_OK         = -5
MOBILEBACKUP_E_UNKNOWN_ERROR      = -256

DEVICE_LINK_FILE_STATUS_NONE = 0
DEVICE_LINK_FILE_STATUS_HUNK = 1
DEVICE_LINK_FILE_STATUS_LAST_HUNK = 2


class MobileBackupClient(object):
    def __init__(self, lockdown):
        self.lockdown = lockdown
        self.service = lockdown.startService("com.apple.mobilebackup")
        self.udid = lockdown.udid
        DLMessageVersionExchange = self.service.recvPlist()
        print DLMessageVersionExchange
        version_major = DLMessageVersionExchange[1]
        self.service.sendPlist(["DLMessageVersionExchange", "DLVersionsOk", version_major])
        DLMessageDeviceReady = self.service.recvPlist()
        if DLMessageDeviceReady and DLMessageDeviceReady[0] == "DLMessageDeviceReady":
            print "Got DLMessageDeviceReady"
    
    def check_filename(self, name):
        if name.find("../") != -1:
            raise Exception("HAX, sneaky dots in path %s" % name)
        if not name.startswith(self.backupPath):
            if name.startswith(self.udid):
                return os.path.join(self.backupPath, name)
            return os.path.join(self.backupPath, self.udid, name)
        return name
        

    def read_file(self, filename):
        filename = self.check_filename(filename)
        if os.path.isfile(filename):
            f=open(filename, "rb")
            data = f.read()
            f.close()
            return data
        return None
    
    def write_file(self, filename, data): #FIXME
        filename = self.check_filename(filename)
        try:
            print "Writing filename %s" % filename
            f=open(filename, "wb")
            f.write(data)
            f.close()
        except: #FIXME
            print "mobilebackup.py Could not write", filename
            exit()
            
    
    def create_info_plist(self):
        root_node =  self.lockdown.getValue()
        info = {"BuildVersion": root_node["BuildVersion"],
                "DeviceName":  root_node["DeviceName"],
                "Display Name": root_node["DeviceName"],
                "GUID": "---",
                "ProductType": root_node["ProductType"],
                "ProductVersion": root_node["ProductVersion"],
                "Serial Number": root_node["SerialNumber"],
                "Unique Identifier": self.udid.upper(),
                "Target Identifier": self.udid,
                "Target Type": "Device",
                "iTunes Version": "10.0.1"
                }
        if root_node.has_key("IntegratedCircuitCardIdentity"):
            info["ICCID"] = root_node["IntegratedCircuitCardIdentity"]
        if root_node.has_key("InternationalMobileEquipmentIdentity"):
            info["IMEI"] = root_node["InternationalMobileEquipmentIdentity"]
        info["Last Backup Date"] = datetime.datetime.now()
        
        iTunesFiles = ["ApertureAlbumPrefs",
                        "IC-Info.sidb",
                        "IC-Info.sidv",
                        "PhotosFolderAlbums",
                        "PhotosFolderName",
                        "PhotosFolderPrefs",
                        "iPhotoAlbumPrefs",
                        "iTunesApplicationIDs",
                        "iTunesPrefs",
                        "iTunesPrefs.plist"
        ]
        afc = AFCClient(self.lockdown)
        iTunesFilesDict = {}
        iTunesFiles = afc.read_directory("/iTunes_Control/iTunes/")
        #print iTunesFiles
        for i in iTunesFiles:
            data = afc.get_file_contents("/iTunes_Control/iTunes/"  + i)
            if data:
                iTunesFilesDict[i] = plistlib.Data(data)
        info["iTunesFiles"] = iTunesFilesDict
        
        iBooksData2 = afc.get_file_contents("/Books/iBooksData2.plist")
        if iBooksData2:
            info["iBooks Data 2"] = plistlib.Data(iBooksData2)
        #pprint(info)
        print self.lockdown.getValue("com.apple.iTunes")
        info["iTunes Settings"] = self.lockdown.getValue("com.apple.iTunes")
        #self.backupPath = self.udid
        #if not os.path.isdir(self.backupPath):
        #    os.makedirs(self.backupPath)
        #print info
        #raw_input()
        print "Creating %s" % os.path.join(self.udid,"Info.plist")
        self.write_file(os.path.join(self.udid,"Info.plist"), plistlib.writePlistToString(info))

    def ping(self, message):
        self.service.sendPlist(["DLMessagePing", message])
        print "ping response", self.service.recvPlist()
    
    def device_link_service_send_process_message(self, msg):
        return self.service.sendPlist(["DLMessageProcessMessage", msg])
    
    def device_link_service_receive_process_message(self):
        req = self.service.recvPlist()
        if req:
            assert req[0] == "DLMessageProcessMessage"
            return req[1]
    
    def send_file_received(self):
        return self.device_link_service_send_process_message({"BackupMessageTypeKey": "kBackupMessageBackupFileReceived"})

    def request_backup(self):
        req = {"BackupComputerBasePathKey": "/",
        "BackupMessageTypeKey": "BackupMessageBackupRequest",
        "BackupProtocolVersion": "1.6"
        }
        self.create_info_plist()
        self.device_link_service_send_process_message(req)
        res = self.device_link_service_receive_process_message()
        if not res:
            return
        if res["BackupMessageTypeKey"] != "BackupMessageBackupReplyOK":
            print res
            return
        self.device_link_service_send_process_message(res)
        
        filedata = ""
        f = None
        outpath = None
        while True:
            res = self.service.recvPlist()
            if not res or res[0] != "DLSendFile":
                if res[0] == "DLMessageProcessMessage":
                    if res[1].get("BackupMessageTypeKey") == "BackupMessageBackupFinished":
                        print "Backup finished OK !"
                        #TODO BackupFilesToDeleteKey
                        plistlib.writePlist(res[1]["BackupManifestKey"], self.check_filename("Manifest.plist"))
                break
            data = res[1].data
            info = res[2]
            if not f:
                outpath = self.check_filename(info["DLFileDest"])
                print info["DLFileAttributesKey"]["Filename"], info["DLFileDest"]
                f = open(outpath + ".mddata", "wb")
            f.write(data)
            if info.get("DLFileStatusKey") == DEVICE_LINK_FILE_STATUS_LAST_HUNK:
                self.send_file_received()
                f.close()
                if not info.get("BackupManifestKey", False):
                    plistlib.writePlist(info["BackupFileInfo"], outpath + ".mdinfo")
                f = None
    
if __name__ == "__main__":
    lockdown = LockdownClient()
    mb = MobileBackupClient(lockdown)
    mb.request_backup()

