import plistlib
import os
import datetime
import logging
import codecs

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService

MOBILEBACKUP_E_SUCCESS = 0
MOBILEBACKUP_E_INVALID_ARG = -1
MOBILEBACKUP_E_PLIST_ERROR = -2
MOBILEBACKUP_E_MUX_ERROR = -3
MOBILEBACKUP_E_BAD_VERSION = -4
MOBILEBACKUP_E_REPLY_NOT_OK = -5
MOBILEBACKUP_E_UNKNOWN_ERROR = -256

DEVICE_LINK_FILE_STATUS_NONE = 0
DEVICE_LINK_FILE_STATUS_HUNK = 1
DEVICE_LINK_FILE_STATUS_LAST_HUNK = 2


class DeviceVersionNotSupported(Exception):
    def __str__(self):
        return "Device version not supported, please use mobilebackup2"


class MobileBackup(object):
    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        product_version = self.lockdown.get_value("", "ProductVersion")
        if product_version[0] >= "5":
            raise DeviceVersionNotSupported()
        self.start()

    def start(self):
        self.service = self.lockdown.start_service("com.apple.mobilebackup")
        self.udid = self.lockdown.udid
        DLMessageVersionExchange = self.service.recv_plist()
        version_major = DLMessageVersionExchange[1]
        self.service.send_plist(["DLMessageVersionExchange", "DLVersionsOk", version_major])
        DLMessageDeviceReady = self.service.recv_plist()
        if DLMessageDeviceReady and DLMessageDeviceReady[0] == "DLMessageDeviceReady":
            self.logger.info("Got DLMessageDeviceReady")

    def check_filename(self, name):
        if not isinstance(name, str):
            name = codecs.decode(name)
        if "../" in name:
            raise Exception("HAX, sneaky dots in path %s" % name)
        if not name.startswith(self.backupPath):
            if name.startswith(self.udid):
                name = os.path.join(self.backupPath, name)
                return name
            name = os.path.join(self.backupPath, self.udid, name)
            return name
        return name

    def read_file(self, filename):
        filename = self.check_filename(filename)
        if os.path.isfile(filename):
            with open(filename, 'rb') as f:
                data = f.read()
                f.close()
                return data
        return None

    def write_file(self, filename, data):
        filename = self.check_filename(filename)
        with open(filename, 'wb') as f:
            f.write(data)
            f.close()

    def create_info_plist(self):
        root_node = self.lockdown.all_values
        info = {"BuildVersion": root_node.get("BuildVersion") or "", "DeviceName": root_node.get("DeviceName") or "",
                "Display Name": root_node.get("DeviceName") or "", "GUID": "---",
                "ProductType": root_node.get("ProductType") or "",
                "ProductVersion": root_node.get("ProductVersion") or "",
                "Serial Number": root_node.get("SerialNumber") or "", "Unique Identifier": self.udid.upper(),
                "Target Identifier": self.udid, "Target Type": "Device", "iTunes Version": "10.0.1",
                "ICCID": root_node.get("IntegratedCircuitCardIdentity") or "",
                "IMEI": root_node.get("InternationalMobileEquipmentIdentity") or "",
                "Last Backup Date": datetime.datetime.now()}

        afc = AfcService(self.lockdown)
        iTunesFilesDict = {}
        iTunesFiles = afc.listdir("/iTunes_Control/iTunes/")

        for i in iTunesFiles:
            data = afc.get_file_contents("/iTunes_Control/iTunes/" + i)
            if data:
                iTunesFilesDict[i] = plistlib.Data(data)
        info["iTunesFiles"] = iTunesFilesDict

        iBooksData2 = afc.get_file_contents("/Books/iBooksData2.plist")
        if iBooksData2:
            info["iBooks Data 2"] = plistlib.Data(iBooksData2)

        info["iTunes Settings"] = self.lockdown.get_value("com.apple.iTunes")
        self.logger.info("Creating: %s", os.path.join(self.udid, "Info.plist"))
        self.write_file(os.path.join(self.udid, "Info.plist"), plistlib.writePlistToString(info))

    def ping(self, message):
        self.service.send_plist(["DLMessagePing", message])
        res = self.service.recv_plist()
        self.logger.debug("ping response:", res)

    def device_link_service_send_process_message(self, msg):
        return self.service.send_plist(["DLMessageProcessMessage", msg])

    def device_link_service_receive_process_message(self):
        req = self.service.recv_plist()
        if req:
            assert req[0] == "DLMessageProcessMessage"
            return req[1]

    def send_file_received(self):
        return self.device_link_service_send_process_message(
            {"BackupMessageTypeKey": "kBackupMessageBackupFileReceived"})

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
            self.logger.error(res)
            return
        self.device_link_service_send_process_message(res)

        f = None
        outpath = None
        while True:
            res = self.service.recv_plist()
            if not res or res[0] != "DLSendFile":
                if res[0] == "DLMessageProcessMessage":
                    if res[1].get("BackupMessageTypeKey") == "BackupMessageBackupFinished":
                        self.logger.info("Backup finished OK !")
                        # TODO: BackupFilesToDeleteKey
                        with open(self.check_filename("Manifest.plist"), 'wb') as f:
                            plistlib.dump(res[1]["BackupManifestKey"], f)
                break
            data = res[1].data
            info = res[2]
            if not f:
                outpath = self.check_filename(info.get("DLFileDest"))
                self.logger.debug("%s %s", info["DLFileAttributesKey"]["Filename"], info.get("DLFileDest"))
                f = open(outpath + ".mddata", "wb")
            f.write(data)
            if info.get("DLFileStatusKey") == DEVICE_LINK_FILE_STATUS_LAST_HUNK:
                self.send_file_received()
                f.close()
                if not info.get("BackupManifestKey", False):
                    with open(outpath + ".mdinfo", 'wb') as f:
                        plistlib.dump(info.get("BackupFileInfo"), f)
                f = None
