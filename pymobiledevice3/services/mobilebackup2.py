#!/usr/bin/env python3
import plistlib
import datetime
import os

from optparse import OptionParser
from time import mktime, gmtime
from uuid import uuid4
from stat import *

from pymobiledevice3.afc import AFCClient
from pymobiledevice3.services.installation_proxy_service import InstallationProxyService
from pymobiledevice3.services.notification_proxy_service import *
from pymobiledevice3.services.springboard_services import SpringBoardServicesService
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobilebackup import MobileBackup

CODE_SUCCESS = 0x00
CODE_ERROR_LOCAL = 0x06
CODE_ERROR_REMOTE = 0x0b
CODE_FILE_DATA = 0x0c

ERROR_ENOENT = -6
ERROR_EEXIST = -7

LOCK_ATTEMPTS = 10


class DeviceVersionNotSupported(Exception):
    def __str__(self):
        return "Device version not supported, please use mobilebackup"


class MobileBackup2(MobileBackup):
    service = None

    def __init__(self, lockdown=None, backupPath=None, password="", udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.backupPath = backupPath if backupPath else "backups"
        self.password = password
        self.lockdown = lockdown if lockdown else LockdownClient(udid=udid)
        if not self.lockdown:
            raise Exception("Unable to start lockdown")

        ProductVersion = self.lockdown.get_value("", "ProductVersion")
        if ProductVersion and int(ProductVersion[:ProductVersion.find('.')]) < 5:
            raise DeviceVersionNotSupported
        self.start()

    def start(self):
        self.udid = lockdown.get_value("", "UniqueDeviceID")
        self.willEncrypt = lockdown.get_value("com.apple.mobile.backup", "WillEncrypt")
        self.escrowBag = lockdown.get_value('', 'EscrowBag')
        self.afc = AFCClient(self.lockdown)  # We need this to create lock files
        self.service = self.lockdown.start_service("com.apple.mobilebackup2")
        if not self.service:
            raise Exception("MobileBackup2 init error : Could not start com.apple.mobilebackup2")

        if not os.path.isdir(self.backupPath):
            os.makedirs(self.backupPath, 0o0755)

        self.logger.info("Starting new com.apple.mobilebackup2 service with working dir: %s", self.backupPath)

        DLMessageVersionExchange = self.service.recv_plist()
        version_major = DLMessageVersionExchange[1]
        self.service.send_plist(["DLMessageVersionExchange", "DLVersionsOk", version_major])
        DLMessageDeviceReady = self.service.recv_plist()
        if DLMessageDeviceReady and DLMessageDeviceReady[0] == "DLMessageDeviceReady":
            res = self.version_exchange()
            protocol_version = res.get('ProtocolVersion')
            self.logger.info("Negotiated Protocol Version %s", protocol_version)
        else:
            raise Exception("MobileBackup2 init error %s", DLMessageDeviceReady)

    def __del__(self):
        if self.service:
            self.service.send_plist(["DLMessageDisconnect", "___EmptyParameterString___"])

    def internal_mobilebackup2_send_message(self, name, data):
        data["MessageName"] = name
        self.device_link_service_send_process_message(data)

    def internal_mobilebackup2_receive_message(self, name=None):
        res = self.device_link_service_receive_process_message()
        if res:
            if name and res["MessageName"] != name:
                self.logger.error("MessageName does not match %s %s", name, str(res))
            return res

    def version_exchange(self):
        self.internal_mobilebackup2_send_message("Hello",
                                                 {"SupportedProtocolVersions": [2.0, 2.1]})

        return self.internal_mobilebackup2_receive_message("Response")

    def mobilebackup2_send_request(self, request, target, source, options=None):
        if options is None:
            options = {}
        d = {"TargetIdentifier": target,
             "SourceIdentifier": source,
             "Options": options}

        self.internal_mobilebackup2_send_message(request, d)

    def mobilebackup2_receive_message(self):
        return self.service.recv_plist()

    def mobilebackup2_send_status_response(self, status_code,
                                           status1="___EmptyParameterString___",
                                           status2=None):
        if status2 is None:
            status2 = {}
        a = ["DLMessageStatusResponse", status_code, status1, status2]
        self.service.send_plist(a)

    def mb2_handle_free_disk_space(self, msg):
        s = os.statvfs(self.backupPath)
        freeSpace = s.f_bsize * s.f_bavail
        res = ["DLMessageStatusResponse", 0, "___EmptyParameterString___", freeSpace]
        self.service.send_plist(res)

    def mb2_multi_status_add_file_error(self, errplist, path, error_code, error_message):
        errplist[path] = {"DLFileErrorCode": error_code, "DLFileErrorString": error_message}

    def mb2_handle_copy_item(self, msg):
        src = self.check_filename(msg[1])
        dst = self.check_filename(msg[2])
        if os.path.isfile(src):
            data = self.read_file(src)
            self.write_file(dst, data)
        else:
            os.makedirs(dst)
        self.mobilebackup2_send_status_response(0)

    def mb2_handle_send_file(self, filename, errplist):
        self.service.send_raw(filename)
        if not filename.startswith(self.udid):
            filename = self.udid + "/" + filename

        data = self.read_file(self.check_filename(filename))
        if data is not None:
            self.logger.info("Sending %s to device", filename)
            msg = b"".join([(CODE_FILE_DATA).to_bytes(1, 'little'), data])
            self.service.send_raw(msg)
            self.service.send_raw(chr(CODE_SUCCESS))
        else:
            self.logger.warning("File %s requested from device not found", filename)
            self.service.send_raw(chr(CODE_ERROR_LOCAL))
            self.mb2_multi_status_add_file_error(errplist, filename,
                                                 ERROR_ENOENT, "Could not find the droid you were looking for ;)")

    def mb2_handle_send_files(self, msg):
        err_plist = {}
        for f in msg[1]:
            self.mb2_handle_send_file(f, err_plist)
        msg = b'\x00\x00\x00\x00'
        self.service.send(msg)
        if len(err_plist):
            self.mobilebackup2_send_status_response(-13, 'Multi status', err_plist)
        else:
            self.mobilebackup2_send_status_response(0)

    def mb2_handle_list_directory(self, msg):
        path = msg[1]
        self.logger.info("List directory: %s" % path)
        dirlist = {}
        if path.find("../") != -1:
            raise Exception("HAX, sneaky dots in path %s" % name)
        for root, dirs, files in os.walk(os.path.join(self.backupPath, path)):
            for fname in files:
                fpath = os.path.join(root, fname)
                finfo = {}
                st = os.stat(fpath)
                ftype = "DLFileTypeUnknown"
                if S_ISDIR(st.st_mode):
                    ftype = "DLFileTypeDirectory"
                elif S_ISREG(st.st_mode):
                    ftype = "DLFileTypeRegular"
                finfo["DLFileType"] = ftype
                finfo["DLFileSize"] = st.st_size
                finfo["DLFileModificationDate"] = st.st_mtime
                dirlist[fname] = finfo
        self.mobilebackup2_send_status_response(0, status2=dirlist);

    def mb2_handle_make_directory(self, msg):
        dirname = self.check_filename(msg[1])
        self.logger.info("Creating directory %s", dirname)
        if not os.path.isdir(dirname):
            os.makedirs(dirname)
        self.mobilebackup2_send_status_response(0, "")

    def mb2_handle_receive_files(self, msg):
        done = 0
        while not done:
            device_filename = self.service.recv_raw()
            if device_filename == "":
                break
            backup_filename = self.service.recv_raw()
            self.logger.debug("Downloading: %s to %s", device_filename, backup_filename)
            filedata = bytearray(b"")
            last_code = 0x00
            while True:
                stuff = self.service.recv_raw()
                code = stuff[0]
                if code == CODE_FILE_DATA:
                    filedata = stuff[1:]
                elif code == CODE_SUCCESS:
                    self.write_file(self.check_filename(backup_filename), filedata)
                    break
                elif code == CODE_ERROR_REMOTE:
                    if last_code != CODE_FILE_DATA:
                        self.logger.warning("Received an error message from device: %s for:\n\t%s\n\t[%s]",
                                            ord(code), device_filename, backup_filename)
                else:
                    self.logger.warning("Unknown code: %s for:\n\t%s\n\t[%s]",
                                        code, device_filename, backup_filename)
                    self.logger.warning(msg)
                    # break
            last_code = code
        self.mobilebackup2_send_status_response(0)

    def mb2_handle_move_files(self, msg):
        self.logger.info("Moving %d files", len(msg[1]))
        for k, v in msg[1].items():
            self.logger.info("Renaming:\n\t%s \n\tto %s", self.check_filename(k), self.check_filename(v))
            os.rename(self.check_filename(k), self.check_filename(v))
        self.mobilebackup2_send_status_response(0)

    def mb2_handle_remove_files(self, msg):
        self.logger.info("Removing %d files", len(msg[1]))
        for filename in msg[1]:
            self.logger.info("Removing %s", self.check_filename(filename))
            try:
                filename = self.check_filename(filename)
                if os.path.isfile(filename):
                    os.unlink(filename)
            except Exception as e:
                self.logger.error(e)
        self.mobilebackup2_send_status_response(0)

    def work_loop(self):
        while True:
            msg = self.mobilebackup2_receive_message()
            if not msg:
                break

            assert (msg[0] in ["DLMessageDownloadFiles",
                               "DLContentsOfDirectory",
                               "DLMessageCreateDirectory",
                               "DLMessageUploadFiles",
                               "DLMessageMoveFiles", "DLMessageMoveItems",
                               "DLMessageRemoveFiles", "DLMessageRemoveItems",
                               "DLMessageCopyItem",
                               "DLMessageProcessMessage",
                               "DLMessageGetFreeDiskSpace",
                               "DLMessageDisconnect"])

            if msg[0] == "DLMessageDownloadFiles":
                self.mb2_handle_send_files(msg)
            elif msg[0] == "DLContentsOfDirectory":
                self.mb2_handle_list_directory(msg)
            elif msg[0] == "DLMessageCreateDirectory":
                self.mb2_handle_make_directory(msg)
            elif msg[0] == "DLMessageUploadFiles":
                self.mb2_handle_receive_files(msg)
            elif msg[0] in ["DLMessageMoveFiles", "DLMessageMoveItems"]:
                self.mb2_handle_move_files(msg)
            elif msg[0] in ["DLMessageRemoveFiles", "DLMessageRemoveItems"]:
                self.mb2_handle_remove_files(msg)
            elif msg[0] == "DLMessageCopyItem":
                self.mb2_handle_copy_item(msg)
            elif msg[0] == "DLMessageProcessMessage":
                errcode = msg[1].get("ErrorCode")
                if errcode == 0:
                    m = msg[1].get("MessageName")
                    if m != "Response":
                        self.logger.warning(m)
                    break
                if errcode == 1:
                    self.logger.info("Please unlock your device and retry...")
                    raise Exception("Please unlock your device and retry...")
                if errcode == 211:
                    self.logger.info("Please go to Settings->iClould->Find My iPhone and disable it")
                    raise Exception('Please go to Settings->iClould->Find My iPhone and disable it')
                if errcode == 105:
                    self.logger.info("Not enough free space on device for restore")
                    raise Exception('Not enough free space on device for restore')
                if errcode == 17:
                    self.logger.info("please press 'trust this computer' in your device")
                    raise Exception('please press \'trust this computer\' in your device')
                if errcode == 102:
                    self.logger.info("Please reboot your device and try again")
                    raise Exception('Please reboot your device and try again')
                self.logger.error("Unknown error: %d : %s", errcode, msg[1].get("ErrorDescription", ""))
                raise Exception('Unknown error ' + str(errcode) + msg[1].get("ErrorDescription", ""))
            elif msg[0] == "DLMessageGetFreeDiskSpace":
                self.mb2_handle_free_disk_space(msg)
            elif msg[0] == "DLMessageDisconnect":
                break

    def create_status_plist(self, fullBackup=True):
        # Creating Status file for backup
        statusDict = {'UUID': str(uuid4()).upper(),
                      'BackupState': 'new',
                      'IsFullBackup': fullBackup,
                      'Version': '2.4',
                      'Date': datetime.datetime.fromtimestamp(mktime(gmtime())),
                      'SnapshotState': 'finished'
                      }
        with open(self.check_filename("Status.plist"), 'wb') as f:
            plistlib.dump(statusDict, f)

    def create_info_plist(self):
        # Get device information
        device_info = self.lockdown.all_values

        # Get a list of installed user applications
        instpxy = InstallationProxyService(self.lockdown)
        apps = instpxy.browse({"ApplicationType": "User"},
                              ["CFBundleIdentifier", "ApplicationSINF", "iTunesMetadata"])
        # Create new info.plits
        info = {"BuildVersion": device_info.get("BuildVersion") or "",
                "DeviceName": device_info.get("DeviceName") or "", "Display Name": device_info.get("DeviceName") or "",
                "GUID": "---", "Product Name": device_info.get("ProductName" or ""),
                "ProductType": device_info.get("ProductType") or "",
                "ProductVersion": device_info.get("ProductVersion") or "",
                "Serial Number": device_info.get("SerialNumber") or "", "Unique Identifier": self.udid.upper(),
                "Target Identifier": self.udid, "Target Type": "Device", "iTunes Version": "10.0.1",
                "MEID": device_info.get("MobileEquipmentIdentifier") or "",
                "Phone Number": device_info.get("PhoneNumber") or "",
                "ICCID": device_info.get("IntegratedCircuitCardIdentity") or "",
                "IMEI": device_info.get("InternationalMobileEquipmentIdentity") or "",
                "Last Backup Date": datetime.datetime.now()}

        # Starting SpringBoard service to retrieve icons position
        self.sbs = SpringBoardServicesService(self.lockdown)
        installed_apps = []
        apps_data = {}
        for app_entry in apps:
            tmp = {}
            bid = app_entry.get("CFBundleIdentifier")
            if bid:
                installed_apps.append(bid)
                pngdata = self.sbs.get_icon_pngdata(bid)
                if pngdata:
                    tmp["PlaceholderIcon"] = pngdata
                tmp["iTunesMetadata"] = app_entry.get("iTunesMetadata")
                tmp["ApplicationSINF"] = app_entry.get("ApplicationSINF")
                apps_data[bid] = tmp

        info["Applications"] = apps_data
        info["Installed Applications"] = installed_apps
        # Handling itunes files
        iTunesFiles = ["ApertureAlbumPrefs", "IC-Info.sidb", "IC-Info.sidv", "PhotosFolderAlbums",
                       "PhotosFolderName", "PhotosFolderPrefs", "VoiceMemos.plist", "iPhotoAlbumPrefs",
                       "iTunesApplicationIDs", "iTunesPrefs", "iTunesPrefs.plist"]
        iTunesFilesDict = {}
        for i in iTunesFiles:
            data = self.afc.get_file_contents("/iTunes_Control/iTunes/" + i)
            if data:
                iTunesFilesDict[i] = data

        info["iTunesFiles"] = iTunesFilesDict
        iBooksData2 = self.afc.get_file_contents("/Books/iBooksData2.plist")
        if iBooksData2:
            info["iBooks Data 2"] = iBooksData2

        info["iTunes Settings"] = self.lockdown.get_value("com.apple.iTunes")
        self.logger.info("Creating %s", os.path.join(self.udid, "Info.plist"))
        self.write_file(os.path.join(self.udid, "Info.plist"), plistlib.writePlistToString(info))

    def backup(self, full_backup=True):
        # TODO set_sync_lock
        self.logger.info("Starting %s backup...", ("Encrypted " if self.willEncrypt else ""))
        if not os.path.isdir(os.path.join(self.backupPath, self.udid)):
            os.makedirs(os.path.join(self.backupPath, self.udid))
        self.logger.info("Backup mode: %s", "Full backup" if full_backup else "Incremental backup")
        self.create_info_plist()
        options = {"ForceFullBackup": full_backup}
        self.mobilebackup2_send_request("Backup", self.udid, options)
        self.work_loop()

    def restore(self, options=None,
                password=None):

        if options is None:
            options = {"RestoreSystemFiles": True,
                       "RestoreShouldReboot": True,
                       "RestorePreserveCameraRoll": True,
                       "RemoveItemsNotRestored": False,
                       "RestoreDontCopyBackup": True,
                       "RestorePreserveSettings": True}
        self.logger.info("Starting restoration...")
        m = os.path.join(self.backupPath, self.udid, "Manifest.plist")
        try:
            with open(m, 'rb') as f:
                manifest = plistlib.load(f)
        except IOError:
            self.logger.error("not a valid backup folder")
            return -1
        if manifest.get("IsEncrypted"):
            print("Backup is encrypted, enter password : ")
            if password:
                self.password = password
            else:
                self.password = input()
            options["Password"] = self.password
        self.mobilebackup2_send_request("Restore", self.udid, self.udid, options)
        self.work_loop()

    def info(self, options=None):
        if options is None:
            options = {}
        source_udid = self.udid
        self.mobilebackup2_send_request("Info", self.udid, source_udid, options)
        self.work_loop()

    def list(self, options=None):
        if options is None:
            options = {}
        source_udid = self.udid
        self.mobilebackup2_send_request("List", self.udid, source_udid, options)
        self.work_loop()

    def changepw(self, oldpw, newpw):
        options = {"OldPassword": oldpw,
                   "NewPassword": newpw}

        self.mobilebackup2_send_request("ChangePassword", self.udid, "", options)
        self.work_loop()

    def unback(self, options=None):
        if options is None:
            options = {"Password": None}
        source_udid = self.udid
        self.mobilebackup2_send_request("Unback", self.udid, source_udid, options)
        self.work_loop()

    def enableCloudBackup(self, options=None):
        if options is None:
            options = {"CloudBackupState": False}
        self.mobilebackup2_send_request("EnableCloudBackup", self.udid, options)
        self.work_loop()


if __name__ == "__main__":
    parser = OptionParser(usage="%prog -u <udid> cmd <command options>")
    parser.add_option("-u", "--udid", default=False, action="store", dest="device_udid", metavar="DEVICE_UDID",
                      help="Device udid")
    parser.add_option("-b", "--backup", dest="backup", action="store_true", default=False,
                      help="Backup device")
    parser.add_option("-r", "--restore", dest="restore", action="store_true", default=False,
                      help="Restore device")
    parser.add_option("-i", "--info", dest="info", action="store_true", default=False,
                      help="Show backup info")
    parser.add_option("-l", "--list", dest="list", action="store_true", default=False,
                      help="Show backup info")
    parser.add_option("-p", "--path", dest="path", action="store", default=False,
                      help="path to backup/restore to")
    (options, args) = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    lockdown = LockdownClient(options.device_udid)
    mb = MobileBackup2(lockdown, options.path)
    if options.backup:
        mb.backup(full_backup=False)
    elif options.restore:
        mb.restore()
    elif options.info:
        mb.info()
    elif options.list:
        mb.list()
    else:
        parser.error("Incorrect number of arguments")
