from lockdown import LockdownClient
from mobilebackup import MobileBackupClient
from optparse import OptionParser
from pprint import pprint
#from util import makedirs, read_file, 
from util import write_file, hexdump
#from util.bplist import BPlistReader
from biplist import writePlist, readPlist, Data
import os
import hashlib
from struct import unpack, pack
from time import mktime, gmtime, sleep, time
import datetime

CODE_SUCCESS = 0x00
CODE_ERROR_LOCAL =  0x06
CODE_ERROR_REMOTE = 0x0b
CODE_FILE_DATA = 0x0c

ERROR_ENOENT = -6
ERROR_EEXIST = -7

MBDB_SIGNATURE = 'mbdb\x05\x00'
MASK_SYMBOLIC_LINK = 0xa000
MASK_REGULAR_FILE = 0x8000
MASK_DIRECTORY = 0x4000

class MobileBackup2Client(MobileBackupClient):
    def __init__(self, lockdown = None,backupPath = None):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()
        try:
            self.udid = lockdown.getValue("", "UniqueDeviceID")#lockdown.udid
        except:
            self.lockdown = LockdownClient()
            self.udid = self.lockdown.getValue("", "UniqueDeviceID")
        self.service = self.lockdown.startService("com.apple.mobilebackup2")
        if not self.service:
            raise Exception("MobileBackup2Client init error : Could not start com.apple.mobilebackup2")
        if backupPath:
            self.backupPath = backupPath
        else:
            self.backupPath = "backups" #self.udid
        if not os.path.isdir(self.backupPath):
            os.makedirs(self.backupPath,0o0755)  
        
        print "Starting new com.apple.mobilebackup2 service with working dir: %s" %  self.backupPath
        self.password = ""
        DLMessageVersionExchange = self.service.recvPlist()
        #print DLMessageVersionExchange
        version_major = DLMessageVersionExchange[1]
        self.service.sendPlist(["DLMessageVersionExchange", "DLVersionsOk", version_major])
        DLMessageDeviceReady = self.service.recvPlist()
        #print DLMessageDeviceReady
        if DLMessageDeviceReady and DLMessageDeviceReady[0] == "DLMessageDeviceReady":
            #print "Got DLMessageDeviceReady"
            self.version_exchange()
        else:
            raise Exception("MobileBackup2Client init error %s" % DLMessageDeviceReady)

    def __del__(self):
        if self.service:
            #print "Disconnecting"
            self.service.sendPlist(["DLMessageDisconnect", "___EmptyParameterString___"])
            #print self.service.recvPlist() 
         
    def internal_mobilebackup2_send_message(self, name, data):
        data["MessageName"] = name
        self.device_link_service_send_process_message(data)
    
    def internal_mobilebackup2_receive_message(self, name=None):
        res = self.device_link_service_receive_process_message()
        if res:
            if name and res["MessageName"] != name:
                print "MessageName does not match %s %s" % (name, str(res))
            return res

    def version_exchange(self):
        self.internal_mobilebackup2_send_message("Hello", {"SupportedProtocolVersions": [2.0,2.1]})
        return self.internal_mobilebackup2_receive_message("Response")
    
    def mobilebackup2_send_request(self, request, target, source, options={}):
        d = {"TargetIdentifier": target,
             "SourceIdentifier": source,
             "Options": options}
        #pprint(d)
        self.internal_mobilebackup2_send_message(request, d)        
    
    def mobilebackup2_receive_message(self):
        return self.service.recvPlist()
    
    def mobilebackup2_send_status_response(self, status_code, status1="___EmptyParameterString___", status2={}):
        a = ["DLMessageStatusResponse", status_code, status1, status2]
        self.service.sendPlist(a)

    def mb2_handle_free_disk_space(self,msg): #DRK
        s = os.statvfs(self.backupPath)
        freeSpace = s.f_bsize * s.f_bavail
        #print "freeSpage %s" % freeSpace
        a = ["DLMessageStatusResponse", 0, freeSpace]
        self.service.sendPlist(a)



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
        #print "Reading",self.check_filename(filename) #FIXME
        data = self.read_file(self.check_filename(filename))
        if data != None:
            #print hexdump(data)
            print "Sending %s to device" % filename
            self.service.send_raw(chr(CODE_FILE_DATA) + data)
            self.service.send_raw(chr(CODE_SUCCESS))
        else:
            #print "DATA %s" % hexdump(data)
            print "File %s requested from device not found" % filename
            self.service.send_raw(chr(CODE_ERROR_LOCAL))
            self.mb2_multi_status_add_file_error(errplist, filename, ERROR_ENOENT, "Could not find the droid you were looking for ;)")
        
    def mb2_handle_send_files(self, msg):
        errplist = {}
        for f in msg[1]:
            self.mb2_handle_send_file(f, errplist)
        self.service.send("\x00\x00\x00\x00")
        if len(errplist):
            self.mobilebackup2_send_status_response(-13, "Multi status", errplist)
        else:
            self.mobilebackup2_send_status_response(0)

    def mb2_handle_list_directory(self, msg):
        path = msg[1]
        dirlist = {}
        self.mobilebackup2_send_status_response(0, status2=dirlist);

    def mb2_handle_make_directory(self, msg):
        dirname = self.check_filename(msg[1])
        print "Creating directory %s" % dirname
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
            #print device_filename, backup_filename
            filedata = ""
            while True:
                stuff = self.service.recv_raw()
                if ord(stuff[0]) == CODE_FILE_DATA:
                    filedata += stuff[1:]
                elif ord(stuff[0]) == CODE_SUCCESS:
                    #print "Success"
                    self.write_file(self.check_filename(backup_filename), filedata)
                    break
                else:
                    print "Unknown code", ord(stuff[0])
                    break
        self.mobilebackup2_send_status_response(0)

    def mb2_handle_move_files(self, msg):
        for k,v in msg[1].items():
            print "Renaming %s to %s"  % (self.check_filename(k),self.check_filename(v))
            os.rename(self.check_filename(k),self.check_filename(v))
        self.mobilebackup2_send_status_response(0)

    def mb2_handle_remove_files(self, msg):
        for filename in msg[1]:
            print "Removing ", self.check_filename(filename)
            try:
                filename = self.check_filename(filename)
                if os.path.isfile(filename):
                     os.unlink(filename)
            except Exception, e:
                print e
        self.mobilebackup2_send_status_response(0)
        
    def work_loop(self):
        while True:
            msg = self.mobilebackup2_receive_message()
            #print msg
            if not msg:
                break

            assert(msg[0] in ["DLMessageDownloadFiles",
                    "DLContentsOfDirectory",
                    "DLMessageCreateDirectory",
                    "DLMessageUploadFiles",
                    "DLMessageMoveFiles","DLMessageMoveItems",
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
            elif msg[0] in ["DLMessageMoveFiles","DLMessageMoveItems"]:#DRK
                self.mb2_handle_move_files(msg)
            elif msg[0] in ["DLMessageRemoveFiles", "DLMessageRemoveItems"]:#DRK
                self.mb2_handle_remove_files(msg)
            elif msg[0] == "DLMessageCopyItem":
                self.mb2_handle_copy_item(msg)
            elif msg[0] == "DLMessageProcessMessage":
                return msg[1]
            elif msg[0] == "DLMessageGetFreeDiskSpace":
                self.mb2_handle_free_disk_space(msg) #
            elif msg[0] == "DLMessageDisconnect":
                break
  
    def create_status_plist(self):
        #Creating Status file for backup
        statusDict = { 'UUID': '82D108D4-521C-48A5-9C42-79C5E654B98F', #FixMe We Should USE an UUID generator uuid.uuid3(uuid.NAMESPACE_DNS, hostname)
                   'BackupState': 'new', 
                   'IsFullBackup': True, 
                   'Version': '2.4', 
                   'Date': datetime.datetime.fromtimestamp(mktime(gmtime())),
                   'SnapshotState': 'finished'
                 }
        writePlist(statusDict,self.check_filename("Status.plist"))


    def backup(self):#,bkpPath=None):
        #if bkpPath:
        #   self.backupPath = bkpPath
        if not os.path.isdir(os.path.join(self.backupPath,self.udid)):
            os.makedirs(os.path.join(self.backupPath,self.udid))
        self.create_info_plist()
        self.mobilebackup2_send_request("Backup", self.udid, "")
        self.work_loop()
    
    def restore(self,options = {"RestoreSystemFiles": True,
                                "RestoreShouldReboot": False,
                                "RestoreDontCopyBackup": True, #FIXME
                                "RestorePreserveSettings": True}):#,bkpPath=None):
        
        #if bkpPath:
        #   self.backupPath = bkpPath
        m = os.path.join(self.backupPath,self.udid,"Manifest.plist")
        manifest = readPlist(m)
        if manifest["IsEncrypted"]:
            print "Backup is encrypted, enter password : "
            self.password = raw_input()
            options["Password"] = self.password
        self.mobilebackup2_send_request("Restore", self.udid, self.udid, options)
        self.work_loop()

    def info(self):
        self.mobilebackup2_send_request("Info", self.udid, "")
        info = self.work_loop()
        if info:
            pprint(info['Content'])

    def list(self):
        self.mobilebackup2_send_request("List", self.udid, "")
        z = self.work_loop()
        if z:
            print z["Content"]
   
    def unback(self):
        self.mobilebackup2_send_request("Unback", self.udid, "")
        print self.work_loop()
    
    def mbdb_add_link(self, domain, path, target, mode=0xA1ED):
        return self.mbdb_add(domain,path,target=target, mode=mode | MASK_SYMBOLIC_LINK)
    
    def mbdb_add_file(self, domain, path, filedata, mode=0x81ED,protection_class=0x04,num_attributes=0x00):
        return self.mbdb_add(domain,path, filedata=filedata, 
                             mode=(mode | MASK_REGULAR_FILE),
                             protection_class=protection_class,
                             num_attributes=num_attributes)

    def mbdb_add_directory(self, domain, path, mode=0x41ED):
        return self.mbdb_add(domain,path, mode=mode | MASK_DIRECTORY)
    
    def mbdb_add(self, domain, path, target="", encryption_key="", filedata="", 
                mode=0x81ED,inode_number=0x1337,
                user_id=501,group_id=501,last_modification=None,
                last_status_change_time=None,birth_time=None,
                protection_class=0x00,num_attributes=0x00):
        #print path, protection_class
        if not last_status_change_time:
            last_status_change_time = time()
        if not birth_time:
            birth_time = time()
        if not last_modification:
            last_modification = time()

        digest = ""
        fn = domain + "-" + path
        namedigest = hashlib.sha1(fn).digest()
        if (mode & MASK_SYMBOLIC_LINK) != MASK_SYMBOLIC_LINK and (mode & MASK_DIRECTORY) != MASK_DIRECTORY : 
            fpath = os.path.join(self.backupPath, self.udid ,namedigest.encode("hex"))
            if os.path.isfile(fpath):
                print "%s-%s already exists, deleting it" % (domain, path)
                os.remove(fpath)
            if filedata:
                if domain == "HomeDomain":
                    digest = hashlib.sha1(filedata).digest()
                write_file(fpath, filedata) 


        data = []
        data.append(pack('>H', mode)) # mode, sur 2octets 
        data.append(pack('>Q', inode_number)) # inode_number, sur 8octets
        data.append(pack('>I', user_id)) # user_id, sur 4octets
        data.append(pack('>I', group_id)) # group_id, sur 4octets
        data.append(pack('>i', last_modification)) # last_modification, sur 4octets
        data.append(pack('>i', last_status_change_time)) # last_status_change_time, sur 4octets
        data.append(pack('>i', birth_time)) # birth_time, sur 4octets
        data.append(pack('>q', len(filedata)))
        data.append(chr(protection_class)) # protection_class, sur 1octet
        data.append(chr(num_attributes)) # num_attributes, sur 1octet
    
        payload = ""
        for i in [domain,path,target,digest,encryption_key]:
            if len(i) == 0:
                payload += pack('>H',0xFFFF)
            else:
                payload += pack('>H',len(i)) + i
         
        payload += "".join(map(str,data))
        #print hexdump(payload)
        m = os.path.join(self.backupPath,self.udid,"Manifest.mbdb")
        if  os.path.isfile(m):
            off = os.path.getsize(os.path.join(m))
            f = open(m, "ab")
        else:
            off = 0
            print "[!] Creating new mbdb file:", m
            f = open(m, "wb+")
            f.write(MBDB_SIGNATURE)

        f.write(payload)
        f.close()
        print "Creating %s from %s" % (namedigest.encode("hex"),path) 
        #HAX for ios 4  
        if os.path.exists(os.path.join(self.backupPath,self.udid,"Manifest.mbdx")):
            print "Patching mbdx, mdbd offset=%d" % off
            f = open(os.path.join(self.backupPath,self.udid,"Manifest.mbdx"), "rb")
            mbdx = f.read()
            f.close()
            nrecords = unpack(">L", mbdx[6:10])[0]
            print "%d recrods in mdbx" % nrecords
            nrecords += 1
            index = namedigest + pack(">L", off-6) + pack('>H',mode)
            f = open(os.path.join(self.backupPath, "Manifest.mbdx"), "wb")
            f.write("mbdx\x02\x00" + pack(">L", nrecords) + mbdx[10:] +index)
            f.close()

    def save_mbdb(self):
        return read_file(os.path.join(self.backupPath, "Manifest.mbdb"))
    
    def restore_mbdb(self, data):
        return write_file(os.path.join(self.backupPath, "Manifest.mbdb"), data)

    def save_mbdb(self):
        return read_file(os.path.join(self.backupPath, "Manifest.mbdb"))
    
    def restore_mbdb(self, data):
        return write_file(os.path.join(self.backupPath, "Manifest.mbdb"), data)


    
                     
if __name__ == "__main__":
    parser = OptionParser(usage="%prog")
    parser.add_option("-b", "--backup", dest="backup", action="store_true", default=False,
                  help="Backup device")
    parser.add_option("-r", "--restore", dest="restore", action="store_true", default=False,
                  help="Restore device")
    parser.add_option("-i", "--info", dest="info", action="store_true", default=False,
                  help="Show backup info")
    parser.add_option("-l", "--list", dest="list", action="store_true", default=False,
                  help="Show backup info")
    #parser.set_defaults(backup=True)
    (options, args) = parser.parse_args()
    
    lockdown = LockdownClient()
    mb = MobileBackup2Client(lockdown)

    if options.backup:
        print "Lauching device backup..."
        mb.backup()
    elif options.restore:
        print "Restoring device backup..."
        mb.restore()
    if options.info:
        mb.info()
    if options.list:
        mb.list()

