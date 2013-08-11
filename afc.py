from construct.core import Struct
from construct.lib.container import Container
from construct.macros import String, ULInt64
from lockdown import LockdownClient
import struct
from cmd import Cmd
import os
from util import hexdump, parsePlist
from pprint import pprint
import plistlib
import time 
"""
<key>com.apple.afc</key>
    <dict>
        <key>AllowUnactivatedService</key>
        <true/>
        <key>Label</key>
        <string>com.apple.afc</string>
        <key>ProgramArguments</key>
        <array>
            <string>/usr/libexec/afcd</string>
            <string>--lockdown</string>
            <string>-d</string>
            <string>/var/mobile/Media</string>
            <string>-u</string>
            <string>mobile</string>
        </array>
    </dict>
"""

AFC_OP_STATUS          = 0x00000001
AFC_OP_DATA            = 0x00000002    #Data */
AFC_OP_READ_DIR        = 0x00000003    #ReadDir */
AFC_OP_READ_FILE       = 0x00000004    #ReadFile */
AFC_OP_WRITE_FILE      = 0x00000005    #WriteFile */
AFC_OP_WRITE_PART      = 0x00000006    #WritePart */
AFC_OP_TRUNCATE        = 0x00000007    #TruncateFile */
AFC_OP_REMOVE_PATH     = 0x00000008    #RemovePath */
AFC_OP_MAKE_DIR        = 0x00000009    #MakeDir */
AFC_OP_GET_FILE_INFO   = 0x0000000a    #GetFileInfo */
AFC_OP_GET_DEVINFO     = 0x0000000b    #GetDeviceInfo */
AFC_OP_WRITE_FILE_ATOM = 0x0000000c    #WriteFileAtomic (tmp file+rename) */
AFC_OP_FILE_OPEN       = 0x0000000d    #FileRefOpen */
AFC_OP_FILE_OPEN_RES   = 0x0000000e    #FileRefOpenResult */
AFC_OP_READ            = 0x0000000f    #FileRefRead */
AFC_OP_WRITE           = 0x00000010    #FileRefWrite */
AFC_OP_FILE_SEEK       = 0x00000011    #FileRefSeek */
AFC_OP_FILE_TELL       = 0x00000012    #FileRefTell */
AFC_OP_FILE_TELL_RES   = 0x00000013    #FileRefTellResult */
AFC_OP_FILE_CLOSE      = 0x00000014    #FileRefClose */
AFC_OP_FILE_SET_SIZE   = 0x00000015    #FileRefSetFileSize (ftruncate) */
AFC_OP_GET_CON_INFO    = 0x00000016    #GetConnectionInfo */
AFC_OP_SET_CON_OPTIONS = 0x00000017    #SetConnectionOptions */
AFC_OP_RENAME_PATH     = 0x00000018    #RenamePath */
AFC_OP_SET_FS_BS       = 0x00000019    #SetFSBlockSize (0x800000) */
AFC_OP_SET_SOCKET_BS   = 0x0000001A    #SetSocketBlockSize (0x800000) */
AFC_OP_FILE_LOCK       = 0x0000001B    #FileRefLock */
AFC_OP_MAKE_LINK       = 0x0000001C    #MakeLink */
AFC_OP_SET_FILE_TIME   = 0x0000001E    #set st_mtime */

AFC_E_SUCCESS                = 0
AFC_E_UNKNOWN_ERROR          = 1
AFC_E_OP_HEADER_INVALID      = 2
AFC_E_NO_RESOURCES           = 3
AFC_E_READ_ERROR             = 4
AFC_E_WRITE_ERROR            = 5
AFC_E_UNKNOWN_PACKET_TYPE    = 6
AFC_E_INVALID_ARG            = 7
AFC_E_OBJECT_NOT_FOUND       = 8
AFC_E_OBJECT_IS_DIR          = 9
AFC_E_PERM_DENIED            =10
AFC_E_SERVICE_NOT_CONNECTED  =11
AFC_E_OP_TIMEOUT             =12
AFC_E_TOO_MUCH_DATA          =13
AFC_E_END_OF_DATA            =14
AFC_E_OP_NOT_SUPPORTED       =15
AFC_E_OBJECT_EXISTS          =16
AFC_E_OBJECT_BUSY            =17
AFC_E_NO_SPACE_LEFT          =18
AFC_E_OP_WOULD_BLOCK         =19
AFC_E_IO_ERROR               =20
AFC_E_OP_INTERRUPTED         =21
AFC_E_OP_IN_PROGRESS         =22
AFC_E_INTERNAL_ERROR         =23

AFC_E_MUX_ERROR              =30
AFC_E_NO_MEM                 =31
AFC_E_NOT_ENOUGH_DATA        =32
AFC_E_DIR_NOT_EMPTY          =33

AFC_FOPEN_RDONLY   = 0x00000001 #/**< r   O_RDONLY */
AFC_FOPEN_RW       = 0x00000002 #/**< r+  O_RDWR   | O_CREAT */
AFC_FOPEN_WRONLY   = 0x00000003 #/**< w   O_WRONLY | O_CREAT  | O_TRUNC */
AFC_FOPEN_WR       = 0x00000004 #/**< w+  O_RDWR   | O_CREAT  | O_TRUNC */
AFC_FOPEN_APPEND   = 0x00000005 #/**< a   O_WRONLY | O_APPEND | O_CREAT */
AFC_FOPEN_RDAPPEND = 0x00000006 #/**< a+  O_RDWR   | O_APPEND | O_CREAT */

AFC_HARDLINK = 1
AFC_SYMLINK = 2

AFC_LOCK_SH = 1 | 4  #/**< shared lock */
AFC_LOCK_EX = 2 | 4  #/**< exclusive lock */
AFC_LOCK_UN = 8 | 4  #/**< unlock */


AFCMAGIC = "CFA6LPAA"
AFCPacket = Struct("AFCPacket",
                   String("magic", 8,),
                   ULInt64("entire_length"),
                   ULInt64("this_length"),
                   ULInt64("packet_num"),
                   ULInt64("operation")
                   )
#typedef struct {
#    uint64_t filehandle, size;
#} AFCFilePacket;

class AFCClient(object):
    def __init__(self, lockdown=None, serviceName="com.apple.afc", service=None):
        if lockdown:
            self.lockdown = lockdown
        else:
            self.lockdown = LockdownClient()

        if service:
            self.service = service
        else:
            self.service = self.lockdown.startService(serviceName)
        self.packet_num = 0

    def stop_session(self):
        print "Disconecting..."
        self.service.close()
        
    def dispatch_packet(self, operation, data, this_length=0):
        afcpack = Container(magic=AFCMAGIC,
                   entire_length=40 + len(data),
                   this_length=40 + len(data),
                   packet_num=self.packet_num,
                   operation=operation)
        if this_length:
            afcpack.this_length = this_length
        header = AFCPacket.build(afcpack)
        self.packet_num += 1
        self.service.send(header + data)
    
    def receive_data(self):
        res = self.service.recv(40)
        status = AFC_E_SUCCESS
        data = ""
        if res:
            res = AFCPacket.parse(res)
            assert res["entire_length"] >= 40
            length = res["entire_length"] - 40
            data = self.service.recv_exact(length)
            if res.operation == AFC_OP_STATUS:
                if length != 8:
                    print "Status length != 8"
                status = struct.unpack("<Q", data[:8])[0]
            elif res.operation != AFC_OP_DATA:
                pass#print "error ?", res
        return status, data


    def do_operation(self, opcode, data=""):
        try:
            self.dispatch_packet(opcode, data)
            return self.receive_data()
        except:
            self.lockdown = LockdownClient()
            self.service = lockdown.startService(serviceName)
            return  self.do_operation(opcode, data)
    
    def list_to_dict(self, d):
        t = d.split("\x00")
        t = t[:-1]
        
        assert len(t) % 2 == 0
        res = {}
        for i in xrange(len(t)/2):
            res[t[i*2]] = t[i*2 + 1]
        return res
        
    def get_device_infos(self):
        status, infos = self.do_operation(AFC_OP_GET_DEVINFO)
        if status == AFC_E_SUCCESS:
            return self.list_to_dict(infos)

    def read_directory(self, dirname):
        status, data = self.do_operation(AFC_OP_READ_DIR, dirname)
        if status == AFC_E_SUCCESS:
            return filter(lambda x:x!="", data.split("\x00"))
        return []
    
    def make_directory(self, dirname):
        status, data = self.do_operation(AFC_OP_MAKE_DIR, dirname)
        return status
    
    def remove_directory(self, dirname):
        info = self.get_file_info(dirname)
        if not info or info.get("st_ifmt") != "S_IFDIR":
            #print "remove_directory: %s not S_IFDIR" % dirname
            return
        for d in self.read_directory(dirname):
            if d == "." or d == ".." or d == "":
                continue
            info = self.get_file_info(dirname + "/" + d)
            if info.get("st_ifmt") == "S_IFDIR":
                self.remove_directory(dirname + "/" + d)
            else:
                print dirname + "/" + d
                self.file_remove(dirname + "/" + d)
        assert len(self.read_directory(dirname)) == 2 #.. et .
        return self.file_remove(dirname)
        
    def get_file_info(self, filename):
        status, data = self.do_operation(AFC_OP_GET_FILE_INFO, filename)
        if status == AFC_E_SUCCESS:
            return self.list_to_dict(data)


    def make_link(self, target, linkname, type=AFC_SYMLINK):
        status, data = self.do_operation(AFC_OP_MAKE_LINK, struct.pack("<Q", type) + target + "\x00" + linkname + "\x00")
        print "make_link", status
        return status
        
    def file_open(self, filename, mode=AFC_FOPEN_RDONLY):
        status, data = self.do_operation(AFC_OP_FILE_OPEN, struct.pack("<Q", mode) + filename + "\x00")
        if data:
            handle = struct.unpack("<Q", data)[0]
            return handle
    
    def file_close(self, handle):
        status, data = self.do_operation(AFC_OP_FILE_CLOSE, struct.pack("<Q", handle))
        return status
    
    def file_remove(self, filename):
        status, data = self.do_operation(AFC_OP_REMOVE_PATH, filename + "\x00")
        return status 
    
    def file_rename(self, old, new):
        status, data = self.do_operation(AFC_OP_RENAME_PATH, old + "\x00" + new + "\x00")
        return status
    
    def file_read(self, handle, sz):
        MAXIMUM_READ_SIZE = 1 << 16
        data = ""
        while sz > 0:
            if sz > MAXIMUM_READ_SIZE:
                toRead = MAXIMUM_READ_SIZE
            else:
                toRead = sz
	    try:
		self.dispatch_packet(AFC_OP_READ, struct.pack("<QQ", handle, toRead))
		s, d = self.receive_data()
	    except:
		self.lockdown = LockdownClient()
		self.service = self.lockdown.startService("com.apple.afc")
		return  self.file_read(handle, sz)

            if s != AFC_E_SUCCESS:
                break
            sz -= toRead
            data += d
        return data

    def file_write(self, handle, data):
        MAXIMUM_WRITE_SIZE = 1 << 15
        hh = struct.pack("<Q", handle)
        segments = len(data) / MAXIMUM_WRITE_SIZE
	try:
	    for i in xrange(segments):
		self.dispatch_packet(AFC_OP_WRITE,
		                     hh + data[i*MAXIMUM_WRITE_SIZE:(i+1)*MAXIMUM_WRITE_SIZE],
			             this_length=48)
		s, d = self.receive_data()
		if s != AFC_E_SUCCESS:
		    print "file_write error %d" % s
		    break
	    if len(data) % MAXIMUM_WRITE_SIZE:
		self.dispatch_packet(AFC_OP_WRITE,
		                     hh + data[segments*MAXIMUM_WRITE_SIZE:],
			             this_length=48)
		s, d = self.receive_data()
		#print s,d
	except:
	    self.lockdown = LockdownClient()
	    self.service = lockdown.startService(serviceName)
	    self.file_write(handle,data)
        return s
    
    def get_file_contents(self, filename):
	info = self.get_file_info(filename)
	if info:
	    if info['st_ifmt'] == 'S_IFLNK':
		filename =  info['LinkTarget']
	    if info['st_ifmt'] == 'S_IFDIR':
		print "%s is directory..." % filename
		return
	    print "Reading %s" % filename
	    h = self.file_open(filename)
	    if not h:
	        return
	    d = self.file_read(h, int(info["st_size"]))
	    self.file_close(h)
	    return d
	return

    def set_file_contents(self, filename, data):
        h = self.file_open(filename, AFC_FOPEN_WR)
        if not h:
            return
        d = self.file_write(h, data)
        self.file_close(h)

    def dir_walk(self,dir,file_list=[]):
	d = os.path.abspath(dir)
	file_list = []
	for file in [file for file in self.read_directory(d) if not file in [".",".."]]:
	    path = os.path.join(d,file)
	    info =  self.get_file_info(path)
	    if info:
		if info['st_ifmt'] == 'S_IFDIR':
		    file_list += self.dir_walk(path,file_list)
		info['path'] = path
	    	file_list.append(info)
	return file_list

class AFCShell(Cmd):
    def __init__(self, completekey='tab', stdin=None, stdout=None, afc=None):
        Cmd.__init__(self, completekey=completekey, stdin=stdin, stdout=stdout)
        self.lockdown = LockdownClient()
        if afc:
            self.afc = afc
        else:
            self.afc = AFCClient(self.lockdown, "com.apple.afc")
        self.prompt = "(AFC) / "
        self.curdir = "/"
        self.complete_cat = self._complete
        self.complete_ls = self._complete
    
    def do_exit(self, p):
        return True
    
    def do_quit(self, p):
        return True
    
    def do_pwd(self, p):
        print self.curdir
            
    def do_link(self, p):
        z = p.split()
        self.afc.make_link(AFC_SYMLINK, z[0], z[1])
        
    def do_cd(self, p):
        if not p.startswith("/"):
            new = self.curdir + "/" + p
        else:
            new = p
        
        new = os.path.normpath(new).replace("\\","/").replace("//","/")
        
        d = self.afc.read_directory(new)
        if d:
            self.curdir = new
            self.prompt = "(AFC) %s " % new
        else:
            print "%s does not exists" % new
    
   
    def _complete(self, text, line, begidx, endidx):
        filename = text.split("/")[-1]
        dirname = "/".join(text.split("/")[:-1])
        return [dirname + "/" + x for x in self.afc.read_directory(self.curdir + "/" + dirname) if x.startswith(filename)]
    
    def do_ls(self, p):
        d = self.afc.read_directory(self.curdir + "/" + p)
        if d:
            for dd in d:
                print dd
    
    def do_cat(self, p):
        data = self.afc.get_file_contents(self.curdir + "/" + p)
        if data and p.endswith(".plist"):
            pprint(parsePlist(data))
        else:
            print data

    def do_rm(self, p):
        d = self.afc.file_remove(self.curdir + "/" + p)
        
    def do_pull(self, p):
        data = self.afc.get_file_contents(self.curdir + "/" + p)
        if data and p.endswith(".plist"):
            z = parsePlist(data)
            plistlib.writePlist(z, os.path.basename(p))
        else:
            open(os.path.basename(p), "wb").write(data)

    def do_push(self, p):
        t = p.split()
        if len(t) != 2:
            return
        data = open(t[1], "rb").read()
        self.afc.set_file_contents(self.curdir + "/" + t[0], data)
            
    def do_head(self, p):
        print self.afc.get_file_contents(self.curdir + "/" + p)[:32]

    def do_hexdump(self, p):
        t = p.split(" ")
        l = 0
        if len(t) < 1:
            return
        if len(t) == 2:
            l = int(t[1])
        z = self.afc.get_file_contents(self.curdir + "/" + t[0])
        if not z:
            return
        if l:
            z = z[:l]
        hexdump(z)
    
    def do_mkdir(self, p):
        print self.afc.make_directory(p)

    def do_infos(self, p):
        print self.afc.get_device_infos()
        
if __name__ == "__main__":
    #lockdown = LockdownClient()
    #afc = AFCClient(lockdown)
    #afc.read_directory("/DCIM/100APPLE/")
    #d = afc.get_file_contents("/DCIM/100APPLE/IMG_0001.JPG")
    #open("test.jpg","wb").write(d)
    #afc.set_file_contents("/test.txt", "hello world")
    #print afc.get_file_info("/etc/fstab")
    AFCShell().cmdloop("Hello")
