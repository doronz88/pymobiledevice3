from pprint import pprint
import sys
from struct import unpack, pack
import os

#Values for mode, OR'd together:

ISDIR  = 0o040000	#Directory
ISFIFO = 0o010000	#FIFO
ISREG  = 0o0100000  #Regular file
ISBLK  = 0o060000	#Block special file
ISCHR  = 0o020000   #Character special file
ISCTG  = 0o0110000  #Reserved for contiguous files
ISLNK  = 0o0120000	#Reserved for symbolic links
ISOCK  = 0o0140000  #Reserved for sockets
IFMT   = 0o0170000	#type of file

MODEMASK =  0o0000777
TRAILER = "TRAILER!!!"

NEW_MAGIC = 0o070701 #New ASCII magic
CRC_MAGIC = 0o070702 #New CRC magic
OLD_MAGIC = 0o070707 #Old ASCII magic

def version():
    return '0.1'


class CpioArchive(object):

    def __init__(self, cpiofile=None, fileobj=None, mode="rb"):
        #assert(self.is_cpiofile(cpiofile=cpiofile,fileobj=fileobj))
        if fileobj:
            self.ifile = fileobj
        else:
            self.ifile = open(cpiofile,mode)

    def is_cpiofile(self,cpiofile=None,fileobj=None):
        print cpiofile,fileobj
        if fileobj:
            magic = int(fileobj.read(6),8)    
        else:
            magic = int(open(cpiofile,'r').read(6),8)
        print oct(magic)

        if magic in [NEW_MAGIC, CRC_MAGIC, OLD_MAGIC]:
            return True

    def read_old_ascii_cpio_record(self):
        f = {}
        f["dev"]	   = int(self.ifile.read(6),8)  #device where file resides
        f["ino"]	   = int(self.ifile.read(6),8)  #I-number of file
        f["mode"]	   = int(self.ifile.read(6),8)  #Ifile mode
        f["uid"]	   = int(self.ifile.read(6),8)  #owner user ID
        f["gid"]	   = int(self.ifile.read(6),8)  #owner group ID
        f["nlink"]	   = int(self.ifile.read(6),8)  #number of links to file
        f["rdev"]	   = int(self.ifile.read(6),8)  #device major/minor for special file
        f["mtime"]	   = int(self.ifile.read(11),8) #modify time of file
        f["namesize"]  = int(self.ifile.read(6),8)  #length of file name
        f["filesize"]  = int(self.ifile.read(11),8) #length of file to follow
        f["name"] = self.ifile.read(f["namesize"])[:-1] # Removing \x00
        f["data"] = self.ifile.read(f["filesize"])
        return f

    def extract_files(self,files=None,outpath="."):
        print "[+] Extracting files from CPIO archive" 
        while 1: 
            hdr = int(self.ifile.read(6),8)
            if hdr != OLD_MAGIC: #OLD CPIO MAGIC
                raise NotImplementedError #FIXME Should implement new & Binary CPIO record
            
            f = self.read_old_ascii_cpio_record()
            if f["name"] == TRAILER:
                break
            
            if files:
                if not f["name"] in files:
                    print "[!] Skipped",f["name"]
                    continue

            fullOutPath = os.path.join(outpath,f["name"].strip("../")) 
            #print "[|] CPIO Creating:",fullOutPath
   
            if (f["mode"] & IFMT == ISFIFO):#FIFO
                if not os.path.isdir(os.path.dirname(fullOutPath)):
                    os.makedirs(os.path.dirname(fullOutPath),0o0755)
                os.mkfifo(fullOutPath, f["mode"] & MODEMASK)
                os.chmod(fullOutPath, f["mode"] & MODEMASK)

            if (f["mode"] & IFMT == ISDIR): #Directory
                if not os.path.isdir(fullOutPath):
                    os.makedirs(fullOutPath, f["mode"] & MODEMASK)
   
            if (f["mode"] & IFMT == ISBLK): #Block special file
                #if not os.path.isdir(os.path.dirname(fullOutPath)):
                #    os.makedirs(os.path.dirname(fullOutPath),0o0755)
                #os.mknod(fullOutPath, mode=f["mode"] & FILEMODE, device)
                raise NotImplementedError
            
            if (f["mode"] & IFMT == ISCHR): #Character special file
                #if not os.path.isdir(os.path.dirname(fullOutPath)):
                #    os.makedirs(os.path.dirname(fullOutPath),0o0755)
                raise NotImplementedError
            
            if (f["mode"] & IFMT == ISLNK): #Reserved for symbolic links
                #if not os.path.islink((fullOutPath)):
                #    if not os.path.islink(os.path.dirname(fullOutPath)):
                #        os.makedirs(os.path.dirname(fullOutPath),0o0755)
                #    print "L",os.path.join(outpath,f["data"].strip("../")),fullOutPath
                #    #os.symlink(os.path.join(outpath,f["data"].strip("../")),fullOutPath)
                raise NotImplementedError

            if (f["mode"] & IFMT == ISOCK): #Reserved for sockets
                #if not os.path.isdir(os.path.dirname(fullOutPath)):
                #    os.makedirs(os.path.dirname(fullOutPath),0o0755)
                #os.mknod(fullOutPath, mode=f["mode"] & FILEMODE, device)
                raise NotImplementedError
            
            if (f["mode"] & IFMT == ISCTG) or (f["mode"] & IFMT == ISREG): #Contiguous or Regular file
                if not os.path.isdir(os.path.dirname(fullOutPath)):
                    os.makedirs(os.path.dirname(fullOutPath),0o0755)
                fd = open(fullOutPath,"wb")
                fd.write(f["data"])

            os.chmod(fullOutPath, f["mode"] & MODEMASK)
            #os.chown(fullOutPath, f["uid"], f["gid"])
        
            
if __name__ == "__main__":
    a = CpioArchive(sys.argv[1],mode="rb",)
    a.extract_files()

