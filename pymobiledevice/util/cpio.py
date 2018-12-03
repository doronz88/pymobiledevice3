#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# $Id$
#
# Copyright (c) 2012-2014 "dark[-at-]gotohack.org"
#
# This file is part of pymobiledevice
#
# pymobiledevice is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#

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
        if fileobj:
            self.ifile = fileobj
        else:
            self.ifile = open(cpiofile,mode)

    def is_cpiofile(self,cpiofile=None,fileobj=None):
        if fileobj:
            magic = int(fileobj.read(6),8)    
        else:
            magic = int(open(cpiofile,'r').read(6),8)

        if magic in [NEW_MAGIC, CRC_MAGIC, OLD_MAGIC]:
            return True

    def read_old_ascii_cpio_record(self):
        f = {}
        try:
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
            f["name"] = self.ifile.read(f.get("namesize"))[:-1] # Removing \x00
            f["data"] = self.ifile.read(f.get("filesize"))
        except:
            print('ERROR: cpio record trunked (incomplete archive)')
            return None
        return f

    def extract_files(self,files=None,outpath="."):
        print("Extracting files from CPIO archive" )
        while 1:
            try:
                hdr = int(self.ifile.read(6),8)
            except:
                print('ERROR: cpio record trunked (incomplete archive)')
                break

            if hdr != OLD_MAGIC:
                raise NotImplementedError #FIXME Should implement new & Binary CPIO record
            
            f = self.read_old_ascii_cpio_record()            
            if f and f.get("name") == TRAILER:
                break
            
            if files:
                if not f.get("name") in files:
                    print("Skipped %s" % f.get("name"))
                    continue
            
            fullOutPath = os.path.join(outpath,f.get("name").strip("../")) 
            print("x %s" % fullOutPath)

            if (f.get("mode") & IFMT == ISFIFO):#FIFO
                if not os.path.isdir(os.path.dirname(fullOutPath)):
                    os.makedirs(os.path.dirname(fullOutPath),0o0755)
                os.mkfifo(fullOutPath, f.get("mode") & MODEMASK)
                os.chmod(fullOutPath, f.get("mode") & MODEMASK)

            if (f.get("mode") & IFMT == ISDIR): #Directory
                if not os.path.isdir(fullOutPath):
                    os.makedirs(fullOutPath, f.get("mode") & MODEMASK)
   
            if (f.get("mode") & IFMT == ISBLK): #Block special file
                raise NotImplementedError
            
            if (f.get("mode") & IFMT == ISCHR): #Character special file
                raise NotImplementedError
            
            if (f.get("mode") & IFMT == ISLNK): #Reserved for symbolic links
                raise NotImplementedError

            if (f.get("mode") & IFMT == ISOCK): #Reserved for sockets
                raise NotImplementedError
            
            if (f.get("mode") & IFMT == ISCTG) or (f.get("mode") & IFMT == ISREG): #Contiguous or Regular file
                if not os.path.isdir(os.path.dirname(fullOutPath)):
                    os.makedirs(os.path.dirname(fullOutPath),0o0755)
                fd = open(fullOutPath,"wb")
                fd.write(f.get("data"))

            os.chmod(fullOutPath, f.get("mode") & MODEMASK)
        
            
if __name__ == "__main__":
    a = CpioArchive(sys.argv[1],mode="rb",)
    a.extract_files()

