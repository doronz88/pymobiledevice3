import os
import sys
from util import sizeof_fmt, hexdump
from progressbar import ProgressBar
from crypto.aes import AESdecryptCBC, AESencryptCBC

class FileBlockDevice(object):
    def __init__(self, filename, offset=0, write=False):
        flag = os.O_RDONLY if not write else os.O_RDWR
        if sys.platform == 'win32':
            flag = flag | os.O_BINARY
        self.filename = filename
        self.fd = os.open(filename, flag)
        self.offset = offset
        self.writeFlag = write
        self.size = os.path.getsize(filename)
        self.setBlockSize(8192)
        
    def setBlockSize(self, bs):
        self.blockSize = bs
        self.nBlocks = self.size / bs
        
    def readBlock(self, blockNum):
        os.lseek(self.fd, self.offset + self.blockSize * blockNum, os.SEEK_SET)
        return os.read(self.fd, self.blockSize)

    def write(self, offset, data):
        if self.writeFlag: #fail silently for testing 
            os.lseek(self.fd, self.offset + offset, os.SEEK_SET)
            return os.write(self.fd, data)

    def writeBlock(self, lba, block):
        return self.write(lba*self.blockSize, block)

class FTLBlockDevice(object):
    def __init__(self, nand, first_lba, last_lba, defaultKey=None):
        self.nand = nand
        self.pageSize = nand.pageSize
        self.blockSize = 0 #not used
        self.key = defaultKey
        self.lbaoffset = first_lba
        self.last_lba = last_lba
        self.setBlockSize(self.pageSize)
        
    def setBlockSize(self, bs):
        self.blockSize = bs
        self.lbasPerPage = self.pageSize / bs
        self.lbaToLpnFactor = bs / (self.pageSize+0.0)
        self.pagesPerLBA = bs / self.pageSize
        if bs > self.pageSize:
            pass#raise Exception("FTLBlockDevice lba-size > pageSize not handled")
        
    def readBlock(self, blockNum):
        #if (self.lbaoffset + blockNum / self.lbasPerPage) > self.last_lba:
        #    print "readBlock past last lba", blockNum
        #    print "readBlock past last lba", blockNum
        #    return "\x00" * self.blockSize
        lpn = int(self.lbaoffset + blockNum * self.lbaToLpnFactor)
        d = self.nand.readLPN(lpn, self.key)
        for i in range(1, self.pagesPerLBA):
            d += self.nand.readLPN(lpn + i, self.key)
        if self.lbasPerPage:
            zz = blockNum % self.lbasPerPage
            return d[zz*self.blockSize:(zz+1)*self.blockSize]
        return d

    def write(self, offset, data):
        raise Exception("FTLBlockDevice write method not implemented")
    
    def writeBlock(self, lba, block):
        raise Exception("FTLBlockDevice writeBlock method not implemented")

    def dumpToFile(self, outputfilename):
        hs = sizeof_fmt((self.last_lba - self.lbaoffset) * self.pageSize)
        print("Dumping partition to %s (%s)" % (outputfilename, hs))
        flags = os.O_CREAT | os.O_RDWR
        if sys.platform == "win32":
            flags |= os.O_BINARY
        fd=os.open(outputfilename, flags)
        
        pbar = ProgressBar(self.last_lba - self.lbaoffset - 1)
        pbar.start()
        for i in range(self.lbaoffset, self.last_lba):
            pbar.update(i-self.lbaoffset)
            d = self.nand.readLPN(i, self.key)
            if i == self.lbaoffset and d[0x400:0x402] != "HX":
                print("FAIL? Not HFS partition or wrong key")
            os.write(fd, d)
        pbar.finish()
        os.close(fd)

class IMG3BlockDevice(object):
    def __init__(self, filename, key, iv, write=False):
        flag = os.O_RDONLY if not write else os.O_RDWR
        if sys.platform == 'win32':
            flag = flag | os.O_BINARY
        self.filename = filename
        self.fd = os.open(filename, flag)
        self.writeFlag = write
        d = os.read(self.fd, 8192)
        if d[:4] != "3gmI":
            raise Exception("IMG3BlockDevice bad magic %s" % d[:4])
        if d[0x34:0x38] != "ATAD":
            raise Exception("Fu")
        self.encrypted = True
        self.key = key
        self.iv0 = iv
        self.offset = 0x40
        self.size = os.path.getsize(filename)
        self.setBlockSize(8192)
        
    def setBlockSize(self, bs):
        self.blockSize = bs
        self.nBlocks = self.size / bs
        self.ivs = {0: self.iv0}
    
    def getIVforBlock(self, blockNum):
        #read last 16 bytes of previous block to get IV
        if blockNum not in self.ivs:
            os.lseek(self.fd, self.offset + self.blockSize *
                     blockNum - 16, os.SEEK_SET)
            self.ivs[blockNum] = os.read(self.fd, 16)
        return self.ivs[blockNum]

    def readBlock(self, blockNum):
        os.lseek(self.fd, self.offset + self.blockSize * blockNum, os.SEEK_SET)
        data = os.read(self.fd, self.blockSize)
        if self.encrypted:
            data = AESdecryptCBC(data, self.key, self.getIVforBlock(blockNum))
        return data

    def _write(self, offset, data):
        if self.writeFlag: #fail silently for testing 
            os.lseek(self.fd, self.offset + offset, os.SEEK_SET)
            return os.write(self.fd, data)

    def writeBlock(self, lba, data):
        if self.encrypted:
            data = AESencryptCBC(data, self.key, self.getIVforBlock(lba))
        return self._write(lba*self.blockSize, data)
