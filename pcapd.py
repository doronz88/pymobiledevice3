import struct
import time
import sys
from lockdown import LockdownClient

"""
struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;
typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;
"""
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW      = 101

class PcapOut(object):
    def __init__(self, name):
        self.f = open("test.pcap","wb")
        self.f.write(struct.pack("<LHHLLLL", 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
    
    def __del__(self):
        self.f.close()
        
    def writePacket(self, packet):
        t = time.time()
        #TODO check milisecond conversion
        pkthdr = struct.pack("<LLLL", int(t), int(t*1000000 % 1000000), len(packet), len(packet))
        data = pkthdr + packet
        l = self.f.write(data)
        self.f.flush()
        return True

class Win32Pipe(object):
    def __init__(self, pipename=r'\\.\pipe\wireshark'):
        self.pipe = win32pipe.CreateNamedPipe(pipename,
                                           win32pipe.PIPE_ACCESS_OUTBOUND,
                                           win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
                                           1, 65536, 65536,
                                           300,
                                           None)
        print "Connect wireshark to %s" % pipename
        win32pipe.ConnectNamedPipe(self.pipe, None)
        win32file.WriteFile(self.pipe, struct.pack("<LHHLLLL", 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))

    def writePacket(self, packet):
        t = time.time()
        pkthdr = struct.pack("<LLLL", int(t), int(t*1000000 % 1000000), len(packet), len(packet))
        errCode, nBytesWritten = win32file.WriteFile(self.pipe, pkthdr + packet)
        return errCode == 0

if __name__ == "__main__":
    if sys.platform == "win32":
        import win32pipe, win32file
        output = Win32Pipe()
    elif sys.platform == "darwin":
        print "Why not use rvictl ?"
	output = PcapOut("test2.pcap")

    else:
        output = PcapOut()

    lockdown = LockdownClient()
    
    pcap = lockdown.startService("com.apple.pcapd")
    
    while True:
        d = pcap.recvPlist()
        if not d:
            break
        data = d.data
        hdrsize, xxx, packet_size = struct.unpack(">LBL", data[:9])
        flags1, flags2, offset_to_ip_data, zero = struct.unpack(">LLLL", data[9:0x19])
        assert hdrsize >= 0x19
        interfacetype= data[0x19:hdrsize].strip("\x00")
        t = time.time()
        print interfacetype, packet_size, t
        packet = data[hdrsize:]
        assert packet_size == len(packet)
        if offset_to_ip_data == 0:
            #add fake ethernet header for pdp packets
            packet = "\xBE\xEF" * 6 + "\x08\x00" + packet
        if not output.writePacket(packet):
            break
        
