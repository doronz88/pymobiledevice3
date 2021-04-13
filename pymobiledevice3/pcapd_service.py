#!/usr/bin/env python3

import logging
import struct
import time
import sys

import click

from pymobiledevice3.lockdown import LockdownClient

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
LINKTYPE_RAW = 101


class PcapdService:
    SERVICE_NAME = 'com.apple.pcapd'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.SERVICE_NAME)

    def watch(self, out=None):
        if out:
            out.write(struct.pack("<LHHLLLL", 0xa1b2c3d4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))

        while True:
            d = self.service.recv_plist()
            if not d:
                break
            hdrsize, xxx, packet_size = struct.unpack(">LBL", d[:9])
            flags1, flags2, offset_to_ip_data, zero = struct.unpack(">LLLL", d[9:0x19])

            assert hdrsize >= 0x19
            interfacetype = d[0x19:hdrsize].strip(b"\x00")
            packet = d[hdrsize:]
            logging.info(packet)
            assert packet_size == len(packet)

            if offset_to_ip_data == 0:
                # add fake ethernet header for pdp packets
                packet = b"\xBE\xEF" * 6 + b"\x08\x00" + packet

            if out:
                t = time.time()
                # TODO: check milliseconds conversion
                pkthdr = struct.pack('<LLLL', int(t), int(t * 1000000 % 1000000), len(packet), len(packet))
                data = pkthdr + packet
                out.write(data)
