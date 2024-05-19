#!/usr/bin/env python3

import enum
import socket
from typing import Generator, Optional

import pcapng.blocks as blocks
from construct import Byte, Bytes, Container, CString, Int16ub, Int32ub, Int32ul, Padded, Seek, Struct, this
from pcapng import FileWriter

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

INTERFACE_NAMES = enum.Enum('InterfaceNames', names={
    'other': 1,
    'regular1822': 2,
    'hdh1822': 3,
    'ddnX25': 4,
    'rfc877x25': 5,
    'ethernetCsmacd': 6,
    'iso88023Csmacd': 7,
    'iso88024TokenBus': 8,
    'iso88025TokenRing': 9,
    'iso88026Man': 10,
    'starLan': 11,
    'proteon10Mbit': 12,
    'proteon80Mbit': 13,
    'hyperchannel': 14,
    'fddi': 15,
    'lapb': 16,
    'sdlc': 17,
    'ds1': 18,
    'e1': 19,
    'basicISDN': 20,
    'primaryISDN': 21,
    'propPointToPointSerial': 22,
    'ppp': 23,
    'softwareLoopback': 24,
    'eon': 25,
    'ethernet3Mbit': 26,
    'nsip': 27,
    'slip': 28,
    'ultra': 29,
    'ds3': 30,
    'sip': 31,
    'frameRelay': 32,
    'rs232': 33,
    'para': 34,
    'arcnet': 35,
    'arcnetPlus': 36,
    'atm': 37,
    'miox25': 38,
    'sonet': 39,
    'x25ple': 40,
    'iso88022llc': 41,
    'localTalk': 42,
    'smdsDxi': 43,
    'frameRelayService': 44,
    'v35': 45,
    'hssi': 46,
    'hippi': 47,
    'modem': 48,
    'aal5': 49,
    'sonetPath': 50,
    'sonetVT': 51,
    'smdsIcip': 52,
    'propVirtual': 53,
    'propMultiplexor': 54,
    'ieee80212': 55,
    'fibreChannel': 56,
    'hippiInterface': 57,
    'frameRelayInterconnect': 58,
    'aflane8023': 59,
    'aflane8025': 60,
    'cctEmul': 61,
    'fastEther': 62,
    'isdn': 63,
    'v11': 64,
    'v36': 65,
    'g703at64k': 66,
    'g703at2mb': 67,
    'qllc': 68,
    'fastEtherFX': 69,
    'channel': 70,
    'ieee80211': 71,
    'ibm370parChan': 72,
    'escon': 73,
    'dlsw': 74,
    'isdns': 75,
    'isdnu': 76,
    'lapd': 77,
    'ipSwitch': 78,
    'rsrb': 79,
    'atmLogical': 80,
    'ds0': 81,
    'ds0Bundle': 82,
    'bsc': 83,
    'async': 84,
    'cnr': 85,
    'iso88025Dtr': 86,
    'eplrs': 87,
    'arap': 88,
    'propCnls': 89,
    'hostPad': 90,
    'termPad': 91,
    'frameRelayMPI': 92,
    'x213': 93,
    'adsl': 94,
    'radsl': 95,
    'sdsl': 96,
    'vdsl': 97,
    'iso88025CRFPInt': 98,
    'myrinet': 99,
    'voiceEM': 100,
    'voiceFXO': 101,
    'voiceFXS': 102,
    'voiceEncap': 103,
    'voiceOverIp': 104,
    'atmDxi': 105,
    'atmFuni': 106,
    'atmIma': 107,
    'pppMultilinkBundle': 108,
    'ipOverCdlc': 109,
    'ipOverClaw': 110,
    'stackToStack': 111,
    'virtualIpAddress': 112,
    'mpc': 113,
    'ipOverAtm': 114,
    'iso88025Fiber': 115,
    'tdlc': 116,
    'gigabitEthernet': 117,
    'hdlc': 118,
    'lapf': 119,
    'v37': 120,
    'x25mlp': 121,
    'x25huntGroup': 122,
    'transpHdlc': 123,
    'interleave': 124,
    'fast': 125,
    'ip': 126,
    'docsCableMaclayer': 127,
    'docsCableDownstream': 128,
    'docsCableUpstream': 129,
    'a12MppSwitch': 130,
    'tunnel': 131,
    'coffee': 132,
    'ces': 133,
    'atmSubInterface': 134,
    'l2vlan': 135,
    'l3ipvlan': 136,
    'l3ipxvlan': 137,
    'digitalPowerline': 138,
    'mediaMailOverIp': 139,
    'dtm': 140,
    'dcn': 141,
    'ipForward': 142,
    'msdsl': 143,
    'ieee1394': 144,
    'if-gsn': 145,
    'dvbRccMacLayer': 146,
    'dvbRccDownstream': 147,
    'dvbRccUpstream': 148,
    'atmVirtual': 149,
    'mplsTunnel': 150,
    'srp': 151,
    'voiceOverAtm': 152,
    'voiceOverFrameRelay': 153,
    'idsl': 154,
    'compositeLink': 155,
    'ss7SigLink': 156,
    'propWirelessP2P': 157,
    'frForward': 158,
    'rfc1483': 159,
    'usb': 160,
    'ieee8023adLag': 161,
    'bgppolicyaccounting': 162,
    'frf16MfrBundle': 163,
    'h323Gatekeeper': 164,
    'h323Proxy': 165,
    'mpls': 166,
    'mfSigLink': 167,
    'hdsl2': 168,
    'shdsl': 169,
    'ds1FDL': 170,
    'pos': 171,
    'dvbAsiIn': 172,
    'dvbAsiOut': 173,
    'plc': 174,
    'nfas': 175,
    'tr008': 176,
    'gr303RDT': 177,
    'gr303IDT': 178,
    'isup': 179,
    'propDocsWirelessMaclayer': 180,
    'propDocsWirelessDownstream': 181,
    'propDocsWirelessUpstream': 182,
    'hiperlan2': 183,
    'propBWAp2Mp': 184,
    'sonetOverheadChannel': 185,
    'digitalWrapperOverheadChannel': 186,
    'aal2': 187,
    'radioMAC': 188,
    'atmRadio': 189,
    'imt': 190,
    'mvl': 191,
    'reachDSL': 192,
    'frDlciEndPt': 193,
    'atmVciEndPt': 194,
    'opticalChannel': 195,
    'opticalTransport': 196,
    'propAtm': 197,
    'voiceOverCable': 198,
    'infiniband': 199,
    'teLink': 200,
    'q2931': 201,
    'virtualTg': 202,
    'sipTg': 203,
    'sipSig': 204,
    'docsCableUpstreamChannel': 205,
    'econet': 206,
    'pon155': 207,
    'pon622': 208,
    'bridge': 209,
    'linegroup': 210,
    'voiceEMFGD': 211,
    'voiceFGDEANA': 212,
    'voiceDID': 213,
    'mpegTransport': 214,
    'sixToFour': 215,
    'gtp': 216,
    'pdnEtherLoop1': 217,
    'pdnEtherLoop2': 218,
    'opticalChannelGroup': 219,
    'homepna': 220,
    'gfp': 221,
    'ciscoISLvlan': 222,
    'actelisMetaLOOP': 223,
    'fcipLink': 224,
    'rpr': 225,
    'qam': 226,
    'lmp': 227,
    'cblVectaStar': 228,
    'docsCableMCmtsDownstream': 229,
    'adsl2': 230,
    'macSecControlledIF': 231,
    'macSecUncontrolledIF': 232,
    'aviciOpticalEther': 233,
    'atmbond': 234,
    'voiceFGDOS': 235,
    'mocaVersion1': 236,
    'ieee80216WMAN': 237,
    'adsl2plus': 238,
    'dvbRcsMacLayer': 239,
    'dvbTdm': 240,
    'dvbRcsTdma': 241,
    'x86Laps': 242,
    'wwanPP': 243,
    'wwanPP2': 244,
    'voiceEBS': 245,
    'ifPwType': 246,
    'ilan': 247,
    'pip': 248,
    'aluELP': 249,
    'gpon': 250,
    'vdsl2': 251,
    'capwapDot11Profile': 252,
    'capwapDot11Bss': 253,
    'capwapWtpVirtualRadio': 254,
    'bits': 255,
    'docsCableUpstreamRfPort': 256,
    'cableDownstreamRfPort': 257,
    'vmwareVirtualNic': 258,
    'ieee802154': 259,
})

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

ETHERNET_HEADER = b'\xBE\xEF' * 6 + b'\x08\x00'

device_packet_struct = Struct(
    'header_length' / Int32ub,
    'header_version' / Byte,
    'packet_length' / Int32ub,
    'interface_type' / Byte,
    'unit' / Int16ub,
    'io' / Byte,
    'protocol_family' / Int32ub,
    'frame_pre_length' / Int32ub,
    'frame_post_length' / Int32ub,
    'interface_name' / Padded(16, CString('utf8')),
    'pid' / Int32ul,
    'comm' / Padded(17, CString('utf8')),
    'svc' / Int32ub,
    'epid' / Int32ul,
    'ecomm' / Padded(17, CString('utf8')),
    'seconds' / Int32ub,
    'microseconds' / Int32ub,
    Seek(this.header_length),
    'data' / Bytes(this.packet_length),
)


class PcapdService(LockdownService):
    """
    Starting iOS 5, apple added a remote virtual interface (RVI) facility that allows mirroring networks traffic from
    an iOS device. On macOS, the virtual interface can be enabled with the rvictl command. This script allows to use
    this service on other systems.
    """
    RSD_SERVICE_NAME = 'com.apple.pcapd.shim.remote'
    SERVICE_NAME = 'com.apple.pcapd'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def watch(self, packets_count: int = -1, process: Optional[str] = None, interface_name: Optional[str] = None) \
            -> Generator[Container, None, None]:
        packet_index = 0
        while packet_index != packets_count:
            d = self.service.recv_plist()
            if not d:
                break

            packet = device_packet_struct.parse(d)

            if process is not None:
                if process != str(packet.pid) and process != packet.comm:
                    continue

            if interface_name is not None:
                if interface_name != packet.interface_name:
                    continue

            packet.interface_type = INTERFACE_NAMES(packet.interface_type)
            packet.protocol_family = socket.AddressFamily(packet.protocol_family)

            if not packet.frame_pre_length:
                # Add fake ethernet header for pdp packets.
                packet.data = ETHERNET_HEADER + packet.data
            elif packet.interface_name == 'pdp_ip':
                packet.data = ETHERNET_HEADER + packet.data[4:]

            yield packet

            packet_index += 1

    def write_to_pcap(self, out, packet_generator) -> None:
        shb = blocks.SectionHeader(
            options={
                'shb_hardware': 'artificial',
                'shb_os': 'iOS',
                'shb_userappl': 'pymobiledevice3',
            }
        )
        shb.new_member(
            blocks.InterfaceDescription,
            link_type=1,
            options={
                'if_description': 'iOS Packet Capture',
                'if_os': f'iOS {self.lockdown.product_version}'
            },
        )
        writer = FileWriter(out, shb)

        for packet in packet_generator:
            enhanced_packet = shb.new_member(blocks.EnhancedPacket, options={
                'opt_comment': f'PID: {packet.pid}, ProcName: {packet.comm}, EPID: {packet.epid}, '
                               f'EProcName: {packet.ecomm}, SVC: {packet.svc}'
            })

            enhanced_packet.packet_data = packet.data
            writer.write_block(enhanced_packet)
