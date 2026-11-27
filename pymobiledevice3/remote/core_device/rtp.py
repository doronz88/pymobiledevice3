"""
The RTP and RTCP handling the screen servers (``serve-web`` and ``serve-vnc``) share.

The device sends its video and audio as RTP over UDP, and reaps a session which gets no RTCP
receiver report for some seconds. These are the pure parts of that: reading an RTP packet and
building the RTCP packets sent back.
"""

import struct
from typing import Optional


def rtp_payload(packet: bytes) -> Optional[bytes]:
    """The payload of an RTP packet, past its CSRC list and header extension.

    ``None`` for what is not an RTP data packet: one shorter than the fixed header, or an RTCP
    packet arriving on the same socket. A packet cut short inside its header has an empty payload.
    """
    if len(packet) < 12:
        return None
    if 64 <= packet[1] & 0x7F <= 95:  # RTCP
        return None
    header_len = 12 + (packet[0] & 0x0F) * 4
    if packet[0] & 0x10:  # extension
        ext_len = int.from_bytes(packet[header_len + 2 : header_len + 4], "big")
        header_len += 4 + ext_len * 4
    return packet[header_len:]


def extend_sequence(highest: int, seq: int) -> int:
    """The extended highest sequence number (RFC 3550, cycles << 16 | seq) after receiving ``seq``.

    ``highest`` is the value so far, 0 before the first packet. A late packet does not move it back.
    """
    cycles = (highest >> 16) & 0xFFFF
    if seq < highest & 0xFFFF and (highest & 0xFFFF) - seq > 0x8000:
        cycles = (cycles + 1) & 0xFFFF  # the sequence number wrapped
    extended = (cycles << 16) | seq
    if highest == 0 or ((extended - highest) & 0xFFFFFFFF) < 0x80000000:
        return extended
    return highest


def rtcp_receiver_report(local_ssrc: int, remote_ssrc: int, highest_seq: int) -> bytes:
    """An RTCP Receiver Report (RFC 3550 §6.4.2) with one report block, 32 bytes.

    It reports no loss and no jitter: it is the keepalive of a session, whose ``RTCPTimeoutInterval``
    the device enforces.
    """
    return struct.pack(
        "!BBHII BBBB IIII",
        0x81,  # V=2, P=0, RC=1
        0xC9,  # PT=201 (RR)
        7,  # length: 8 words
        local_ssrc & 0xFFFFFFFF,
        remote_ssrc & 0xFFFFFFFF,
        0,  # fraction lost
        0,
        0,
        0,  # cumulative loss (3 bytes)
        highest_seq & 0xFFFFFFFF,
        0,  # interarrival jitter
        0,  # last SR (none was received)
        0,  # delay since last SR
    )


def rtcp_sdes(ssrc: int) -> bytes:
    """A minimal RTCP SDES chunk (RFC 3550 §6.5) with an empty CNAME, 12 bytes.

    Byte-identical to Xcode's mirror (``81 ca 0002 <ssrc> 01 00 00 00``), which always sends its
    receiver reports compound with one.
    """
    return struct.pack(
        "!BBHI BBBB",
        0x81,  # V=2, P=0, SC=1
        0xCA,  # PT=202 (SDES)
        2,  # length: 3 words
        ssrc & 0xFFFFFFFF,
        0x01,  # item type 1 = CNAME
        0x00,  # of length 0
        0x00,  # end of items
        0x00,  # padding to a 32-bit boundary
    )


def rtcp_pli(local_ssrc: int, remote_ssrc: int) -> bytes:
    """An RTCP Picture Loss Indication (RFC 4585 §6.3.1), 12 bytes: asks the encoder for a fresh IDR."""
    return struct.pack(
        "!BBHII",
        0x81,  # V=2, P=0, FMT=1
        0xCE,  # PT=206 (PSFB)
        2,  # length: 3 words
        local_ssrc & 0xFFFFFFFF,
        remote_ssrc & 0xFFFFFFFF,
    )
