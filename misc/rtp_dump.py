#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Convert an RTP capture produced by
``pymobiledevice3 developer core-device display start-video-stream``
into an Annex-B HEVC (H.265) bitstream playable by ffmpeg / ffplay / VLC.

Input format (length-prefixed RTP datagrams written by the CLI):
    [4-byte big-endian length] [RTP/RTCP packet bytes] ...

The device sends RTP/HEVC per RFC 7798 — Aggregation Packets (nal_type=48),
Fragmentation Units (nal_type=49), and single NAL units (nal_type 0-47).
Each NAL is unwrapped and prefixed with the Annex-B start code ``00 00 00 01``.

Usage:
    rtp_dump.py screen-test.rtp screen-test.h265
    ffplay -framerate 60 screen-test.h265
"""

import argparse
import pathlib

START_CODE = b"\x00\x00\x00\x01"
H265_NAL_AP = 48  # Aggregation Packet
H265_NAL_FU = 49  # Fragmentation Unit


def _h265_nal_type(payload: bytes) -> int:
    """Return the NAL unit type from the first byte of an HEVC payload."""
    return (payload[0] >> 1) & 0x3F


def _emit_nal(nal: bytes, out: list[bytes]) -> None:
    out.append(START_CODE + nal)


def _process_rtp_payload(payload: bytes, fu_buffer: bytearray, out: list[bytes]) -> None:
    if len(payload) < 2:
        return
    nal_type = _h265_nal_type(payload)
    if nal_type == H265_NAL_AP:
        # Aggregation Packet: skip 2-byte AP NAL header, then iterate
        # [2-byte size][NAL unit][2-byte size][NAL unit]...
        i = 2
        while i + 2 <= len(payload):
            size = int.from_bytes(payload[i : i + 2], "big")
            i += 2
            _emit_nal(payload[i : i + size], out)
            i += size
    elif nal_type == H265_NAL_FU:
        # Fragmentation Unit: 2-byte FU NAL header + 1-byte FU header + data
        # Reconstruct the original NAL header from the FU's PayloadHdr and FU type field.
        fu_header = payload[2]
        start = fu_header & 0x80
        end = fu_header & 0x40
        original_nal_type = fu_header & 0x3F
        if start:
            # Build the original NAL header from the layered values in the FU PayloadHdr
            orig_byte0 = (payload[0] & 0x81) | (original_nal_type << 1)
            orig_byte1 = payload[1]
            fu_buffer[:] = bytes([orig_byte0, orig_byte1]) + payload[3:]
        else:
            fu_buffer.extend(payload[3:])
        if end and fu_buffer:
            _emit_nal(bytes(fu_buffer), out)
            fu_buffer.clear()
    else:
        # Single NAL unit
        _emit_nal(payload, out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=pathlib.Path, help="Capture from start-video-stream")
    parser.add_argument("output", type=pathlib.Path, help="Output .h265 (Annex-B bitstream)")
    args = parser.parse_args()

    data = args.input.read_bytes()
    i = 0
    nal_chunks: list[bytes] = []
    fu_buffer = bytearray()
    rtp_count = 0
    rtcp_count = 0

    while i < len(data):
        if len(data) - i < 4:
            break
        length = int.from_bytes(data[i : i + 4], "big")
        i += 4
        packet = data[i : i + length]
        i += length
        if len(packet) < 12:
            continue
        pt = packet[1] & 0x7F
        if 64 <= pt <= 95:  # RTCP
            rtcp_count += 1
            continue
        rtp_count += 1
        cc = packet[0] & 0x0F
        header_len = 12 + cc * 4
        if packet[0] & 0x10:  # extension header
            ext_len = int.from_bytes(packet[header_len + 2 : header_len + 4], "big")
            header_len += 4 + ext_len * 4
        _process_rtp_payload(packet[header_len:], fu_buffer, nal_chunks)

    args.output.write_bytes(b"".join(nal_chunks))
    print(f"RTP: {rtp_count}, RTCP: {rtcp_count}")
    print(f"NAL units emitted: {len(nal_chunks)}")
    print(f"Wrote {args.output} ({args.output.stat().st_size} bytes)")
    print(f"Play with: ffplay -framerate 60 {args.output}")


if __name__ == "__main__":
    main()
