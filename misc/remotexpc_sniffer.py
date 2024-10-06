import logging
from pprint import pformat
from typing import Optional

import click
import coloredlogs
from construct import ConstError, StreamError
from hexdump import hexdump
from hyperframe.frame import DataFrame, Frame, GoAwayFrame, HeadersFrame
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from scapy.sendrecv import sniff

from pymobiledevice3.remote.remotexpc import HTTP2_MAGIC
from pymobiledevice3.remote.tunnel_service import PairingDataComponentTLVBuf
from pymobiledevice3.remote.xpc_message import XpcWrapper, decode_xpc_object

logger = logging.getLogger()

FRAME_HEADER_SIZE = 9


def create_stream_key(src: str, sport: int, dst: str, dport: int) -> str:
    return f'{src}/{sport}//{dst}/{dport}'


class TCPStream:
    def __init__(self, src: str, sport: int, dst: str, dport: int):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.key = create_stream_key(src, sport, dst, dport)
        self.data = bytearray()
        self.seq: Optional[int] = None  # so we know seq hasn't been initialized yet
        self.segments = {}  # data segments to add later

    def __repr__(self) -> str:
        return f'Stream<{self.key}>'

    def __len__(self) -> int:
        return len(self.data)

    def add(self, tcp_pkt: TCP) -> bool:
        """
        Returns True if we added an in-order segment, False if not
        """
        if self.seq is None:
            # set initial seq
            self.seq = tcp_pkt.seq
        data = bytes(tcp_pkt.payload)
        data_len = len(data)
        seq_offset = tcp_pkt.seq - self.seq
        if len(self.data) < seq_offset:
            # if this data is out of order and needs to be inserted later
            self.segments[seq_offset] = data
            return False
        else:
            # if this data is in order (has a place to be inserted)
            self.data[seq_offset:seq_offset + data_len] = data
            # check if there are any waiting data segments to add
            for seq_offset in sorted(self.segments.keys()):
                if seq_offset <= len(self.data):  # if we can add this segment to the stream
                    segment_payload = self.segments[seq_offset]
                    self.data[seq_offset:seq_offset + len(segment_payload)] = segment_payload
                    self.segments.pop(seq_offset)
                else:
                    break  # short circuit because list is sorted
            return True


class H2Stream(TCPStream):
    def pop_frames(self) -> list[Frame]:
        """ Pop all available H2Frames """

        # If self.data starts with the http/2 magic bytes, pop them off
        if self.data.startswith(HTTP2_MAGIC):
            logger.debug('HTTP/2 magic bytes')
            self.data = self.data[len(HTTP2_MAGIC):]
            self.seq += len(HTTP2_MAGIC)

        frames = []
        while len(self.data) >= FRAME_HEADER_SIZE:
            frame, additional_size = Frame.parse_frame_header(memoryview(self.data[:FRAME_HEADER_SIZE]))
            if len(self.data) - FRAME_HEADER_SIZE < additional_size:
                # the frame has an incomplete body
                break
            self.data = self.data[FRAME_HEADER_SIZE:]
            frame.parse_body(memoryview(self.data[:additional_size]))
            self.data = self.data[additional_size:]
            self.seq += FRAME_HEADER_SIZE + additional_size
            frames.append(frame)
        return frames


class RemoteXPCSniffer:
    def __init__(self):
        self._h2_streams: dict[str, H2Stream] = {}
        self._previous_frame_data: dict[str, bytes] = {}

    def process_packet(self, packet: Packet) -> None:
        if packet.haslayer(TCP) and packet[TCP].payload:
            self._process_tcp(packet)

    def _process_tcp(self, pkt: Packet) -> None:
        # we are going to separate TCP packets into TCP streams between unique
        # endpoints (ip/port) then, for each stream, we will create a new H2Stream
        # object and pass TCP packets into it H2Stream objects will take the bytes
        # from each TCP packet and add them to the stream.  No error correction /
        # checksum checking will be done. The stream will just overwrite its bytes
        # with whatever is presented in the packets. If the stream receives packets
        # out of order, it will add the bytes at the proper index.
        if pkt.haslayer(IP):
            net_pkt = pkt[IP]
        elif pkt.haslayer(IPv6):
            net_pkt = pkt[IPv6]
        else:
            return
        tcp_pkt = pkt[TCP]
        stream_key = create_stream_key(net_pkt.src, tcp_pkt.sport, net_pkt.dst, tcp_pkt.dport)
        stream = self._h2_streams.setdefault(
            stream_key, H2Stream(net_pkt.src, tcp_pkt.sport, net_pkt.dst, tcp_pkt.dport))
        stream_finished_assembling = stream.add(tcp_pkt)
        if stream_finished_assembling:  # if we just added something in order
            self._process_stream(stream)

    def _handle_data_frame(self, stream: H2Stream, frame: DataFrame) -> None:
        previous_frame_data = self._previous_frame_data.get(stream.key, b'')
        try:
            payload = XpcWrapper.parse(previous_frame_data + frame.data).message.payload
            if payload is None:
                return None
            xpc_message = decode_xpc_object(payload.obj)
        except ConstError:  # if we don't know what this payload is
            logger.debug(
                f'New Data frame {stream.src}->{stream.dst} on HTTP/2 stream {frame.stream_id} TCP port {stream.dport}')
            hexdump(frame.data[:64])
            if len(frame.data) > 64:
                logger.debug(f'... {len(frame.data)} bytes')
            return
        except StreamError:
            self._previous_frame_data[stream.key] = previous_frame_data + frame.data
            return

        if stream.key in self._previous_frame_data:
            self._previous_frame_data.pop(stream.key)

        if xpc_message is None:
            return

        logger.info(f'As Python Object (#{frame.stream_id}): {pformat(xpc_message)}')

        # print `pairingData` if exists, since it contains an inner struct
        if 'value' not in xpc_message:
            return
        message = xpc_message['value']['message']
        if 'plain' not in message:
            return
        plain = message['plain']['_0']
        if 'event' not in plain:
            return
        pairing_data = plain['event']['_0']['pairingData']['_0']['data']
        logger.info(PairingDataComponentTLVBuf.parse(pairing_data))

    def _handle_single_frame(self, stream: H2Stream, frame: Frame) -> None:
        logger.debug(f'New HTTP/2 frame: {stream.key} ({frame})')
        if isinstance(frame, HeadersFrame):
            logger.debug(
                f'{stream.src} opening stream {frame.stream_id} for communication on port {stream.dport}')
        elif isinstance(frame, GoAwayFrame):
            logger.debug(f'{stream.src} closing stream {frame.stream_id} on port {stream.sport}')
        elif isinstance(frame, DataFrame):
            self._handle_data_frame(stream, frame)

    def _process_stream(self, stream: H2Stream) -> None:
        for frame in stream.pop_frames():
            self._handle_single_frame(stream, frame)


@click.group()
def cli():
    """ Parse RemoteXPC traffic """
    pass


@cli.command()
@click.argument('file', type=click.Path(exists=True, file_okay=True, dir_okay=False))
def offline(file: str):
    """ Parse RemoteXPC traffic from a .pcap file """
    sniffer = RemoteXPCSniffer()
    for p in sniff(offline=file):
        sniffer.process_packet(p)


@cli.command()
@click.argument('iface')
def live(iface: str):
    """ Parse RemoteXPC live from a given network interface """
    sniffer = RemoteXPCSniffer()
    sniff(iface=iface, prn=sniffer.process_packet)


if __name__ == '__main__':
    coloredlogs.install(level=logging.DEBUG)
    cli()
