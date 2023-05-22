import struct
from datetime import datetime
from typing import IO

import click
import hexdump
from pygments import formatters, highlight, lexers

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.pcapd import PACKET_HEADER, PCAP_HEADER, PcapdService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.command(cls=Command)
@click.argument('out', type=click.File('wb'), required=False)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of packets to sniff. Omit to endless sniff.')
@click.option('--process', default=None, help='Process to filter. Omit for all.')
@click.option('--color/--no-color', default=True)
def pcap(lockdown: LockdownClient, out: IO, count: int, process: str, color: bool):
    """ sniff device traffic """
    service = PcapdService(lockdown=lockdown)
    packets_generator = service.watch(packets_count=count, process=process)

    if out is not None:
        out.write(PCAP_HEADER)

    formatter = formatters.TerminalTrueColorFormatter(style='native')

    for packet in packets_generator:
        date = datetime.fromtimestamp(packet.seconds + (packet.microseconds / 1000000))
        data = (
            f'{date}: '
            f'Process {packet.comm} ({packet.pid}), '
            f'Interface: {packet.interface_name} ({packet.interface_type.name}), '
            f'Family: {packet.protocol_family.name}'
        )
        if not color:
            print(data)
        else:
            print(highlight(data, lexers.HspecLexer(), formatter), end='')
        hex_dump = hexdump.hexdump(packet.data, result='return')
        if color:
            print(highlight(hex_dump, lexers.HexdumpLexer(), formatter))
        else:
            print(hex_dump, end='\n\n')

        if out is not None:
            length = len(packet.data)
            pkthdr = struct.pack(PACKET_HEADER, packet.seconds, packet.microseconds, length, length)
            data = pkthdr + packet.data
            out.write(data)
