from datetime import datetime

import click
from pygments import highlight, lexers, formatters
import hexdump

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.pcapd import PcapdService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.command(cls=Command)
@click.argument('out', type=click.File('wb'), required=False)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of packets to sniff. Omit to endless sniff.')
@click.option('--process', default=None, help='Process to filter. Omit for all.')
@click.option('--nocolor', is_flag=True)
def pcap(lockdown, out, count, process, nocolor):
    """ sniff device traffic """
    service = PcapdService(lockdown=lockdown)
    packets_generator = service.watch(packets_count=count, process=process)
    if out is not None:
        service.write_to_pcap(out, packets_generator)
        return

    formatter = formatters.TerminalTrueColorFormatter(style='native')

    for packet in packets_generator:
        date = datetime.fromtimestamp(packet.seconds + (packet.microseconds / 1000000))
        data = (
            f'{date}: '
            f'Process {packet.comm} ({packet.pid}), '
            f'Interface: {packet.interface_name} ({packet.interface_type.name}), '
            f'Family: {packet.protocol_family.name}'
        )
        if nocolor:
            print(data)
        else:
            print(highlight(data, lexers.HspecLexer(), formatter), end='')
        hex_dump = hexdump.hexdump(packet.data, result='return')
        if nocolor:
            print(hex_dump, end='\n\n')
        else:
            print(highlight(hex_dump, lexers.HexdumpLexer(), formatter))
