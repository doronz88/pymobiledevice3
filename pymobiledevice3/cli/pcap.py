from datetime import datetime
from typing import IO, Optional

import click
from pygments import formatters, highlight, lexers

from pymobiledevice3.cli.cli_common import Command, print_hex
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.pcapd import PcapdService


@click.group()
def cli():
    """ apps cli """
    pass


def print_packet_header(packet, color: bool):
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
        print(highlight(data, lexers.HspecLexer(), formatters.TerminalTrueColorFormatter(style='native')), end='')


def print_packet(packet, color: bool):
    """ Return the packet so it can be chained in a generator """
    print_packet_header(packet, color)
    print_hex(packet.data, color)
    return packet


@cli.command(cls=Command)
@click.argument('out', type=click.File('wb'), required=False)
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of packets to sniff. Omit to endless sniff.')
@click.option('--process', default=None, help='Process to filter. Omit for all.')
@click.option('-i', '--interface', default=None, help='Interface name to filter. Omit for all.')
@click.option('--color/--no-color', default=True)
def pcap(service_provider: LockdownClient, out: Optional[IO], count: int, process: Optional[str],
         interface: Optional[str], color: bool):
    """ sniff device traffic """
    service = PcapdService(lockdown=service_provider)
    packets_generator = service.watch(packets_count=count, process=process, interface_name=interface)

    if out is not None:
        packets_generator_with_print = map(lambda p: print_packet(p, color), packets_generator)
        service.write_to_pcap(out, packets_generator_with_print)
        return

    for packet in packets_generator:
        print_packet(packet, color)
