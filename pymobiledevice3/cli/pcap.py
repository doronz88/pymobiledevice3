from datetime import datetime
from typing import IO, Optional

import click
from pygments import formatters, highlight, lexers

from pymobiledevice3.cli.cli_common import Command, print_hex, user_requested_colored_output
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.pcapd import PcapdService


@click.group()
def cli() -> None:
    pass


def print_packet_header(packet, color: bool) -> None:
    date = datetime.fromtimestamp(packet.seconds + (packet.microseconds / 1000000))
    data = (
        f"{date}: "
        f"Process {packet.comm} ({packet.pid}), "
        f"Interface: {packet.interface_name} ({packet.interface_type.name}), "
        f"Family: {packet.protocol_family.name}"
    )
    if not color:
        print(data)
    else:
        print(highlight(data, lexers.HspecLexer(), formatters.Terminal256Formatter(style="native")), end="")


def print_packet(packet, color: Optional[bool] = None):
    """Return the packet, so it can be chained in a generator"""
    if color is None:
        color = user_requested_colored_output()
    print_packet_header(packet, color)
    print_hex(packet.data, color)
    return packet


@cli.command(cls=Command)
@click.argument("out", type=click.File("wb"), required=False)
@click.option("-c", "--count", type=click.INT, default=-1, help="Number of packets to sniff. Omit to endless sniff.")
@click.option("--process", default=None, help="Process to filter. Omit for all.")
@click.option("-i", "--interface", default=None, help="Interface name to filter. Omit for all.")
def pcap(
    service_provider: LockdownServiceProvider,
    out: Optional[IO],
    count: int,
    process: Optional[str],
    interface: Optional[str],
) -> None:
    """Sniff device traffic"""
    service = PcapdService(lockdown=service_provider)
    packets_generator = service.watch(packets_count=count, process=process, interface_name=interface)

    if out is not None:
        packets_generator_with_print = (print_packet(p) for p in packets_generator)
        service.write_to_pcap(out, packets_generator_with_print)
        return

    for packet in packets_generator:
        print_packet(packet)
