from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer
from pygments import formatters, highlight, lexers
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_hex, user_requested_colored_output
from pymobiledevice3.services.pcapd import PcapdService

cli = InjectingTyper(
    name="pcap",
    help="Sniff device traffic via pcapd and optionally save to a .pcap file.",
    no_args_is_help=True,
)


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


@cli.command()
def pcap(
    service_provider: ServiceProviderDep,
    out: Optional[Path] = None,
    count: Annotated[
        int,
        typer.Option(
            "--count",
            "-c",
            help="Number of packets to sniff. Omit to endless sniff.",
        ),
    ] = -1,
    process: Annotated[
        Optional[str],
        typer.Option(help="Process to filter. Omit for all."),
    ] = None,
    interface: Annotated[
        Optional[str],
        typer.Option(
            "--interface",
            "-i",
            help="Interface name to filter. Omit for all.",
        ),
    ] = None,
) -> None:
    """Sniff device traffic."""
    service = PcapdService(lockdown=service_provider)
    packets_generator = service.watch(packets_count=count, process=process, interface_name=interface)

    if out is not None:
        packets_generator_with_print = (print_packet(p) for p in packets_generator)
        with out.open("wb") as out_file:
            service.write_to_pcap(out_file, packets_generator_with_print)
        return

    for packet in packets_generator:
        print_packet(packet)
