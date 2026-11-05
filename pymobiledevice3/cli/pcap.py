from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Optional, cast

import typer
from pygments import formatters, highlight, lexers
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_hex, user_requested_colored_output
from pymobiledevice3.services.pcapd import INTERFACE_NAMES, CrossPlatformAddressFamily, DevicePacket, PcapdService

cli = InjectingTyper(
    name="pcap",
    help="Sniff device traffic via pcapd and optionally save to a .pcap file.",
    no_args_is_help=True,
)


def print_packet_header(packet: DevicePacket, color: bool) -> None:
    date = datetime.fromtimestamp(packet.seconds + (packet.microseconds / 1000000))
    data = (
        f"{date}: "
        f"Process {packet.comm} ({packet.pid}), "
        f"Interface: {packet.interface_name}{packet.unit} ({INTERFACE_NAMES(packet.interface_type).name}), "
        f"Family: {CrossPlatformAddressFamily(packet.protocol_family).name}"
    )
    if not color:
        print(data)
    else:
        print(
            highlight(data, cast(Any, lexers).HspecLexer(), cast(Any, formatters).Terminal256Formatter(style="native")),
            end="",
        )


def print_packet(packet: DevicePacket, color: Optional[bool] = None) -> DevicePacket:
    """Return the packet, so it can be chained in a generator"""
    if color is None:
        color = user_requested_colored_output()
    print_packet_header(packet, color)
    print_hex(packet.data, color)
    return packet


@cli.command()
@async_command
async def pcap(
    service_provider: ServiceProviderDep,
    out: Annotated[
        Optional[Path], typer.Option(help="Also save the packets to this file, in pcapng format (e.g. for Wireshark).")
    ] = None,
    count: Annotated[
        int,
        typer.Option(
            "--count",
            "-c",
            help="Stop after this many packets. Omit to capture until Ctrl+C.",
        ),
    ] = -1,
    process: Annotated[
        Optional[str],
        typer.Option(help="Only packets of this process (name or PID). Omit for all."),
    ] = None,
    interface: Annotated[
        Optional[str],
        typer.Option(
            "--interface",
            "-i",
            help="Only packets on this interface: a full name such as en0 or pdp_ip0, or a name without its "
            "unit (en) for all its units. Omit for all.",
        ),
    ] = None,
) -> None:
    """Capture the device's network traffic, print it, and optionally save it to a pcapng file."""
    service = PcapdService(lockdown=service_provider)
    packets_generator = service.watch(packets_count=count, process=process, interface_name=interface)

    if out is not None:

        async def packets_generator_with_print():
            async for packet in packets_generator:
                yield print_packet(packet)

        with out.open("wb") as out_file:
            await service.write_to_pcap(out_file, packets_generator_with_print())
        return

    async for packet in packets_generator:
        print_packet(packet)
