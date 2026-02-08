import ipaddress
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer
from pygments import formatters, highlight, lexers
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_hex, user_requested_colored_output
from pymobiledevice3.services.pcapd import CrossPlatformAddressFamily, PcapdService

logger = logging.getLogger(__name__)

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


@cli.command("wifi-ip")
def wifi_ip(
    service_provider: ServiceProviderDep,
    timeout: Annotated[
        int,
        typer.Option(help="Timeout in seconds to wait for a connection (0 = no timeout)"),
    ] = 5,
) -> None:
    """
    Get the device's WiFi IP address via USB.

    Captures network packets and extracts the first private IPv4 source address,
    which corresponds to the device's WiFi IP.

    This does not require developer mode to be enabled.

    \b
    Examples:
        pymobiledevice3 pcap wifi-ip
        pymobiledevice3 pcap wifi-ip --timeout 10
    """
    ETHERNET_HEADER_LEN = 14
    IPV4_SRC_OFFSET = 12

    service = PcapdService(lockdown=service_provider)
    start_time = time.time()

    for packet in service.watch():
        if timeout > 0 and (time.time() - start_time) > timeout:
            logger.error(f"Timeout after {timeout} seconds. No WiFi IP found.")
            logger.info("Tip: Generate network activity on the device (e.g., open a webpage)")
            raise typer.Exit(code=1)

        if packet.protocol_family != CrossPlatformAddressFamily.AF_INET:
            continue

        if len(packet.data) < ETHERNET_HEADER_LEN + IPV4_SRC_OFFSET + 4:
            continue

        src_ip_bytes = packet.data[ETHERNET_HEADER_LEN + IPV4_SRC_OFFSET:ETHERNET_HEADER_LEN + IPV4_SRC_OFFSET + 4]
        addr = ipaddress.IPv4Address(src_ip_bytes)

        if addr.is_private and not addr.is_loopback and not addr.is_unspecified:
            print(addr)
            return

    logger.error("No private IPv4 address found")
    raise typer.Exit(code=1)
