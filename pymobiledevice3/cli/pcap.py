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
    interface: Annotated[
        str,
        typer.Option(
            "--interface",
            "-i",
            help="Network interface name to capture on.",
        ),
    ] = "en0",
    timeout: Annotated[
        int,
        typer.Option(help="Timeout in seconds to wait for a valid IP (0 = no timeout)."),
    ] = 5,
) -> None:
    """
    Get the device's IP address on a specific network interface via USB.

    Captures packets on the given interface and returns the first private
    IPv4 source address found.

    \b
    Common interface names:
        en0       — WiFi (default)
        pdp_ip0   — Cellular
        lo0       — Loopback

    \b
    Examples:
        pymobiledevice3 pcap wifi-ip
        pymobiledevice3 pcap wifi-ip --interface pdp_ip0
        pymobiledevice3 pcap wifi-ip --timeout 10
    """
    start_time = time.time()
    service = PcapdService(lockdown=service_provider)

    for packet in service.watch(interface_name=interface):
        if timeout > 0 and (time.time() - start_time) > timeout:
            logger.error(f"Timeout after {timeout} seconds. No IP found on interface '{interface}'.")
            logger.info("Tip: Generate network activity on the device (e.g., open a webpage)")
            raise typer.Exit(code=1)

        if packet.protocol_family != CrossPlatformAddressFamily.AF_INET:
            continue

        # Extract source IPv4 from packet data:
        # 14-byte ethernet header + 12-byte offset to src address in IPv4 header
        src_ip = ipaddress.IPv4Address(packet.data[26:30])

        if src_ip.is_private and not src_ip.is_loopback and not src_ip.is_unspecified:
            print(str(src_ip))
            return

    logger.error(f"No private IPv4 address found on interface '{interface}'")
    raise typer.Exit(code=1)
