import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.services.bt_packet_logger import BtPacketLoggerService

cli = InjectingTyper(
    name="btlogger",
    help="Capture Bluetooth HCI traffic via com.apple.bluetooth.BTPacketLogger.",
    no_args_is_help=True,
)


class BtLoggerFormat(str, Enum):
    PACKETLOGGER = "packetlogger"
    PCAP = "pcap"


@cli.command()
@async_command
async def capture(
    service_provider: ServiceProviderDep,
    out: Path,
    format_: Annotated[
        BtLoggerFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format: Apple's PacketLogger format or classic PCAP.",
        ),
    ] = BtLoggerFormat.PACKETLOGGER,
) -> None:
    """Capture Bluetooth HCI traffic to a file. Use '-' to stream to stdout."""
    async with BtPacketLoggerService(service_provider) as service:
        packet_generator = service.watch()
        if str(out) == "-":
            if format_ is BtLoggerFormat.PACKETLOGGER:
                await service.write_to_packetlogger(sys.stdout.buffer, packet_generator)
            else:
                await service.write_to_pcap(sys.stdout.buffer, packet_generator)
            return

        with out.open("wb") as out_file:
            if format_ is BtLoggerFormat.PACKETLOGGER:
                await service.write_to_packetlogger(out_file, packet_generator)
            else:
                await service.write_to_pcap(out_file, packet_generator)
