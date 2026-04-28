import sys
from collections.abc import AsyncIterable
from enum import Enum
from pathlib import Path
from typing import Annotated, BinaryIO

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
    PCAPNG = "pcapng"


async def _write(
    service: BtPacketLoggerService,
    format_: BtLoggerFormat,
    out: BinaryIO,
    packet_generator: AsyncIterable[bytes],
) -> None:
    if format_ is BtLoggerFormat.PACKETLOGGER:
        await service.write_to_packetlogger(out, packet_generator)
    else:
        await service.write_to_pcapng(out, packet_generator)


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
            help="Output format: Apple's PacketLogger format (.pklg) or pcapng for Wireshark.",
        ),
    ] = BtLoggerFormat.PACKETLOGGER,
) -> None:
    """Capture Bluetooth HCI traffic to a file. Use '-' to stream to stdout."""
    async with BtPacketLoggerService(service_provider) as service:
        packet_generator = service.watch()
        if str(out) == "-":
            await _write(service, format_, sys.stdout.buffer, packet_generator)
            return

        with out.open("wb") as out_file:
            await _write(service, format_, out_file, packet_generator)
