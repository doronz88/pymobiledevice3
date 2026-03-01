from pathlib import Path
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import OSUTILS, ServiceProviderDep, async_command
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation

cli = InjectingTyper(
    name="simulate-location",
    help="Simulate device location by given input",
    no_args_is_help=True,
)


@cli.command("clear")
@async_command
async def dvt_simulate_location_clear(service_provider: ServiceProviderDep) -> None:
    """Clear currently simulated location"""
    async with DvtSecureSocketProxyService(service_provider) as dvt:
        await LocationSimulation(dvt).clear()


@cli.command("set")
@async_command
async def dvt_simulate_location_set(service_provider: ServiceProviderDep, latitude: float, longitude: float) -> None:
    """
    Set a simulated location.

    \b
    For example:
    \b    ... set -- 40.690008 -74.045843 for liberty island
    """
    async with DvtSecureSocketProxyService(service_provider) as dvt:
        await LocationSimulation(dvt).set(latitude, longitude)
        OSUTILS.wait_return()


@cli.command("play")
@async_command
async def dvt_simulate_location_play(
    service_provider: ServiceProviderDep,
    filename: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=False),
    ],
    timing_randomness_range: int = 0,
    disable_sleep: Annotated[bool, typer.Option()] = False,
) -> None:
    """Simulate inputs from a given .gpx file"""
    async with DvtSecureSocketProxyService(service_provider) as dvt:
        await LocationSimulation(dvt).play_gpx_file(
            str(filename),
            disable_sleep=disable_sleep,
            timing_randomness_range=timing_randomness_range,
        )
        OSUTILS.wait_return()
