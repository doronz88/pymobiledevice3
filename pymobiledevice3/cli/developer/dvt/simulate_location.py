from pathlib import Path
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import OSUTILS, ServiceProviderDep, async_command
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation

cli = InjectingTyper(
    name="simulate-location",
    help="Simulate device location through DVT on iOS 17 and newer.",
    no_args_is_help=True,
)


@cli.command("clear")
@async_command
async def dvt_simulate_location_clear(service_provider: ServiceProviderDep) -> None:
    """Clear the currently simulated location on iOS 17 and newer."""
    async with DvtProvider(service_provider) as dvt, LocationSimulation(dvt) as location_simulation:
        await location_simulation.clear()


@cli.command("set")
@async_command
async def dvt_simulate_location_set(service_provider: ServiceProviderDep, latitude: float, longitude: float) -> None:
    """
    Set a simulated location through DVT on iOS 17 and newer.

    \b
    For example:
    \b    ... set -- 40.690008 -74.045843 for liberty island
    """
    async with DvtProvider(service_provider) as dvt, LocationSimulation(dvt) as location_simulation:
        await location_simulation.set(latitude, longitude)
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
    """Replay a GPX route through DVT on iOS 17 and newer."""
    async with DvtProvider(service_provider) as dvt, LocationSimulation(dvt) as location_simulation:
        await location_simulation.play_gpx_file(
            str(filename),
            disable_sleep=disable_sleep,
            timing_randomness_range=timing_randomness_range,
        )
        OSUTILS.wait_return()
