from pathlib import Path
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import OSUTILS, ServiceProviderDep, async_command
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation

cli = InjectingTyper(
    name="simulate-location",
    help="Simulate the device's GPS location through DVT (use this one on iOS 17 and newer).",
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
async def dvt_simulate_location_set(
    service_provider: ServiceProviderDep,
    latitude: Annotated[float, typer.Argument(help="Latitude in decimal degrees.")],
    longitude: Annotated[float, typer.Argument(help="Longitude in decimal degrees (put `--` before negative values).")],
) -> None:
    """
    Simulate a fixed location, keeping the session open until interrupted (Ctrl+C).

    \b
    For example:
    \b    ... set -- 40.690008 -74.045843 for liberty island
    """
    async with DvtProvider(service_provider) as dvt, LocationSimulation(dvt) as location_simulation:
        await location_simulation.set(latitude, longitude)
        await OSUTILS.wait_return()


@cli.command("play")
@async_command
async def dvt_simulate_location_play(
    service_provider: ServiceProviderDep,
    filename: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=False, help="GPX file with the route to replay."),
    ],
    timing_randomness_range: Annotated[
        int, typer.Argument(help="Random jitter, in milliseconds (+/-), added to each wait between points.")
    ] = 0,
    disable_sleep: Annotated[
        bool, typer.Option(help="Jump through the points without waiting the time between their timestamps.")
    ] = False,
) -> None:
    """Replay a GPX route at its recorded pace, then wait until interrupted (Ctrl+C)."""
    async with DvtProvider(service_provider) as dvt, LocationSimulation(dvt) as location_simulation:
        await location_simulation.play_gpx_file(
            str(filename),
            disable_sleep=disable_sleep,
            timing_randomness_range=timing_randomness_range,
        )
        await OSUTILS.wait_return()
