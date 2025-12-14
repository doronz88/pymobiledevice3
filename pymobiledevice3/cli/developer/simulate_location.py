import logging
from pathlib import Path
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep
from pymobiledevice3.services.simulate_location import DtSimulateLocation

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="simulate-location",
    help="Simulate device location by given input",
    no_args_is_help=True,
)


@cli.command("clear")
def simulate_location_clear(service_provider: ServiceProviderDep) -> None:
    """clear simulated location"""
    DtSimulateLocation(service_provider).clear()


@cli.command("set")
def simulate_location_set(service_provider: ServiceProviderDep, latitude: float, longitude: float) -> None:
    """
    set a simulated location.
    try:
        ... set -- 40.690008 -74.045843 for liberty island
    """
    DtSimulateLocation(service_provider).set(latitude, longitude)


@cli.command("play")
def simulate_location_play(
    service_provider: ServiceProviderDep,
    filename: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=False),
    ],
    timing_randomness_range: int,
    disable_sleep: Annotated[bool, typer.Option()] = False,
) -> None:
    """play a .gpx file"""
    DtSimulateLocation(service_provider).play_gpx_file(
        str(filename),
        disable_sleep=disable_sleep,
        timing_randomness_range=timing_randomness_range,
    )
