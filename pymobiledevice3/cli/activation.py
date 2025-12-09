from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep
from pymobiledevice3.services.mobile_activation import MobileActivationService

cli = InjectingTyper(
    name="activation",
    help="Perform iCloud activation/deactivation or query the current state",
    no_args_is_help=True,
)


@cli.command()
def state(service_provider: ServiceProviderDep) -> None:
    """Get current activation state"""
    print(MobileActivationService(service_provider).state)


@cli.command()
def activate(
    service_provider: ServiceProviderDep,
    now: Annotated[
        bool,
        typer.Option(help="do not wait for next nonce cycle"),
    ] = False,
) -> None:
    """Activate device"""
    activation_service = MobileActivationService(service_provider)
    if not now:
        activation_service.wait_for_activation_session()
    activation_service.activate()


@cli.command()
def deactivate(service_provider: ServiceProviderDep) -> None:
    """Deactivate device"""
    MobileActivationService(service_provider).deactivate()


@cli.command()
def itunes(service_provider: ServiceProviderDep) -> None:
    """Tell the device that it has been connected to iTunes (useful for < iOS 4)"""
    service_provider.set_value(True, key="iTunesHasConnected")
