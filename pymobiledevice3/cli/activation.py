from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.services.mobile_activation import MobileActivationService

cli = InjectingTyper(
    name="activation",
    help="Perform iCloud activation/deactivation or query the current state",
    no_args_is_help=True,
)


@cli.command()
@async_command
async def state(service_provider: ServiceProviderDep) -> None:
    """Get current activation state"""
    print(await MobileActivationService(service_provider).state())


@cli.command()
@async_command
async def activate(
    service_provider: ServiceProviderDep,
    now: Annotated[
        bool,
        typer.Option(help="do not wait for next nonce cycle"),
    ] = False,
) -> None:
    """Activate device"""
    activation_service = MobileActivationService(service_provider)
    if not now:
        await activation_service.wait_for_activation_session()
    await activation_service.activate()


@cli.command()
@async_command
async def deactivate(service_provider: ServiceProviderDep) -> None:
    """Deactivate device"""
    await MobileActivationService(service_provider).deactivate()


@cli.command()
@async_command
async def itunes(service_provider: ServiceProviderDep) -> None:
    """Tell the device that it has been connected to iTunes (useful for < iOS 4)"""
    await service_provider.set_value(True, key="iTunesHasConnected")
