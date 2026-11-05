from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.services.mobile_activation import MobileActivationService

cli = InjectingTyper(
    name="activation",
    help="Activate or deactivate the device with Apple's servers, or query its activation state.",
    no_args_is_help=True,
)


@cli.command()
@async_command
async def state(service_provider: ServiceProviderDep) -> None:
    """Print the activation state (e.g. Unactivated, Activated)."""
    print(await MobileActivationService(service_provider).state())


@cli.command()
@async_command
async def activate(
    service_provider: ServiceProviderDep,
    now: Annotated[
        bool,
        typer.Option(help="Do not wait for a fresh activation session before activating."),
    ] = False,
) -> None:
    """Activate the device against Apple's activation servers (needs Internet).

    Does nothing if the device is already activated. If the server asks for
    Apple ID credentials (Activation Lock), you are prompted for them.
    """
    activation_service = MobileActivationService(service_provider)
    if not now:
        await activation_service.wait_for_activation_session()
    await activation_service.activate()


@cli.command()
@async_command
async def deactivate(service_provider: ServiceProviderDep) -> None:
    """Deactivate the device (returns it to the unactivated state)."""
    await MobileActivationService(service_provider).deactivate()


@cli.command()
@async_command
async def itunes(service_provider: ServiceProviderDep) -> None:
    """Tell the device it has been connected to iTunes (sets iTunesHasConnected; for iOS < 4)."""
    await service_provider.set_value(True, key="iTunesHasConnected")
