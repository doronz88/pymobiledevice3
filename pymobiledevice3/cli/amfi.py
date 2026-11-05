import logging
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.amfi import AmfiService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="amfi",
    help="Manage Developer Mode and trust of developer app signers (AMFI).",
    no_args_is_help=True,
)


@cli.command()
@async_command
async def reveal_developer_mode(service_provider: ServiceProviderDep) -> None:
    """Show the Developer Mode toggle in Settings > Privacy & Security.

    Only reveals the switch; it does not turn Developer Mode on.
    """
    await AmfiService(service_provider).reveal_developer_mode_option_in_ui()


@cli.command()
@async_command
async def enable_developer_mode(service_provider: ServiceProviderDep) -> None:
    """Enable Developer Mode (restarts the device).

    Does nothing if Developer Mode is already on. Otherwise the device restarts;
    this command waits for it to reconnect and confirms the post-restart
    prompt for you. Fails if the device has a passcode set: in that case enable it
    manually in Settings > Privacy & Security > Developer Mode.
    """
    if await service_provider.get_developer_mode_status():
        logger.info("Developer mode is already enabled")
        return
    await AmfiService(service_provider).enable_developer_mode()


@cli.command()
@async_command
async def developer_mode_status(service_provider: ServiceProviderDep) -> None:
    """Print whether Developer Mode is enabled (true/false)."""
    print_json(await service_provider.get_developer_mode_status())


@cli.command()
@async_command
async def trust_app_signer(
    service_provider: ServiceProviderDep,
    profile_uuid: Annotated[str, typer.Argument(help="UUID of the installed provisioning profile")],
) -> None:
    """Trust the developer app signer of an installed provisioning profile.

    Same as tapping "Trust" under Settings > General > VPN & Device Management.
    Find the UUID with `provision list`.
    """
    print_json(await AmfiService(service_provider).trust_app_signer(profile_uuid))
