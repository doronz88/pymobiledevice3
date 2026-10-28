import logging
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.amfi import AmfiService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="amfi",
    help="Manage developer-mode and app signer trust",
    no_args_is_help=True,
)


@cli.command()
@async_command
async def reveal_developer_mode(service_provider: ServiceProviderDep) -> None:
    """reveal developer mode option in device's UI"""
    await AmfiService(service_provider).reveal_developer_mode_option_in_ui()


@cli.command()
@async_command
async def enable_developer_mode(service_provider: ServiceProviderDep) -> None:
    """enable developer mode"""
    if await service_provider.get_developer_mode_status():
        logger.info("Developer mode is already enabled")
        return
    await AmfiService(service_provider).enable_developer_mode()


@cli.command()
@async_command
async def developer_mode_status(service_provider: ServiceProviderDep) -> None:
    """query developer mode status"""
    print_json(await service_provider.get_developer_mode_status())


@cli.command()
@async_command
async def trust_app_signer(
    service_provider: ServiceProviderDep,
    profile_uuid: Annotated[str, typer.Argument(help="UUID of the installed provisioning profile")],
) -> None:
    """trust the developer app signer of an installed provisioning profile"""
    print_json(await AmfiService(service_provider).trust_app_signer(profile_uuid))
