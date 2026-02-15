from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import OSUTILS, ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.dvt.instruments.condition_inducer import ConditionInducer

cli = InjectingTyper(
    name="developer",
    help="Force predefined device conditions (network, thermal, battery) via DVT.",
    no_args_is_help=True,
)


@cli.command("list")
@async_command
async def condition_list(service_provider: ServiceProviderDep) -> None:
    """List available condition profiles."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        print_json(await ConditionInducer(dvt).list())


@cli.command("clear")
@async_command
async def condition_clear(service_provider: ServiceProviderDep) -> None:
    """Clear any active induced condition."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        await ConditionInducer(dvt).clear()


@cli.command("set")
@async_command
async def condition_set(service_provider: ServiceProviderDep, profile_identifier: str) -> None:
    """Apply a specific condition profile by identifier."""
    async with DvtSecureSocketProxyService(lockdown=service_provider) as dvt:
        await ConditionInducer(dvt).set(profile_identifier)
        OSUTILS.wait_return()
