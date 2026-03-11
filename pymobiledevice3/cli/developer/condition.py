from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import OSUTILS, ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.dvt.instruments.condition_inducer import ConditionInducer
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider

cli = InjectingTyper(
    name="condition",
    help="Force predefined device conditions (network, thermal, battery) via DVT.",
    no_args_is_help=True,
)


@cli.command("list")
@async_command
async def condition_list(service_provider: ServiceProviderDep) -> None:
    """List available condition profiles."""
    async with DvtProvider(service_provider) as dvt, ConditionInducer(dvt) as condition_inducer:
        print_json(await condition_inducer.list())


@cli.command("clear")
@async_command
async def condition_clear(service_provider: ServiceProviderDep) -> None:
    """Clear any active induced condition."""
    async with DvtProvider(service_provider) as dvt, ConditionInducer(dvt) as condition_inducer:
        await condition_inducer.clear()


@cli.command("set")
@async_command
async def condition_set(service_provider: ServiceProviderDep, profile_identifier: str) -> None:
    """Apply a specific condition profile by identifier."""
    async with DvtProvider(service_provider) as dvt, ConditionInducer(dvt) as condition_inducer:
        await condition_inducer.set(profile_identifier)
        OSUTILS.wait_return()
