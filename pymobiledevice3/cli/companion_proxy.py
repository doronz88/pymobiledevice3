from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.companion import CompanionProxyService

cli = InjectingTyper(
    name="companion",
    help='List paired "companion" devices',
    no_args_is_help=True,
)


@cli.callback()
def callback() -> None:
    # Force subgroup
    pass


@cli.command("list")
@async_command
async def companion_list(service_provider: ServiceProviderDep) -> None:
    """list all paired companion devices"""
    print_json(await CompanionProxyService(service_provider).list(), default=lambda x: "<non-serializable>")
