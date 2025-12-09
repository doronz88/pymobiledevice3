from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
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
def companion_list(service_provider: ServiceProviderDep) -> None:
    """list all paired companion devices"""
    print_json(CompanionProxyService(service_provider).list(), default=lambda x: "<non-serializable>")
