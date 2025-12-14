import logging

from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
from pymobiledevice3.services.amfi import AmfiService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="amfi",
    help="Enable developer-mode or query its state",
    no_args_is_help=True,
)


@cli.command()
def reveal_developer_mode(service_provider: ServiceProviderDep) -> None:
    """reveal developer mode option in device's UI"""
    AmfiService(service_provider).reveal_developer_mode_option_in_ui()


@cli.command()
def enable_developer_mode(service_provider: ServiceProviderDep) -> None:
    """enable developer mode"""
    AmfiService(service_provider).enable_developer_mode()


@cli.command()
def developer_mode_status(service_provider: ServiceProviderDep) -> None:
    """query developer mode status"""
    print_json(service_provider.developer_mode_status)
