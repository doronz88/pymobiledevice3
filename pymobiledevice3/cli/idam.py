import logging
from textwrap import dedent

from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
from pymobiledevice3.services.idam import IDAMService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="idam",
    help=dedent("""\
        Access IDAM (Inter-Device Audio and MIDI) configuration

        For more info refer to:
        <https://www.youtube.com/watch?v=IXmP938brnc>
    """),
    no_args_is_help=True,
)


@cli.command()
def configuration_inquiry(service_provider: ServiceProviderDep) -> None:
    """Inquiry IDAM configuration"""
    with IDAMService(service_provider) as idam:
        print_json(idam.configuration_inquiry())


@cli.command()
def enable(service_provider: ServiceProviderDep) -> None:
    """Enable IDAM"""
    with IDAMService(service_provider) as idam:
        idam.set_idam_configuration(True)


@cli.command()
def disable(service_provider: ServiceProviderDep) -> None:
    """Disable IDAM"""
    with IDAMService(service_provider) as idam:
        idam.set_idam_configuration(False)
