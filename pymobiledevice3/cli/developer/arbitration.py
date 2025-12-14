import logging
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import OSUTILS, ServiceProviderDep, print_json
from pymobiledevice3.exceptions import DeviceAlreadyInUseError
from pymobiledevice3.services.device_arbitration import DtDeviceArbitration

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="arbitration",
    help='Mark/unmark a device as "in-use" to avoid conflicts with other tools.',
    no_args_is_help=True,
)


@cli.command("version")
def version(service_provider: ServiceProviderDep) -> None:
    """Show arbitration protocol version."""
    with DtDeviceArbitration(service_provider) as device_arbitration:
        print_json(device_arbitration.version)


@cli.command("check-in")
def check_in(
    service_provider: ServiceProviderDep,
    hostname: str,
    force: Annotated[
        bool,
        typer.Option("--force", "-f"),
    ] = False,
) -> None:
    """Check-in as owner (marks device as in-use; use --force to override)."""
    with DtDeviceArbitration(service_provider) as device_arbitration:
        try:
            device_arbitration.check_in(hostname, force=force)
            OSUTILS.wait_return()
        except DeviceAlreadyInUseError as e:
            logger.error(e.message)


@cli.command("check-out")
def check_out(service_provider: ServiceProviderDep) -> None:
    """Release ownership and allow other tools to use the device."""
    with DtDeviceArbitration(service_provider) as device_arbitration:
        device_arbitration.check_out()
