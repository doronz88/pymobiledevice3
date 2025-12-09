import logging
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
from pymobiledevice3.cli.diagnostics import battery
from pymobiledevice3.lockdown import retry_create_using_usbmux
from pymobiledevice3.services.diagnostics import DiagnosticsService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="diagnostics",
    help="Reboot/Shutdown device or access other diagnostics services",
    no_args_is_help=True,
)
cli.add_typer(battery.cli)


@cli.command("restart")
def diagnostics_restart(
    service_provider: ServiceProviderDep,
    reconnect: Annotated[
        bool,
        typer.Option(
            "--reconnect",
            "-r",
            help="Wait until the device reconnects before finishing the operation.",
        ),
    ] = False,
) -> None:
    """Restart device"""
    DiagnosticsService(lockdown=service_provider).restart()
    if reconnect:
        # Wait for the device to be available again
        with retry_create_using_usbmux(None, serial=service_provider.udid):
            print(f"Device Reconnected ({service_provider.udid}).")


@cli.command("shutdown")
def diagnostics_shutdown(service_provider: ServiceProviderDep) -> None:
    """Shutdown device"""
    DiagnosticsService(lockdown=service_provider).shutdown()


@cli.command("sleep")
def diagnostics_sleep(service_provider: ServiceProviderDep) -> None:
    """Put device into sleep"""
    DiagnosticsService(lockdown=service_provider).sleep()


@cli.command("info")
def diagnostics_info(service_provider: ServiceProviderDep) -> None:
    """Get diagnostics info"""
    print_json(DiagnosticsService(lockdown=service_provider).info())


@cli.command("ioregistry")
def diagnostics_ioregistry(
    service_provider: ServiceProviderDep,
    plane: Annotated[Optional[str], typer.Option()] = None,
    name: Annotated[Optional[str], typer.Option()] = None,
    ioclass: Annotated[Optional[str], typer.Option()] = None,
) -> None:
    """Get ioregistry info"""
    print_json(DiagnosticsService(lockdown=service_provider).ioregistry(plane=plane, name=name, ioclass=ioclass))


@cli.command("mg")
def diagnostics_mg(service_provider: ServiceProviderDep, keys: Optional[list[str]] = None) -> None:
    """Get MobileGestalt key values from given list. If empty, return all known."""
    print_json(DiagnosticsService(lockdown=service_provider).mobilegestalt(keys=keys))
