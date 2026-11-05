import logging
from typing import Annotated, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.cli.diagnostics import battery
from pymobiledevice3.lockdown import retry_create_using_usbmux
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.usbmux import wait_for_device_detach

logger = logging.getLogger(__name__)


# How long a device may stay connected after accepting a restart before it is taken to have
# dropped off and come back unnoticed.
RESTART_DETACH_TIMEOUT = 60.0


async def wait_for_restart(udid: Optional[str]) -> None:
    """
    Wait for a device that was just told to restart to go away and come back.

    The device stays connected for a few seconds after it accepts the request, so connecting to it
    right away would succeed before it has even gone down.
    """
    if udid is not None and not await wait_for_device_detach(udid, timeout=RESTART_DETACH_TIMEOUT):
        logger.warning("device did not disconnect within %d seconds", RESTART_DETACH_TIMEOUT)
    lockdown = await retry_create_using_usbmux(None, serial=udid)
    await lockdown.close()


cli = InjectingTyper(
    name="diagnostics",
    help="Restart, shut down or sleep the device, and query diagnostics (IORegistry, MobileGestalt, battery).",
    no_args_is_help=True,
)
cli.add_typer(battery.cli)


@cli.command("restart")
@async_command
async def diagnostics_restart(
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
    """Restart the device."""
    # The device only goes down once the connection that asked for the restart is closed.
    async with DiagnosticsService(lockdown=service_provider) as diagnostics:
        await diagnostics.restart()
    if reconnect:
        await wait_for_restart(service_provider.udid)
        print(f"Device Reconnected ({service_provider.udid}).")


@cli.command("shutdown")
@async_command
async def diagnostics_shutdown(service_provider: ServiceProviderDep) -> None:
    """Shut the device down."""
    await DiagnosticsService(lockdown=service_provider).shutdown()


@cli.command("sleep")
@async_command
async def diagnostics_sleep(service_provider: ServiceProviderDep) -> None:
    """Put the device to sleep."""
    await DiagnosticsService(lockdown=service_provider).sleep()


@cli.command("info")
@async_command
async def diagnostics_info(service_provider: ServiceProviderDep) -> None:
    """Print the device's diagnostics report (all categories)."""
    print_json(await DiagnosticsService(lockdown=service_provider).info())


@cli.command("ioregistry")
@async_command
async def diagnostics_ioregistry(
    service_provider: ServiceProviderDep,
    plane: Annotated[
        Optional[str], typer.Option(help="IORegistry plane to traverse (e.g. IODeviceTree, IOService).")
    ] = None,
    name: Annotated[Optional[str], typer.Option(help="Only the entry with this name.")] = None,
    ioclass: Annotated[Optional[str], typer.Option(help="Only the entry of this class.")] = None,
) -> None:
    """Print IORegistry entries, optionally narrowed by plane, name or class."""
    print_json(await DiagnosticsService(lockdown=service_provider).ioregistry(plane=plane, name=name, ioclass=ioclass))


@cli.command("mg")
@async_command
async def diagnostics_mg(
    service_provider: ServiceProviderDep,
    keys: Annotated[
        Optional[list[str]], typer.Argument(help="MobileGestalt keys to query; omit to query all known keys.")
    ] = None,
) -> None:
    """Print MobileGestalt values (not available on iOS 17.4+)."""
    print_json(await DiagnosticsService(lockdown=service_provider).mobilegestalt(keys=keys))
