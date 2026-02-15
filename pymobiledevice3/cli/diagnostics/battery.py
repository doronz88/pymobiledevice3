import asyncio
import logging

from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.diagnostics import DiagnosticsService

logger = logging.getLogger(__name__)

cli = InjectingTyper(
    name="battery",
    help="Battery options",
    no_args_is_help=True,
)


@cli.command("single")
@async_command
async def diagnostics_battery_single(service_provider: ServiceProviderDep) -> None:
    """get single snapshot of battery data"""
    raw_info = await DiagnosticsService(lockdown=service_provider).get_battery()
    print_json(raw_info)


@cli.command("monitor")
@async_command
async def diagnostics_battery_monitor(service_provider: ServiceProviderDep) -> None:
    """monitor battery usage"""
    diagnostics = DiagnosticsService(lockdown=service_provider)
    while True:
        raw_info = await diagnostics.get_battery()
        info = {
            "InstantAmperage": raw_info.get("InstantAmperage"),
            "Temperature": raw_info.get("Temperature"),
            "Voltage": raw_info.get("Voltage"),
            "IsCharging": raw_info.get("IsCharging"),
            "CurrentCapacity": raw_info.get("CurrentCapacity"),
        }
        logger.info(info)
        await asyncio.sleep(1)


@cli.command("wifi")
@async_command
async def diagnostics_wifi(service_provider: ServiceProviderDep) -> None:
    """Query WiFi info from IORegistry"""
    raw_info = await DiagnosticsService(lockdown=service_provider).get_wifi()
    print_json(raw_info)
