import ast
import logging

from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import OSUTILS, ServiceProviderDep, async_command
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="settings",
    help="accessibility settings",
    no_args_is_help=True,
)


@cli.command("show")
@async_command
async def accessibility_settings_show(service_provider: ServiceProviderDep) -> None:
    """show current settings"""
    for setting in await AccessibilityAudit(service_provider).settings():
        print(setting)


@cli.command("set")
@async_command
async def accessibility_settings_set(service_provider: ServiceProviderDep, setting: str, value: str) -> None:
    """
    change current settings

    in order to list all available use the "show" command
    """
    service = AccessibilityAudit(service_provider)
    await service.set_setting(setting, ast.literal_eval(value))
    OSUTILS.wait_return()


@cli.command("reset")
@async_command
async def accessibility_settings_reset(service_provider: ServiceProviderDep) -> None:
    """
    reset accessibility settings to default
    """
    service = AccessibilityAudit(service_provider)
    await service.reset_settings()
