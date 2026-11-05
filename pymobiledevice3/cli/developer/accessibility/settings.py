import ast
import logging
from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import OSUTILS, ServiceProviderDep, async_command
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="settings",
    help="Show, change or reset the device's accessibility settings.",
    no_args_is_help=True,
)


@cli.command("show")
@async_command
async def accessibility_settings_show(service_provider: ServiceProviderDep) -> None:
    """Show the current accessibility settings and their values."""
    for setting in await AccessibilityAudit(service_provider).settings():
        print(setting)


@cli.command("set")
@async_command
async def accessibility_settings_set(
    service_provider: ServiceProviderDep,
    setting: Annotated[str, typer.Argument(help="Setting key to change (see the `show` command).")],
    value: Annotated[str, typer.Argument(help="New value as a Python literal (e.g. True, False, 0.5).")],
) -> None:
    """
    Change an accessibility setting on the device, then wait until interrupted (Ctrl+C).

    To list the available settings use the "show" command.
    """
    service = AccessibilityAudit(service_provider)
    await service.set_setting(setting, ast.literal_eval(value))
    OSUTILS.wait_return()


@cli.command("reset")
@async_command
async def accessibility_settings_reset(service_provider: ServiceProviderDep) -> None:
    """Reset all accessibility settings to their device defaults."""
    service = AccessibilityAudit(service_provider)
    await service.reset_settings()
