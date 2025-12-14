import logging

from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import OSUTILS, ServiceProviderDep
from pymobiledevice3.services.accessibilityaudit import AccessibilityAudit

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="settings",
    help="accessibility settings",
    no_args_is_help=True,
)


@cli.command("show")
def accessibility_settings_show(service_provider: ServiceProviderDep) -> None:
    """show current settings"""
    for setting in AccessibilityAudit(service_provider).settings:
        print(setting)


@cli.command("set")
def accessibility_settings_set(service_provider: ServiceProviderDep, setting: str, value: str) -> None:
    """
    change current settings

    in order to list all available use the "show" command
    """
    service = AccessibilityAudit(service_provider)
    service.set_setting(setting, eval(value))
    OSUTILS.wait_return()


@cli.command("reset")
def accessibility_settings_reset(service_provider: ServiceProviderDep) -> None:
    """
    reset accessibility settings to default
    """
    service = AccessibilityAudit(service_provider)
    service.reset_settings()
