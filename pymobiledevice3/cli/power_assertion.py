import time

import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.power_assertion import PowerAssertionService


@click.group()
def cli() -> None:
    pass


@cli.command("power-assertion", cls=Command)
@click.argument(
    "assertion_type",
    type=click.Choice(["AMDPowerAssertionTypeWirelessSync", "PreventUserIdleSystemSleep", "PreventSystemSleep"]),
)
@click.argument("name")
@click.argument("timeout", type=click.INT)
@click.argument("details", required=False)
def power_assertion(service_provider: LockdownServiceProvider, assertion_type, name, timeout, details) -> None:
    """Create a power assertion"""
    with PowerAssertionService(service_provider).create_power_assertion(assertion_type, name, timeout, details):
        print("> Hit Ctrl+C to exit")
        time.sleep(timeout)
