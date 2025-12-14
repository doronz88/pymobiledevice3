import time
from typing import Literal, Optional

from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep
from pymobiledevice3.services.power_assertion import PowerAssertionService

cli = InjectingTyper(
    name="power-assertion",
    no_args_is_help=True,
)


@cli.command("power-assertion")
def power_assertion(
    service_provider: ServiceProviderDep,
    assertion_type: Literal["AMDPowerAssertionTypeWirelessSync", "PreventUserIdleSystemSleep", "PreventSystemSleep"],
    name: str,
    timeout: int,
    details: Optional[str] = None,
) -> None:
    """Create a power assertion"""
    with PowerAssertionService(service_provider).create_power_assertion(assertion_type, name, timeout, details):
        print("> Hit Ctrl+C to exit")
        time.sleep(timeout)
