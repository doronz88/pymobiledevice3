import asyncio
from typing import Annotated, Literal, Optional

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command
from pymobiledevice3.services.power_assertion import PowerAssertionService

cli = InjectingTyper(
    name="power-assertion",
    no_args_is_help=True,
)


@cli.command("power-assertion")
@async_command
async def power_assertion(
    service_provider: ServiceProviderDep,
    assertion_type: Annotated[
        Literal["AMDPowerAssertionTypeWirelessSync", "PreventUserIdleSystemSleep", "PreventSystemSleep"],
        typer.Argument(help="Power assertion type to create."),
    ],
    name: Annotated[str, typer.Argument(help="Name to identify the assertion on the device.")],
    timeout: Annotated[int, typer.Argument(help="How long to hold the assertion, in seconds.")],
    details: Annotated[Optional[str], typer.Argument(help="Optional description attached to the assertion.")] = None,
) -> None:
    """Hold a power assertion on the device for TIMEOUT seconds (Ctrl+C to stop early)."""
    async with PowerAssertionService(service_provider).create_power_assertion(assertion_type, name, timeout, details):
        print("> Hit Ctrl+C to exit")
        await asyncio.sleep(timeout)
