from typing import Annotated

import typer
from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.os_trace import OsTraceService

cli = InjectingTyper(
    name="processes",
    help="List the processes running on the device.",
    no_args_is_help=True,
)


@cli.command("ps")
@async_command
async def processes_ps(service_provider: ServiceProviderDep) -> None:
    """Print every running process, keyed by PID."""
    print_json((await OsTraceService(lockdown=service_provider).get_pid_list()).get("Payload"))


@cli.command("pgrep")
@async_command
async def processes_pgrep(
    service_provider: ServiceProviderDep,
    expression: Annotated[str, typer.Argument(help="Case-sensitive substring of the process name.")],
) -> None:
    """Print the PID and name of every process whose name contains EXPRESSION (like pgrep)."""
    processes_list = (await OsTraceService(lockdown=service_provider).get_pid_list()).get("Payload")
    matches = [
        {"pid": pid, "name": process_info.get("ProcessName")}
        for pid, process_info in processes_list.items()
        if expression in process_info.get("ProcessName")
    ]
    print_json(matches)
