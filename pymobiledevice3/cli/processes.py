from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, async_command, print_json
from pymobiledevice3.services.os_trace import OsTraceService

cli = InjectingTyper(
    name="processes",
    help="View process list using diagnosticsd API",
    no_args_is_help=True,
)


@cli.command("ps")
@async_command
async def processes_ps(service_provider: ServiceProviderDep) -> None:
    """show process list"""
    print_json((await OsTraceService(lockdown=service_provider).get_pid_list()).get("Payload"))


@cli.command("pgrep")
@async_command
async def processes_pgrep(service_provider: ServiceProviderDep, expression: str) -> None:
    """try to match processes pid by given expression (like pgrep)"""
    processes_list = (await OsTraceService(lockdown=service_provider).get_pid_list()).get("Payload")
    matches = [
        {"pid": pid, "name": process_info.get("ProcessName")}
        for pid, process_info in processes_list.items()
        if expression in process_info.get("ProcessName")
    ]
    print_json(matches)
