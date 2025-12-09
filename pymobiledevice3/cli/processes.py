import logging

from typer_injector import InjectingTyper

from pymobiledevice3.cli.cli_common import ServiceProviderDep, print_json
from pymobiledevice3.services.os_trace import OsTraceService

logger = logging.getLogger(__name__)


cli = InjectingTyper(
    name="processes",
    help="View process list using diagnosticsd API",
    no_args_is_help=True,
)


@cli.command("ps")
def processes_ps(service_provider: ServiceProviderDep) -> None:
    """show process list"""
    print_json(OsTraceService(lockdown=service_provider).get_pid_list().get("Payload"))


@cli.command("pgrep")
def processes_pgrep(service_provider: ServiceProviderDep, expression: str) -> None:
    """try to match processes pid by given expression (like pgrep)"""
    processes_list = OsTraceService(lockdown=service_provider).get_pid_list().get("Payload")
    for pid, process_info in processes_list.items():
        process_name = process_info.get("ProcessName")
        if expression in process_name:
            logger.info(f"{pid} {process_name}")
