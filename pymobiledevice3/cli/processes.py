import logging

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.os_trace import OsTraceService

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group()
def processes() -> None:
    """ View process list using diagnosticsd API """
    pass


@processes.command('ps', cls=Command)
def processes_ps(service_provider: LockdownClient):
    """ show process list """
    print_json(OsTraceService(lockdown=service_provider).get_pid_list().get('Payload'))


@processes.command('pgrep', cls=Command)
@click.argument('expression')
def processes_pgrep(service_provider: LockdownClient, expression):
    """ try to match processes pid by given expression (like pgrep) """
    processes_list = OsTraceService(lockdown=service_provider).get_pid_list().get('Payload')
    for pid, process_info in processes_list.items():
        process_name = process_info.get('ProcessName')
        if expression in process_name:
            logger.info(f'{pid} {process_name}')
