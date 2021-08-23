#!/usr/bin/env python3
import logging

import click
import coloredlogs

from pymobiledevice3.cli.activation import cli as activation_cli
from pymobiledevice3.cli.afc import cli as afc_cli
from pymobiledevice3.cli.apps import cli as apps_cli
from pymobiledevice3.cli.backup import cli as backup_cli
from pymobiledevice3.cli.crash import cli as crash_cli
from pymobiledevice3.cli.developer import cli as developer_cli
from pymobiledevice3.cli.diagnostics import cli as diagnostics_cli
from pymobiledevice3.cli.list_devices import cli as list_devices_cli
from pymobiledevice3.cli.lockdown import cli as lockdown_cli
from pymobiledevice3.cli.mounter import cli as mounter_cli
from pymobiledevice3.cli.notification import cli as notification_cli
from pymobiledevice3.cli.pcap import cli as pcap_cli
from pymobiledevice3.cli.power_assertion import cli as power_assertion_cli
from pymobiledevice3.cli.processes import cli as ps_cli
from pymobiledevice3.cli.profile import cli as profile_cli
from pymobiledevice3.cli.provision import cli as provision_cli
from pymobiledevice3.cli.restore import cli as restore_cli
from pymobiledevice3.cli.springboard import cli as springboard_cli
from pymobiledevice3.cli.syslog import cli as syslog_cli

coloredlogs.install(level=logging.DEBUG)

logging.getLogger('asyncio').disabled = True
logging.getLogger('parso.cache').disabled = True
logging.getLogger('parso.cache.pickle').disabled = True
logging.getLogger('parso.python.diff').disabled = True
logging.getLogger('humanfriendly.prompts').disabled = True


def cli():
    cli_commands = click.CommandCollection(sources=[
        developer_cli, mounter_cli, apps_cli, profile_cli, lockdown_cli, diagnostics_cli, syslog_cli, pcap_cli,
        crash_cli, afc_cli, ps_cli, notification_cli, list_devices_cli, power_assertion_cli, springboard_cli,
        provision_cli, backup_cli, restore_cli, activation_cli
    ])
    cli_commands()


if __name__ == '__main__':
    cli()
