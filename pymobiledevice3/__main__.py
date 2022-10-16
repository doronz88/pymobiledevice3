#!/usr/bin/env python3
import logging
import traceback

import click
import coloredlogs

from pymobiledevice3.cli.activation import cli as activation_cli
from pymobiledevice3.cli.afc import cli as afc_cli
from pymobiledevice3.cli.amfi import cli as amfi_cli
from pymobiledevice3.cli.apps import cli as apps_cli
from pymobiledevice3.cli.backup import cli as backup_cli
from pymobiledevice3.cli.companion_proxy import cli as companion_cli
from pymobiledevice3.cli.crash import cli as crash_cli
from pymobiledevice3.cli.developer import cli as developer_cli
from pymobiledevice3.cli.diagnostics import cli as diagnostics_cli
from pymobiledevice3.cli.usbmux import cli as usbmux_cli
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
from pymobiledevice3.cli.webinspector import cli as webinspector_cli
from pymobiledevice3.exceptions import NoDeviceConnectedError, NotPairedError, UserDeniedPairingError, \
    PairingDialogResponsePendingError, SetProhibitedError, MissingValueError, DeviceHasPasscodeSetError, \
    DeveloperModeError, UsbmuxConnectionError

coloredlogs.install(level=logging.INFO)

logging.getLogger('asyncio').disabled = True
logging.getLogger('parso.cache').disabled = True
logging.getLogger('parso.cache.pickle').disabled = True
logging.getLogger('parso.python.diff').disabled = True
logging.getLogger('humanfriendly.prompts').disabled = True
logging.getLogger('blib2to3.pgen2.driver').disabled = True
logging.getLogger('urllib3.connectionpool').disabled = True

logger = logging.getLogger(__name__)


def cli():
    cli_commands = click.CommandCollection(sources=[
        developer_cli, mounter_cli, apps_cli, profile_cli, lockdown_cli, diagnostics_cli, syslog_cli, pcap_cli,
        crash_cli, afc_cli, ps_cli, notification_cli, usbmux_cli, power_assertion_cli, springboard_cli,
        provision_cli, backup_cli, restore_cli, activation_cli, companion_cli, webinspector_cli, amfi_cli
    ])
    cli_commands.context_settings = dict(help_option_names=['-h', '--help'])
    try:
        cli_commands()
    except NoDeviceConnectedError:
        logger.error('Device is not connected')
    except ConnectionAbortedError:
        logger.error('Device was disconnected')
    except NotPairedError:
        logger.error('Device is not paired')
    except UserDeniedPairingError:
        logger.error('User refused to trust this computer')
    except PairingDialogResponsePendingError:
        logger.error('Waiting for user dialog approval')
    except SetProhibitedError:
        logger.error('lockdownd denied the access')
    except MissingValueError:
        logger.error('No such value')
    except DeviceHasPasscodeSetError:
        logger.error('Cannot enable developer-mode when passcode is set')
    except DeveloperModeError as e:
        logger.error(f'Failed to enable developer-mode. Error: {e}')
    except UsbmuxConnectionError:
        logger.error('Failed to connect to usbmuxd socket. Make sure it\'s running.')
    except BrokenPipeError:
        traceback.print_exc()


if __name__ == '__main__':
    cli()
