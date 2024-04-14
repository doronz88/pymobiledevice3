import logging
import os
import plistlib
import traceback
from zipfile import ZipFile

import click
import IPython
from pygments import formatters, highlight, lexers
from remotezip import RemoteZip

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import print_json, set_verbosity
from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionFailedToUsbmuxdError, IncorrectModeError
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.restore.restore import Restore
from pymobiledevice3.services.diagnostics import DiagnosticsService

SHELL_USAGE = """
# use `irecv` variable to access Restore mode API
# for example:
print(irecv.getenv('build-version'))
"""

logger = logging.getLogger(__name__)


class Command(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('device', '--ecid'), type=click.INT, callback=self.device),
            click.Option(('verbosity', '-v', '--verbose'), count=True, callback=set_verbosity, expose_value=False),
        ]

    @staticmethod
    def device(ctx, param, value):
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
            # prevent lockdown connection establishment when in autocomplete mode
            return

        ecid = value
        logger.debug('searching among connected devices via lockdownd')
        try:
            for device in usbmux.list_devices():
                try:
                    lockdown = create_using_usbmux(serial=device.serial, connection_type='USB')
                except (ConnectionFailedError, IncorrectModeError):
                    continue
                if (ecid is None) or (lockdown.ecid == value):
                    logger.debug('found device')
                    return lockdown
                else:
                    continue
        except ConnectionFailedToUsbmuxdError:
            pass

        logger.debug('waiting for device to be available in Recovery mode')
        return IRecv(ecid=ecid)


@click.group()
def cli():
    """ cli """
    pass


@cli.group()
def restore():
    """ restore options """
    pass


@restore.command('shell', cls=Command)
def restore_shell(device):
    """ create an IPython shell for interacting with iBoot """
    IPython.embed(
        header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
        user_ns={
            'irecv': device,
        })


@restore.command('enter', cls=Command)
def restore_enter(device):
    """ enter Recovery mode """
    if isinstance(device, LockdownClient):
        device.enter_recovery()


@restore.command('exit')
def restore_exit():
    """ exit Recovery mode """
    irecv = IRecv()
    irecv.set_autoboot(True)
    irecv.reboot()


@restore.command('restart', cls=Command)
def restore_restart(device):
    """ restarts device """
    if isinstance(device, LockdownClient):
        with DiagnosticsService(device) as diagnostics:
            diagnostics.restart()
    else:
        device.reboot()


@restore.command('tss', cls=Command)
@click.argument('ipsw')
@click.argument('out', type=click.File('wb'), required=False)
def restore_tss(device, ipsw, out):
    """ query SHSH blobs """
    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device

    if ipsw.startswith('http://') or ipsw.startswith('https://'):
        ipsw = RemoteZip(ipsw)
    else:
        ipsw = ZipFile(ipsw)

    device = Device(lockdown=lockdown, irecv=irecv)
    tss = Recovery(ipsw, device).fetch_tss_record()
    if out:
        plistlib.dump(tss, out)
    print_json(tss)


@restore.command('ramdisk', cls=Command)
@click.argument('ipsw')
@click.option('--tss', type=click.File('rb'))
def restore_ramdisk(device, ipsw, tss):
    """
    don't perform an actual restore. just enter the update ramdisk

    ipsw can be either a filename or an url
    """
    if tss:
        tss = plistlib.load(tss)

    if ipsw.startswith('http://') or ipsw.startswith('https://'):
        ipsw = RemoteZip(ipsw)
    else:
        ipsw = ZipFile(ipsw)

    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device
    device = Device(lockdown=lockdown, irecv=irecv)
    Recovery(ipsw, device, tss=tss).boot_ramdisk()


@restore.command('update', cls=Command)
@click.argument('ipsw')
@click.option('--tss', type=click.File('rb'))
@click.option('--erase', is_flag=True, help='use the Erase BuildIdentity (full factory-reset)')
@click.option('--ignore-fdr', is_flag=True, help='only establish an FDR service connection, but don\'t proxy any '
                                                 'traffic')
def restore_update(device, ipsw: str, tss, erase, ignore_fdr):
    """
    perform an update

    ipsw can be either a filename or an url
    """
    if tss:
        tss = plistlib.load(tss)

    if ipsw.startswith('http://') or ipsw.startswith('https://'):
        ipsw = RemoteZip(ipsw)
    else:
        ipsw = ZipFile(ipsw)

    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device
    device = Device(lockdown=lockdown, irecv=irecv)

    behavior = Behavior.Update
    if erase:
        behavior = Behavior.Erase

    try:
        Restore(ipsw, device, tss=tss, behavior=behavior, ignore_fdr=ignore_fdr).update()
    except Exception:
        # click may "swallow" several exception types so we try to catch them all here
        traceback.print_exc()
        raise
