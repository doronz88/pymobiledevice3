import logging
import os
import plistlib
import traceback

import IPython
import click
from pygments import highlight, lexers, formatters

from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import print_json, set_verbosity
from pymobiledevice3.exceptions import IncorrectModeError
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Recovery, Behavior
from pymobiledevice3.restore.restore import Restore

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
        for device in usbmux.list_devices():
            try:
                lockdown = LockdownClient(udid=device.serial)
            except IncorrectModeError:
                continue
            if (ecid is None) or (lockdown.ecid == value):
                logger.debug('found device')
                return lockdown
            else:
                continue
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


@restore.command('tss', cls=Command)
@click.argument('ipsw', type=click.File('rb'))
@click.argument('out', type=click.File('wb'), required=False)
@click.option('--color/--no-color', default=True)
def restore_tss(device, ipsw, out, color):
    """ query SHSH blobs """
    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device

    device = Device(lockdown=lockdown, irecv=irecv)
    tss = Recovery(ipsw, device).fetch_tss_record()
    if out:
        plistlib.dump(tss, out)
    print_json(tss, colored=color)


@restore.command('ramdisk', cls=Command)
@click.argument('ipsw', type=click.File('rb'))
@click.option('--tss', type=click.File('rb'))
def restore_ramdisk(device, ipsw, tss):
    """ don't perform an actual restore. just enter the update ramdisk """
    if tss:
        tss = plistlib.load(tss)

    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device
    device = Device(lockdown=lockdown, irecv=irecv)
    Recovery(ipsw, device, tss=tss).boot_ramdisk()


@restore.command('update', cls=Command)
@click.argument('ipsw', type=click.File('rb'))
@click.option('--tss', type=click.File('rb'))
@click.option('--erase', is_flag=True, help='use the Erase BuildIdentity (full factory-reset)')
@click.option('--ignore-fdr', is_flag=True, help='only establish an FDR service connection, but don\'t proxy any '
                                                 'traffic')
def restore_update(device, ipsw, tss, erase, ignore_fdr):
    """ perform an upgrade """
    if tss:
        tss = plistlib.load(tss)

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
