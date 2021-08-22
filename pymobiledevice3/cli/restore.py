import logging
import os
import plistlib

import IPython
import click
from pygments import highlight, lexers, formatters

from pymobiledevice3.cli.cli_common import print_json
from pymobiledevice3.exceptions import IncorrectModeError
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import list_devices, LockdownClient
from pymobiledevice3.restore.recovery import Recovery
from pymobiledevice3.restore.restore import Restore
from pymobiledevice3.restore.restored_client import RestoredClient

SHELL_USAGE = """
# use `irecv` variable to access Restore mode API
# for example:
print(irecv.getenv('build-version'))
"""


class Command(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('device', '--ecid'), type=click.INT, callback=self.device),
        ]

    @staticmethod
    def device(ctx, param, value):
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
            # prevent lockdown connection establishment when in autocomplete mode
            return

        ecid = value
        logging.debug('searching among connected devices via lockdownd')
        for udid in list_devices():
            try:
                lockdown = LockdownClient(udid=udid)
            except IncorrectModeError:
                continue
            if (ecid is None) or (lockdown.ecid == value):
                logging.debug('found device')
                return lockdown
            else:
                continue
        logging.debug(f'waiting for device to be available in Recovery mode')
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
def restore_shell(irecv):
    """ create an IPython shell for interacting with iBoot """
    IPython.embed(
        header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
        user_ns={
            'irecv': irecv,
        })


@restore.command('enter', cls=Command)
def restore_enter(lockdown):
    """ enter Recovery mode """
    lockdown.enter_recovery()


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
@click.option('--offline', is_flag=True)
def restore_tss(device, ipsw, out, color, offline):
    """ query SHSH blobs """
    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device

    tss = Recovery(ipsw, lockdown=lockdown, irecv=irecv, offline=offline).fetch_tss_record()
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
    Recovery(ipsw, lockdown=lockdown, irecv=irecv, tss=tss).boot_ramdisk()


@restore.command('update', cls=Command)
@click.argument('ipsw', type=click.File('rb'))
@click.option('--tss', type=click.File('rb'))
@click.option('--offline', is_flag=True)
@click.option('--erase', is_flag=True)
def restore_update(device, ipsw, tss, offline, erase):
    """ perform an upgrade """
    if tss:
        tss = plistlib.load(tss)

    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device

    behavior = 'Update'
    if erase:
        behavior = 'Erase'
    Restore(ipsw, lockdown=lockdown, irecv=irecv, tss=tss, offline=offline, behavior=behavior).update()
