import logging
import plistlib
import traceback

import IPython
import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.restore.restore import RestoreService


def return_to_normal_mode():
    device = IRecv()
    device.set_autoboot(True)
    device.reboot()


@click.group()
def cli():
    """ cli """
    pass


@cli.group()
def restore():
    """ restore options """
    pass


@restore.command('shell')
def restore_shell():
    """ create an IPython shell for interacting with iBoot """
    device = IRecv()
    IPython.embed(
        user_ns={
            'device': device,
        })


@restore.command('enter', cls=Command)
def restore_enter(lockdown):
    """ enter Recovery mode """
    lockdown.enter_recovery()


@restore.command('exit')
def restore_exit():
    """ exit Recovery mode """
    return_to_normal_mode()


@restore.command('tss', cls=Command)
@click.argument('ipsw', type=click.File('rb'))
@click.argument('out', type=click.File('wb'), required=False)
@click.option('--color/--no-color', default=True)
def restore_tss(lockdown, ipsw, out, color):
    """ query SHSH blobs """
    tss = RestoreService(lockdown, ipsw).fetch_tss_record()
    if out:
        plistlib.dump(tss, out)
    print_json(tss, colored=color)


@restore.command('ramdisk', cls=Command)
@click.argument('ipsw', type=click.File('rb'))
@click.option('--tss', type=click.File('rb'))
def restore_ramdisk(lockdown, ipsw, tss):
    """ don't perform an actual restore. just enter the update ramdisk """
    try:
        if tss:
            tss = plistlib.load(tss)
        RestoreService(lockdown, ipsw, tss=tss).boot_ramdisk()
    except Exception:
        traceback.print_exc()
        logging.info('returning to normal mode')
        return_to_normal_mode()


@restore.command('upgrade', cls=Command)
@click.argument('ipsw', type=click.File('rb'))
@click.option('--tss', type=click.File('rb'))
def restore_upgrade(lockdown, ipsw, tss):
    """ perform an upgrade """
    try:
        if tss:
            tss = plistlib.load(tss)
        RestoreService(lockdown, ipsw, tss=tss).upgrade()
    except Exception:
        traceback.print_exc()
        logging.info('returning to normal mode')
        return_to_normal_mode()
