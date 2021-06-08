import logging
import os

import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.afc import AfcShell, AfcService


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def crash():
    """ crash report options """
    pass


@crash.command('clear', cls=Command)
def crash_clear(lockdown):
    """ clear(/remove) all crash reports """
    afc = AfcService(lockdown, service_name='com.apple.crashreportcopymobile')
    afc.rm('/', force=True)


@crash.command('pull', cls=Command)
@click.argument('out', type=click.Path(file_okay=False, dir_okay=True, exists=False))
def crash_pull(lockdown, out):
    """ pull all crash reports """
    if not os.path.exists(out):
        os.makedirs(out)

    def log(src, dst):
        logging.info(f'{src} --> {dst}')

    afc = AfcService(lockdown, service_name='com.apple.crashreportcopymobile')
    afc.pull('/', out, callback=log)


@crash.command('shell', cls=Command)
def crash_shell(lockdown):
    """ start an afc shell """
    AfcShell(lockdown=lockdown, service_name='com.apple.crashreportcopymobile').cmdloop()


@crash.command('flush', cls=Command)
def crash_mover_flush(lockdown):
    """ trigger com.apple.crashreportmover to flush all products into CrashReports directory """
    ack = b'ping\x00'
    assert ack == lockdown.start_service('com.apple.crashreportmover').recvall(len(ack))
