import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcShell
from pymobiledevice3.services.crash_report import CrashReports

CRASH_MOVER_NAME = 'com.apple.crashreportmover'


@click.group()
def cli():
    """ crash cli """
    pass


@cli.group()
def crash():
    """ crash report options """
    pass


@crash.command('clear', cls=Command)
def crash_clear(lockdown: LockdownClient):
    """ clear(/remove) all crash reports """
    CrashReports(lockdown).clear()


@crash.command('pull', cls=Command)
@click.argument('out', type=click.Path(file_okay=False, dir_okay=True, exists=False))
def crash_pull(lockdown: LockdownClient, out):
    """ pull all crash reports """
    CrashReports(lockdown).pull(out)


@crash.command('shell', cls=Command)
def crash_shell(lockdown: LockdownClient):
    """ start an afc shell """
    AfcShell(lockdown=lockdown, service_name=CrashReports.COPY_MOBILE_NAME).cmdloop()


@crash.command('ls', cls=Command)
@click.argument('remote_file', type=click.Path(), required=False)
@click.option('-d', '--depth', type=click.INT, default=1)
def crash_ls(lockdown: LockdownClient, remote_file, depth):
    """ List  """
    if remote_file is None:
        remote_file = '/'
    for path in CrashReports(lockdown).ls(remote_file, depth):
        print(path)


@crash.command('flush', cls=Command)
def crash_mover_flush(lockdown: LockdownClient):
    """ trigger com.apple.crashreportmover to flush all products into CrashReports directory """
    ack = b'ping\x00'
    assert ack == lockdown.start_service(CRASH_MOVER_NAME).recvall(len(ack))
