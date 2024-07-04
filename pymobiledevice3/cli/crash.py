import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.crash_reports import CrashReportsManager, CrashReportsShell


@click.group()
def cli() -> None:
    pass


@cli.group()
def crash() -> None:
    """ Manage crash reports """
    pass


@crash.command('clear', cls=Command)
@click.option('-f', '--flush', is_flag=True, default=False, help='flush before clear')
def crash_clear(service_provider: LockdownClient, flush):
    """ clear(/remove) all crash reports """
    crash_manager = CrashReportsManager(service_provider)
    if flush:
        crash_manager.flush()
    crash_manager.clear()


@crash.command('pull', cls=Command)
@click.argument('out', type=click.Path(file_okay=False))
@click.argument('remote_file', type=click.Path(), required=False)
@click.option('-e', '--erase', is_flag=True)
def crash_pull(service_provider: LockdownClient, out, remote_file, erase):
    """ pull all crash reports """
    if remote_file is None:
        remote_file = '/'
    CrashReportsManager(service_provider).pull(out, remote_file, erase)


@crash.command('shell', cls=Command)
def crash_shell(service_provider: LockdownClient):
    """ start an afc shell """
    CrashReportsShell.create(service_provider)


@crash.command('ls', cls=Command)
@click.argument('remote_file', type=click.Path(), required=False)
@click.option('-d', '--depth', type=click.INT, default=1)
def crash_ls(service_provider: LockdownClient, remote_file, depth):
    """ List  """
    if remote_file is None:
        remote_file = '/'
    for path in CrashReportsManager(service_provider).ls(remote_file, depth):
        print(path)


@crash.command('flush', cls=Command)
def crash_mover_flush(service_provider: LockdownClient):
    """ trigger com.apple.crashreportmover to flush all products into CrashReports directory """
    CrashReportsManager(service_provider).flush()


@crash.command('watch', cls=Command)
@click.argument('name', required=False)
@click.option('-r', '--raw', is_flag=True)
def crash_mover_watch(service_provider: LockdownClient, name, raw):
    """ watch for crash report generation """
    for crash_report in CrashReportsManager(service_provider).watch(name=name, raw=raw):
        print(crash_report)


@crash.command('sysdiagnose', cls=Command)
@click.argument('out', type=click.Path(exists=False, dir_okay=True, file_okay=True))
@click.option('-e', '--erase', is_flag=True, help='erase file after pulling')
@click.option('-t', '--timeout', default=None, show_default=True, type=click.FLOAT,
              help='Maximum time in seconds to wait for the completion of sysdiagnose archive')
def crash_sysdiagnose(service_provider: LockdownClient, out, erase, timeout):
    """ get a sysdiagnose archive from device (requires user interaction) """
    print('Press Power+VolUp+VolDown for 0.215 seconds')
    CrashReportsManager(service_provider).get_new_sysdiagnose(out, erase=erase, timeout=timeout)
