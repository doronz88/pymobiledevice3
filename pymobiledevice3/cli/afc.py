import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService, AfcShell


@click.group()
def cli() -> None:
    pass


@cli.group()
def afc() -> None:
    """ Manage device multimedia files """
    pass


@afc.command('shell', cls=Command)
def afc_shell(service_provider: LockdownClient):
    """ open an AFC shell rooted at /var/mobile/Media """
    AfcShell.create(service_provider)


@afc.command('pull', cls=Command)
@click.option('-i', '--ignore-errors', is_flag=True, help='Ignore AFC pull errors')
@click.argument('remote_file', type=click.Path(exists=False))
@click.argument('local_file', type=click.Path(exists=False))
def afc_pull(service_provider: LockdownServiceProvider, remote_file: str, local_file: str, ignore_errors: bool) -> None:
    """ pull remote file from /var/mobile/Media """
    AfcService(lockdown=service_provider).pull(remote_file, local_file, ignore_errors=ignore_errors)


@afc.command('push', cls=Command)
@click.argument('local_file', type=click.Path(exists=False))
@click.argument('remote_file', type=click.Path(exists=False))
def afc_push(service_provider: LockdownServiceProvider, local_file: str, remote_file: str) -> None:
    """ push local file into /var/mobile/Media """
    AfcService(lockdown=service_provider).push(local_file, remote_file)


@afc.command('ls', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
@click.option('-r', '--recursive', is_flag=True)
def afc_ls(service_provider: LockdownClient, remote_file, recursive):
    """ perform a dirlist rooted at /var/mobile/Media """
    for path in AfcService(lockdown=service_provider).dirlist(remote_file, -1 if recursive else 1):
        print(path)


@afc.command('rm', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
def afc_rm(service_provider: LockdownClient, remote_file):
    """ remove a file rooted at /var/mobile/Media """
    AfcService(lockdown=service_provider).rm(remote_file)
