import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService, AfcShell


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def afc():
    """ FileSystem utils """
    pass


@afc.command('shell', cls=Command)
def afc_shell(service_provider: LockdownClient):
    """ open an AFC shell rooted at /var/mobile/Media """
    AfcShell.create(service_provider)


@afc.command('pull', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
@click.argument('local_file', type=click.File('wb'))
def afc_pull(service_provider: LockdownClient, remote_file, local_file):
    """ pull remote file from /var/mobile/Media """
    local_file.write(AfcService(lockdown=service_provider).get_file_contents(remote_file))


@afc.command('push', cls=Command)
@click.argument('local_file', type=click.File('rb'))
@click.argument('remote_file', type=click.Path(exists=False))
def afc_push(service_provider: LockdownClient, local_file, remote_file):
    """ push local file into /var/mobile/Media """
    AfcService(lockdown=service_provider).set_file_contents(remote_file, local_file.read())


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
