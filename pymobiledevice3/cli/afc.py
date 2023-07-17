import logging

import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.exceptions import AfcFileNotFoundError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService, AfcShell

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ apps cli """
    pass


@cli.group()
def afc():
    """ FileSystem utils """
    pass


@afc.command('shell', cls=Command)
def afc_shell(lockdown: LockdownClient):
    """ open an AFC shell rooted at /var/mobile/Media """
    AfcShell(lockdown=lockdown, service_name='com.apple.afc').cmdloop()


@afc.command('pull', cls=Command)
@click.argument('remote_path', type=str)
@click.argument('local_path', type=str)
def afc_pull(lockdown: LockdownClient, remote_path, local_path):
    """ pull a remote file/directory from /var/mobile/Media into local file/directory """
    def log(src, dst):
        logger.info(f'{src} --> {dst}')

    try:
        AfcService(lockdown=lockdown).pull(remote_path, local_path, callback=log)
    except (FileNotFoundError, AfcFileNotFoundError, NotADirectoryError, IsADirectoryError) as e:
        logger.error(e)


@afc.command('push', cls=Command)
@click.argument('local_file', type=click.File('rb'))
@click.argument('remote_file', type=click.Path(exists=False))
def afc_push(lockdown: LockdownClient, local_file, remote_file):
    """ push local file into /var/mobile/Media """
    AfcService(lockdown=lockdown).set_file_contents(remote_file, local_file.read())


@afc.command('ls', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
@click.option('-r', '--recursive', is_flag=True)
def afc_ls(lockdown: LockdownClient, remote_file, recursive):
    """ perform a dirlist rooted at /var/mobile/Media """
    for path in AfcService(lockdown=lockdown).dirlist(remote_file, -1 if recursive else 1):
        print(path)


@afc.command('rm', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
def afc_rm(lockdown: LockdownClient, remote_file):
    """ remove a file rooted at /var/mobile/Media """
    AfcService(lockdown=lockdown).rm(remote_file)
