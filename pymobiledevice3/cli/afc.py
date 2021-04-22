import posixpath

import click

from pymobiledevice3.cli.cli_common import Command
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
def afc_shell(lockdown):
    """ open an AFC shell rooted at /var/mobile/Media """
    AfcShell(lockdown=lockdown, service_name='com.apple.afc').cmdloop()


@afc.command('pull', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
@click.argument('local_file', type=click.File('wb'))
def afc_pull(lockdown, remote_file, local_file):
    """ pull remote file from /var/mobile/Media """
    local_file.write(AfcService(lockdown=lockdown).get_file_contents(remote_file))


@afc.command('push', cls=Command)
@click.argument('local_file', type=click.File('rb'))
@click.argument('remote_file', type=click.Path(exists=False))
def afc_push(lockdown, local_file, remote_file):
    """ push local file into /var/mobile/Media """
    AfcService(lockdown=lockdown).set_file_contents(remote_file, local_file.read())


def show_dirlist(afc, dirname, recursive=False):
    for filename in afc.listdir(dirname):
        filename = posixpath.join(dirname, filename)
        print(filename)
        if recursive and afc.isdir(filename):
            show_dirlist(afc, filename, recursive=recursive)


@afc.command('ls', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
@click.option('-r', '--recursive', is_flag=True)
def afc_ls(lockdown, remote_file, recursive):
    """ perform a dirlist rooted at /var/mobile/Media """
    show_dirlist(AfcService(lockdown=lockdown), remote_file, recursive=recursive)


@afc.command('rm', cls=Command)
@click.argument('remote_file', type=click.Path(exists=False))
def afc_rm(lockdown, remote_file):
    """ remove a file rooted at /var/mobile/Media """
    AfcService(lockdown=lockdown).rm(remote_file)
