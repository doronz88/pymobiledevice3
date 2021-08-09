import logging

from tqdm import tqdm
import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
from pymobiledevice3.lockdown import LockdownClient


@click.group()
def cli():
    """ backup cli """
    pass


@cli.group()
def backup2():
    """ backup utils """
    pass


@backup2.command(cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
@click.option('--full', is_flag=True)
def backup(lockdown: LockdownClient, backup_directory, full):
    backup_client = Mobilebackup2Service(lockdown)
    with tqdm(total=100) as pbar:
        def update_bar(percentage):
            pbar.n = percentage
            pbar.refresh()

        backup_client.backup(full=full, backup_directory=backup_directory, progress_callback=update_bar)


@backup2.command(cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
@click.option('--system/--no-system', default=False)
@click.option('--reboot/--no-reboot', default=True)
@click.option('--copy/--no-copy', default=True)
@click.option('--settings/--no-settings', default=True)
@click.option('--remove/--no-remove', default=False)
@click.option('-p', '--password', type=click.STRING, default='')
def restore(lockdown: LockdownClient, backup_directory, system, reboot, copy, settings, remove, password):
    backup_client = Mobilebackup2Service(lockdown)
    with tqdm(total=100) as pbar:
        def update_bar(percentage):
            pbar.n = percentage
            pbar.refresh()

        backup_client.restore(backup_directory=backup_directory, progress_callback=update_bar, system=system,
                              reboot=reboot, copy=copy, settings=settings, remove=remove, password=password)


@backup2.command(cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
def info(lockdown: LockdownClient, backup_directory):
    backup_client = Mobilebackup2Service(lockdown)
    print(backup_client.info(backup_directory=backup_directory))


@backup2.command('list', cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
def list_(lockdown: LockdownClient, backup_directory):
    backup_client = Mobilebackup2Service(lockdown)
    print(backup_client.list(backup_directory=backup_directory))


@backup2.command(cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
@click.option('-p', '--password', type=click.STRING, default='')
def unback(lockdown: LockdownClient, backup_directory, password):
    backup_client = Mobilebackup2Service(lockdown)
    backup_client.unback(backup_directory=backup_directory, password=password)


@backup2.command(cls=Command)
@click.argument('domain-name', type=click.STRING)
@click.argument('relative-path', type=click.STRING)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
@click.option('-p', '--password', type=click.STRING, default='')
def extract(lockdown: LockdownClient, domain_name, relative_path, backup_directory, password):
    backup_client = Mobilebackup2Service(lockdown)
    backup_client.extract(domain_name, relative_path, backup_directory=backup_directory, password=password)


@backup2.command(cls=Command)
@click.argument('on', type=click.BOOL)
@click.argument('password', type=click.STRING)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
def encryption(lockdown: LockdownClient, backup_directory, on, password):
    will_encrypt = lockdown.get_value('com.apple.mobile.backup', 'WillEncrypt')
    if will_encrypt == on:
        logging.error('Encryption already ' + ('on!' if on else 'off!'))
        return
    backup_client = Mobilebackup2Service(lockdown)
    if on:
        backup_client.change_password(backup_directory, new=password)
    else:
        backup_client.change_password(backup_directory, old=password)


@backup2.command(cls=Command)
@click.argument('old-password', type=click.STRING)
@click.argument('new-password', type=click.STRING)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
def change_password(lockdown: LockdownClient, old_password, new_password, backup_directory):
    will_encrypt = lockdown.get_value('com.apple.mobile.backup', 'WillEncrypt')
    if not will_encrypt:
        logging.error('Encryption is not turned on!')
        return
    backup_client = Mobilebackup2Service(lockdown)
    backup_client.change_password(backup_directory, old=old_password, new=new_password)


@backup2.command(cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
def erase_device(lockdown: LockdownClient, backup_directory):
    backup_client = Mobilebackup2Service(lockdown)
    backup_client.erase_device(backup_directory)
