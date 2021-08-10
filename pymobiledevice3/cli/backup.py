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
@click.argument('backup-directory', type=click.Path(file_okay=False))
@click.option('--full', is_flag=True, help=('Whether to do a full backup.'
                                            ' If full is True, any previous backup attempts will be discarded.'))
def backup(lockdown: LockdownClient, backup_directory, full):
    """
    Backup device.

    All backup data will be written to BACKUP_DIRECTORY, under a directory named with the device's udid.
    """
    backup_client = Mobilebackup2Service(lockdown)
    with tqdm(total=100) as pbar:
        def update_bar(percentage):
            pbar.n = percentage
            pbar.refresh()

        backup_client.backup(full=full, backup_directory=backup_directory, progress_callback=update_bar)


@backup2.command(cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
@click.option('--system/--no-system', default=False, help='Restore system files.')
@click.option('--reboot/--no-reboot', default=True, help='Reboot the device when done.')
@click.option('--copy/--no-copy', default=True, help='Create a copy of backup folder before restoring.')
@click.option('--settings/--no-settings', default=True, help='Restore device settings.')
@click.option('--remove/--no-remove', default=False, help='Remove items which aren\'t being restored.')
@click.option('-p', '--password', type=click.STRING, default='', help='Backup password.')
def restore(lockdown: LockdownClient, backup_directory, system, reboot, copy, settings, remove, password):
    """
    Restore a backup to a device.

    The backup will be restored from a directory with the device udid under BACKUP_DIRECTORY.
    """
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
    """
    Print information about a backup.
    """
    backup_client = Mobilebackup2Service(lockdown)
    print(backup_client.info(backup_directory=backup_directory))


@backup2.command('list', cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
def list_(lockdown: LockdownClient, backup_directory):
    """
    List all file in the backup in a CSV format.
    """
    backup_client = Mobilebackup2Service(lockdown)
    print(backup_client.list(backup_directory=backup_directory))


@backup2.command(cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
@click.option('-p', '--password', type=click.STRING, default='', help='Backup password.')
def unback(lockdown: LockdownClient, backup_directory, password):
    """
    Convert all files in the backup to the correct directory hierarchy.
    """
    backup_client = Mobilebackup2Service(lockdown)
    backup_client.unback(backup_directory=backup_directory, password=password)


@backup2.command(cls=Command)
@click.argument('domain-name', type=click.STRING)
@click.argument('relative-path', type=click.STRING)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
@click.option('-p', '--password', type=click.STRING, default='', help='Backup password.')
def extract(lockdown: LockdownClient, domain_name, relative_path, backup_directory, password):
    """
    Extract a file from the backup.

    The file that belongs to the domain DOMAIN_NAME and located on the device in the path RELATIVE_PATH,
    will be extracted to the BACKUP_DIRECTORY.
    """
    backup_client = Mobilebackup2Service(lockdown)
    backup_client.extract(domain_name, relative_path, backup_directory=backup_directory, password=password)


@backup2.command(cls=Command)
@click.argument('on', type=click.BOOL)
@click.argument('password', type=click.STRING)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
def encryption(lockdown: LockdownClient, backup_directory, on, password):
    """
    Set backup encryption on / off.

    When on, PASSWORD will be the new backup password.
    When off, PASSWORD is the current backup password.
    """
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
    """
    Change the backup password.
    """
    will_encrypt = lockdown.get_value('com.apple.mobile.backup', 'WillEncrypt')
    if not will_encrypt:
        logging.error('Encryption is not turned on!')
        return
    backup_client = Mobilebackup2Service(lockdown)
    backup_client.change_password(backup_directory, old=old_password, new=new_password)


@backup2.command(cls=Command)
@click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
def erase_device(lockdown: LockdownClient, backup_directory):
    """
    Erase all data on the device.
    """
    backup_client = Mobilebackup2Service(lockdown)
    backup_client.erase_device(backup_directory)
