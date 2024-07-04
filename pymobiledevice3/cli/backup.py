import logging

import click
from tqdm import tqdm

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

source_option = click.option('--source', default='', help='The UDID of the source device.')
password_option = click.option('-p', '--password', default='', help='Backup password.')
backup_directory_arg = click.argument('backup-directory', type=click.Path(exists=True, file_okay=False))
backup_directory_option = click.option('-b', '--backup-directory', type=click.Path(exists=True, file_okay=False),
                                       default='.')

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


@cli.group()
def backup2() -> None:
    """ Backup/Restore options """
    pass


@backup2.command(cls=Command)
@click.argument('backup-directory', type=click.Path(file_okay=False))
@click.option('--full', is_flag=True, help=('Whether to do a full backup.'
                                            ' If full is True, any previous backup attempts will be discarded.'))
def backup(service_provider: LockdownClient, backup_directory, full):
    """
    Backup device.

    All backup data will be written to BACKUP_DIRECTORY, under a directory named with the device's udid.
    """
    backup_client = Mobilebackup2Service(service_provider)
    with tqdm(total=100, dynamic_ncols=True) as pbar:
        def update_bar(percentage):
            pbar.n = percentage
            pbar.refresh()

        backup_client.backup(full=full, backup_directory=backup_directory, progress_callback=update_bar)


@backup2.command(cls=Command)
@backup_directory_arg
@click.option('--system/--no-system', default=False, help='Restore system files.')
@click.option('--reboot/--no-reboot', default=True, help='Reboot the device when done.')
@click.option('--copy/--no-copy', default=True, help='Create a copy of backup folder before restoring.')
@click.option('--settings/--no-settings', default=True, help='Restore device settings.')
@click.option('--remove/--no-remove', default=False, help='Remove items which aren\'t being restored.')
@password_option
@source_option
def restore(service_provider: LockdownClient, backup_directory, system, reboot, copy, settings, remove, password, source):
    """
    Restore a backup to a device.

    The backup will be restored from a directory with the device udid under BACKUP_DIRECTORY.
    """
    backup_client = Mobilebackup2Service(service_provider)
    with tqdm(total=100, dynamic_ncols=True) as pbar:
        def update_bar(percentage):
            pbar.n = percentage
            pbar.refresh()

        backup_client.restore(backup_directory=backup_directory, progress_callback=update_bar, system=system,
                              reboot=reboot, copy=copy, settings=settings, remove=remove, password=password,
                              source=source)


@backup2.command(cls=Command)
@backup_directory_arg
@source_option
def info(service_provider: LockdownClient, backup_directory, source):
    """
    Print information about a backup.
    """
    backup_client = Mobilebackup2Service(service_provider)
    print(backup_client.info(backup_directory=backup_directory, source=source))


@backup2.command('list', cls=Command)
@backup_directory_arg
@source_option
def list_(service_provider: LockdownClient, backup_directory, source):
    """
    List all file in the backup in a CSV format.
    """
    backup_client = Mobilebackup2Service(service_provider)
    print(backup_client.list(backup_directory=backup_directory, source=source))


@backup2.command(cls=Command)
@backup_directory_arg
@password_option
@source_option
def unback(service_provider: LockdownClient, backup_directory, password, source):
    """
    Convert all files in the backup to the correct directory hierarchy.
    """
    backup_client = Mobilebackup2Service(service_provider)
    backup_client.unback(backup_directory=backup_directory, password=password, source=source)


@backup2.command(cls=Command)
@click.argument('domain-name')
@click.argument('relative-path')
@backup_directory_arg
@password_option
@source_option
def extract(service_provider: LockdownClient, domain_name, relative_path, backup_directory, password, source):
    """
    Extract a file from the backup.

    The file that belongs to the domain DOMAIN_NAME and located on the device in the path RELATIVE_PATH,
    will be extracted to the BACKUP_DIRECTORY.
    """
    backup_client = Mobilebackup2Service(service_provider)
    backup_client.extract(domain_name, relative_path, backup_directory=backup_directory, password=password,
                          source=source)


@backup2.command(cls=Command)
@click.argument('mode', type=click.Choice(['on', 'off'], case_sensitive=False))
@click.argument('password')
@backup_directory_option
def encryption(service_provider: LockdownClient, backup_directory, mode, password):
    """
    Set backup encryption on / off.

    When on, PASSWORD will be the new backup password.
    When off, PASSWORD is the current backup password.
    """
    backup_client = Mobilebackup2Service(service_provider)
    should_encrypt = mode.lower() == 'on'
    if should_encrypt == backup_client.will_encrypt:
        logger.error('Encryption already ' + ('on!' if should_encrypt else 'off!'))
        return
    if should_encrypt:
        backup_client.change_password(backup_directory, new=password)
    else:
        backup_client.change_password(backup_directory, old=password)


@backup2.command(cls=Command)
@click.argument('old-password')
@click.argument('new-password')
@backup_directory_option
def change_password(service_provider: LockdownClient, old_password, new_password, backup_directory):
    """
    Change the backup password.
    """
    backup_client = Mobilebackup2Service(service_provider)
    if not backup_client.will_encrypt:
        logger.error('Encryption is not turned on!')
        return
    backup_client.change_password(backup_directory, old=old_password, new=new_password)


@backup2.command(cls=Command)
@backup_directory_arg
def erase_device(service_provider: LockdownClient, backup_directory):
    """
    Erase all data on the device.
    """
    backup_client = Mobilebackup2Service(service_provider)
    backup_client.erase_device(backup_directory)
