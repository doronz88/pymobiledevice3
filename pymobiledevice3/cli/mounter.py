import logging
import plistlib
import tempfile
import zipfile
from pathlib import Path
from typing import IO

import click
import requests
from tqdm import tqdm

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import NotMountedError, UnsupportedCommandError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobile_image_mounter import MobileImageMounterService

DEVELOPER_DISK_IMAGE_URL = 'https://github.com/pdso/DeveloperDiskImage/raw/master/{ios_version}/{ios_version}.zip'

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """ mounter cli """
    pass


@cli.group()
def mounter():
    """ mounter options """
    pass


@mounter.command('list', cls=Command)
@click.option('--color/--no-color', default=True)
def mounter_list(lockdown: LockdownClient, color):
    """ list all mounted images """
    output = []

    images = MobileImageMounterService(lockdown=lockdown).copy_devices()
    for image in images:
        image_signature = image.get('ImageSignature')
        if image_signature is not None:
            image['ImageSignature'] = image_signature.hex()
        output.append(image)

    print_json(output, colored=color)


@mounter.command('lookup', cls=Command)
@click.option('--color/--no-color', default=True)
@click.argument('image_type')
def mounter_lookup(lockdown: LockdownClient, color, image_type):
    """ lookup mounter image type """
    try:
        signature = MobileImageMounterService(lockdown=lockdown).lookup_image(image_type)
        print_json(signature, colored=color)
    except NotMountedError:
        logger.error(f'Disk image of type: {image_type} is not mounted')


@mounter.command('umount', cls=Command)
@click.option('-t', '--image-type', type=click.Choice(['Developer', 'Cryptex']), default='Developer')
@click.option('-p', '--mount-path', help='Only needed for older iOS version', default='/Developer')
def mounter_umount(lockdown: LockdownClient, image_type: str, mount_path: str):
    """ unmount developer image. """
    image_mounter = MobileImageMounterService(lockdown=lockdown)
    try:
        image_mounter.umount(mount_path, image_type=image_type, signature=b'')
        logger.info('DeveloperDiskImage unmounted successfully')
    except NotMountedError:
        logger.error('DeveloperDiskImage isn\'t currently mounted')
    except UnsupportedCommandError:
        logger.error('Your iOS version doesn\'t support this command')


def download_file(url, local_filename):
    logger.debug(f'downloading: {local_filename}')
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        total_size_in_bytes = int(r.headers.get('content-length', 0))

        with tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, dynamic_ncols=True) as progress_bar:
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    progress_bar.update(len(chunk))
                    f.write(chunk)

    return local_filename


def download_developer_disk_image(ios_version, directory):
    url = DEVELOPER_DISK_IMAGE_URL.format(ios_version=ios_version)
    with tempfile.NamedTemporaryFile('wb+') as f:
        download_file(url, f.name)
        zip_file = zipfile.ZipFile(f)
        zip_file.extractall(directory)


@mounter.command('mount', cls=Command)
@click.argument('image-path', type=click.Path(exists=True))
@click.argument('signature', type=click.Path(exists=True))
@click.argument('image-type', type=click.Choice(['Developer', 'Cryptex']), default='Developer')
@click.option('--trust-cache', type=click.File('rb'), help='Used only for Cryptex images')
@click.option('--info-plist', type=click.File('rb'), help='Used only for Cryptex images')
def mounter_mount(lockdown: LockdownClient, image_path: str, signature: str, image_type: str, trust_cache: IO = None,
                  info_plist: IO = None):
    """ mount developer image. """
    image_mounter = MobileImageMounterService(lockdown=lockdown)
    if image_mounter.is_image_mounted(image_type):
        logger.error(f'{image_type} is already mounted')
        return

    if trust_cache is not None:
        trust_cache = trust_cache.read()

    if info_plist is not None:
        info_plist = plistlib.load(info_plist)

    image_path = Path(image_path)
    signature = Path(signature)
    image_path = image_path.read_bytes()
    signature = signature.read_bytes()

    image_mounter.upload_image(image_type, image_path, signature)
    image_mounter.mount(image_type, signature, trust_cache=trust_cache, info_plist=info_plist)
    logger.info(f'{image_type} mounted successfully')


@mounter.command('auto-mount', cls=Command)
@click.option('-x', '--xcode', type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help='Xcode application path used to figure out automatically the DeveloperDiskImage path')
@click.option('-v', '--version', help='use a different DeveloperDiskImage version from the one retrieved by lockdown'
                                      'connection')
def mounter_auto_mount(lockdown: LockdownClient, xcode: str, version: str):
    """ auto-detect correct DeveloperDiskImage and mount it """
    image_type = 'Developer'

    if xcode is None:
        # avoid "default"-ing this option, because Windows and Linux won't have this path
        xcode = Path('/Applications/Xcode.app')
        if not (xcode.exists()):
            xcode = get_home_folder() / 'Xcode.app'
            xcode.mkdir(parents=True, exist_ok=True)

    image_mounter = MobileImageMounterService(lockdown=lockdown)
    if image_mounter.is_image_mounted(image_type):
        logger.error('DeveloperDiskImage is already mounted')
        return

    logger.debug('trying to figure out the best suited DeveloperDiskImage')
    if version is None:
        version = lockdown.sanitized_ios_version
    image_dir = f'{xcode}/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/{version}'
    image_path = f'{image_dir}/DeveloperDiskImage.dmg'
    signature = f'{image_path}.signature'
    developer_disk_image_dir = Path(image_path).parent

    if not developer_disk_image_dir.exists():
        try:
            download_developer_disk_image(version, developer_disk_image_dir)
        except PermissionError:
            logger.error(
                f'DeveloperDiskImage could not be saved to Xcode default path ({developer_disk_image_dir}). '
                f'Please make sure your user has the necessary permissions')
            return

    image_path = Path(image_path)
    signature = Path(signature)
    image_path = image_path.read_bytes()
    signature = signature.read_bytes()

    image_mounter.upload_image(image_type, image_path, signature)
    image_mounter.mount(image_type, signature)
    logger.info('DeveloperDiskImage mounted successfully')


@mounter.command('query-developer-mode-status', cls=Command)
@click.option('--color/--no-color', default=True)
def mounter_query_developer_mode_status(lockdown: LockdownClient, color):
    """ Query developer mode status """
    print_json(MobileImageMounterService(lockdown=lockdown).query_developer_mode_status(), colored=color)


@mounter.command('query-nonce', cls=Command)
@click.option('--color/--no-color', default=True)
def mounter_query_nonce(lockdown: LockdownClient, color):
    """ Query nonce """
    print_json(MobileImageMounterService(lockdown=lockdown).query_nonce(), colored=color)


@mounter.command('query-personalization-identifiers', cls=Command)
@click.option('--color/--no-color', default=True)
def mounter_query_personalization_identifiers(lockdown: LockdownClient, color):
    """ Query personalization identifiers """
    print_json(MobileImageMounterService(lockdown=lockdown).query_personalization_identifiers(), colored=color)


@mounter.command('roll-personalization-nonce', cls=Command)
def mounter_roll_personalization_nonce(lockdown: LockdownClient):
    MobileImageMounterService(lockdown=lockdown).roll_personalization_nonce()


@mounter.command('roll-cryptex-nonce', cls=Command)
@click.option('--color/--no-color', default=True)
def mounter_roll_cryptex_nonce(lockdown: LockdownClient):
    """ Roll cryptex nonce (will reboot) """
    MobileImageMounterService(lockdown=lockdown).roll_cryptex_nonce()
