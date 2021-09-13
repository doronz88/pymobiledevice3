import logging
import tempfile
import zipfile
from pathlib import Path

import click
import requests
from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.exceptions import NotMountedError, UnsupportedCommandError, AlreadyMountedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobile_image_mounter import MobileImageMounterService
from tqdm import tqdm

DEVELOPER_DISK_IMAGE_URL = 'https://github.com/filsv/iPhoneOSDeviceSupport/raw/master/{ios_version}.zip'


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

    images = MobileImageMounterService(lockdown=lockdown).list_images()['EntryList']
    for image in images:
        image['ImageSignature'] = image['ImageSignature'].hex()
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
        logging.error(f'Disk image of type: {image_type} is not mounted')


@mounter.command('umount', cls=Command)
def mounter_umount(lockdown: LockdownClient):
    """ unmount developer image. """
    image_type = 'Developer'
    mount_path = '/Developer'
    image_mounter = MobileImageMounterService(lockdown=lockdown)
    try:
        image_mounter.umount(image_type, mount_path, b'')
        logging.info('DeveloperDiskImage unmounted successfully')
    except NotMountedError:
        logging.error('DeveloperDiskImage isn\'t currently mounted')
    except UnsupportedCommandError:
        logging.error('Your iOS version doesn\'t support this command')


def download_file(url, local_filename):
    logging.debug(f'downloading: {local_filename}')
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

        # extract to the parent directory since the zip file already contains the ios version in its hierarchy
        zip_file.extractall(directory.parent)


@mounter.command('mount', cls=Command)
@click.option('-i', '--image', type=click.Path(exists=True))
@click.option('-s', '--signature', type=click.Path(exists=True))
@click.option('-x', '--xcode', type=click.Path(exists=True, dir_okay=True, file_okay=False),
              default='/Applications/Xcode.app',
              help='Xcode application path used to figure out automatically the DeveloperDiskImage path')
@click.option('-v', '--version', help='use a different DeveloperDiskImage version from the one retrieved by lockdown'
                                      'connection')
def mounter_mount(lockdown: LockdownClient, image, signature, xcode, version):
    """ mount developer image. """
    image_type = 'Developer'
    developer_disk_image_dir = None

    if image and signature:
        logging.debug('using given image and signature for mount command')
    else:
        logging.debug('trying to figure out the best suited DeveloperDiskImage')
        if version is None:
            version = lockdown.sanitized_ios_version
        image = f'{xcode}/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/{version}/DeveloperDiskImage.dmg'
        signature = f'{image}.signature'
        developer_disk_image_dir = Path(image).parent

    image = Path(image)
    signature = Path(signature)

    if not developer_disk_image_dir.exists():
        try:
            download_developer_disk_image(version, developer_disk_image_dir)
        except PermissionError:
            logging.error(f'DeveloperDiskImage could not be saved to Xcode default path ({developer_disk_image_dir}). '
                          f'Please make sure your user has the necessary permissions')
            return

    image = image.read_bytes()
    signature = signature.read_bytes()

    image_mounter = MobileImageMounterService(lockdown=lockdown)
    image_mounter.upload_image(image_type, image, signature)
    try:
        image_mounter.mount(image_type, signature)
        logging.info('DeveloperDiskImage mounted successfully')
    except AlreadyMountedError:
        logging.error('DeveloperDiskImage is already mounted')
