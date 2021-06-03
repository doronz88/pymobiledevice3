import logging
import re

import click

from pymobiledevice3.cli.cli_common import Command, print_json
from pymobiledevice3.exceptions import DeviceVersionFormatError, PyMobileDevice3Exception, NotMountedError, \
    UnsupportedCommandError
from pymobiledevice3.services.mobile_image_mounter import MobileImageMounterService


@click.group()
def cli():
    """ mounter cli """
    pass


@cli.group()
def mounter():
    """ mounter options """
    pass


@mounter.command('list', cls=Command)
@click.option('--nocolor', is_flag=True)
def mounter_list(lockdown, nocolor):
    """ list all mounted images """
    output = []

    images = MobileImageMounterService(lockdown=lockdown).list_images()['EntryList']
    for image in images:
        image['ImageSignature'] = image['ImageSignature'].hex()
        output.append(image)

    print_json(output, colored=not nocolor)


@mounter.command('lookup', cls=Command)
@click.option('--nocolor', is_flag=True)
@click.argument('image_type')
def mounter_lookup(lockdown, nocolor, image_type):
    """ lookup mounter image type """
    output = []

    signatures = MobileImageMounterService(lockdown=lockdown).lookup_image(image_type)['ImageSignature']
    for signature in signatures:
        output.append(signature.hex())

    print_json(output, colored=not nocolor)


@mounter.command('umount', cls=Command)
def mounter_umount(lockdown):
    """ unmount developer image. """
    image_type = 'Developer'
    mount_path = '/Developer'
    image_mounter = MobileImageMounterService(lockdown=lockdown)
    try:
        image_mounter.umount(image_type, mount_path, b'')
        logging.info('DeveloperDiskImage umounted successfully')
    except NotMountedError:
        logging.error('DeveloperDiskImage isn\'t currently mounted')
    except UnsupportedCommandError:
        logging.error('Your iOS version doesn\'t support this command')


def sanitize_version(version):
    try:
        return re.match(r'\d*\.\d*', version)[0]
    except TypeError as e:
        raise DeviceVersionFormatError from e


@mounter.command('mount', cls=Command)
@click.option('-i', '--image', type=click.Path(exists=True))
@click.option('-s', '--signature', type=click.Path(exists=True))
@click.option('-x', '--xcode', type=click.Path(exists=True, dir_okay=True, file_okay=False),
              default='/Applications/Xcode.app',
              help='Xcode application path used to figure out automatically the DeveloperDiskImage path')
@click.option('-v', '--version', help='use a different DeveloperDiskImage version from the one retrieved by lockdown'
                                      'connection')
def mounter_mount(lockdown, image, signature, xcode, version):
    """ mount developer image. """
    image_type = 'Developer'

    if image and signature:
        logging.debug('using given image and signature for mount command')
    else:
        logging.debug('trying to figure out the best suited DeveloperDiskImage')
        if version is None:
            version = lockdown.ios_version
        version = sanitize_version(version)
        image = f'{xcode}/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/{version}/DeveloperDiskImage.dmg'
        signature = f'{image}.signature'

    with open(image, 'rb') as image:
        image = image.read()

    with open(signature, 'rb') as signature:
        signature = signature.read()

    image_mounter = MobileImageMounterService(lockdown=lockdown)
    image_mounter.upload_image(image_type, image, signature)
    try:
        image_mounter.mount(image_type, signature)
        logging.info('DeveloperDiskImage mounted successfully')
    except PyMobileDevice3Exception as e:
        if 'is already mounted' in str(e):
            logging.error('DeveloperDiskImage is already mounted')
        else:
            raise e
