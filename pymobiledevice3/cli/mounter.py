from pprint import pprint
import logging

import click

from pymobiledevice3.cli.cli_common import Command
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
def mounter_list(lockdown):
    """ lookup mounter image type """
    pprint(MobileImageMounterService(lockdown=lockdown).list_images())


@mounter.command('lookup', cls=Command)
@click.argument('image_type')
def mounter_lookup(lockdown, image_type):
    """ lookup mounter image type """
    pprint(MobileImageMounterService(lockdown=lockdown).lookup_image(image_type))


@mounter.command('umount', cls=Command)
def mounter_umount(lockdown):
    """ unmount developer image. """
    image_type = 'Developer'
    mount_path = '/Developer'
    image_mounter = MobileImageMounterService(lockdown=lockdown)
    image_mounter.umount(image_type, mount_path, b'')


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
        logging.info('using given image and signature for mount command')
    else:
        logging.info('trying to figure out the best suited DeveloperDiskImage')
        if version is None:
            version = lockdown.ios_version
        image = f'{xcode}/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/{version}/DeveloperDiskImage.dmg'
        signature = f'{image}.signature'

    with open(image, 'rb') as image:
        image = image.read()

    with open(signature, 'rb') as signature:
        signature = signature.read()

    image_mounter = MobileImageMounterService(lockdown=lockdown)
    image_mounter.upload_image(image_type, image, signature)
    image_mounter.mount(image_type, signature)
