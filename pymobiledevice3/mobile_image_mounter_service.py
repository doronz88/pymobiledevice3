#!/usr/bin/env python
import logging

from pymobiledevice3.lockdown import LockdownClient


class MobileImageMounterService(object):
    def __init__(self, lockdown=None, service_name="com.apple.mobile.mobile_image_mounter", udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.lockdown = lockdown if lockdown else LockdownClient(udid=udid)
        self.service = self.lockdown.start_service(service_name)

    def list_images(self):
        """ Lookup mounted image by its name. """
        self.service.send_plist({'Command': 'CopyDevices'})
        return self.service.recv_plist()

    def lookup_image(self, image_type):
        """ Lookup mounted image by its name. """
        self.service.send_plist({'Command': 'LookupImage',
                                 'ImageType': image_type})

        return self.service.recv_plist()

    def umount(self, image_type, mount_path, signature):
        """ umount image. """
        self.service.send_plist({'Command': 'UnmountImage',
                                 'ImageType': image_type,
                                 'MountPath': mount_path,
                                 'ImageSignature': signature})
        return self.service.recv_plist()

    def mount(self, image_type, signature):
        """ Upload image into device. """
        self.service.send_plist({'Command': 'MountImage',
                                 'ImageType': image_type,
                                 'ImageSignature': signature})
        result = self.service.recv_plist()
        status = result.get('Status')

        if status != 'Complete':
            raise Exception(f'command MountImage failed with: {result}')

    def upload_image(self, image_type, image, signature):
        """ Upload image into device. """
        self.service.send_plist({'Command': 'ReceiveBytes',
                                 'ImageType': image_type,
                                 'ImageSize': len(image),
                                 'ImageSignature': signature})
        result = self.service.recv_plist()

        status = result.get('Status')

        if status != 'ReceiveBytesAck':
            raise Exception(f'command ReceiveBytes failed with: {result}')

        self.service.send(image)
        result = self.service.recv_plist()

        status = result.get('Status')

        if status != 'Complete':
            raise Exception(f'command ReceiveBytes failed to send bytes with: {result}')
