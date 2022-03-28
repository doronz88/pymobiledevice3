from typing import Optional

from pymobiledevice3.exceptions import PyMobileDevice3Exception, NotMountedError, UnsupportedCommandError, \
    AlreadyMountedError, InternalError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService


class MobileImageMounterService(BaseService):
    SERVICE_NAME = 'com.apple.mobile.mobile_image_mounter'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME)

    def list_images(self):
        """ Lookup mounted image by its name. """
        self.service.send_plist({'Command': 'CopyDevices'})
        response = self.service.recv_plist()

        if response.get('Error'):
            raise PyMobileDevice3Exception('unsupported command')

        return response

    def lookup_image(self, image_type: str) -> Optional[bytes]:
        """ Lookup mounted image by its name. """
        response = self.service.send_recv_plist({'Command': 'LookupImage',
                                                 'ImageType': image_type})

        if not response or not response.get('ImagePresent', True):
            raise NotMountedError()

        signature = response.get('ImageSignature', [])
        if isinstance(signature, list):
            if not signature:
                raise NotMountedError()
            return signature[0]
        return signature

    def is_image_mounted(self, image_type: str) -> bool:
        try:
            self.lookup_image(image_type)
            return True
        except NotMountedError:
            return False

    def umount(self, image_type, mount_path, signature):
        """ umount image. """
        self.service.send_plist({'Command': 'UnmountImage',
                                 'ImageType': image_type,
                                 'MountPath': mount_path,
                                 'ImageSignature': signature})
        response = self.service.recv_plist()
        error = response.get('Error')
        if error:
            if error == 'UnknownCommand':
                raise UnsupportedCommandError()
            elif error == 'InternalError':
                raise InternalError()
            else:
                raise NotMountedError()

    def mount(self, image_type, signature):
        """ Upload image into device. """

        if self.is_image_mounted(image_type):
            raise AlreadyMountedError()

        self.service.send_plist({'Command': 'MountImage',
                                 'ImageType': image_type,
                                 'ImageSignature': signature})
        result = self.service.recv_plist()
        status = result.get('Status')

        if status != 'Complete':
            raise PyMobileDevice3Exception(f'command MountImage failed with: {result}')

    def upload_image(self, image_type, image, signature):
        """ Upload image into device. """
        self.service.send_plist({'Command': 'ReceiveBytes',
                                 'ImageType': image_type,
                                 'ImageSize': len(image),
                                 'ImageSignature': signature})
        result = self.service.recv_plist()

        status = result.get('Status')

        if status != 'ReceiveBytesAck':
            raise PyMobileDevice3Exception(f'command ReceiveBytes failed with: {result}')

        self.service.sendall(image)
        result = self.service.recv_plist()

        status = result.get('Status')

        if status != 'Complete':
            raise PyMobileDevice3Exception(f'command ReceiveBytes failed to send bytes with: {result}')
