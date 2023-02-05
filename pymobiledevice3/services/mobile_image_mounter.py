from typing import List, Mapping

from pymobiledevice3.exceptions import AlreadyMountedError, DeveloperModeIsNotEnabledError, InternalError, \
    MessageNotSupportedError, NotMountedError, PyMobileDevice3Exception, UnsupportedCommandError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService


class MobileImageMounterService(BaseService):
    SERVICE_NAME = 'com.apple.mobile.mobile_image_mounter'

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME)

    def copy_devices(self) -> List[Mapping]:
        """ Copy mounted devices list. """
        try:
            return self.service.send_recv_plist({'Command': 'CopyDevices'})['EntryList']
        except KeyError as e:
            raise MessageNotSupportedError from e

    def lookup_image(self, image_type: str) -> bytes:
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

    def umount(self, mount_path: str, image_type: str = None, signature: bytes = None) -> None:
        """ umount image. """
        request = {'Command': 'UnmountImage', 'MountPath': mount_path}

        if image_type is not None:
            request['ImageType'] = image_type

        if signature is not None:
            request['ImageSignature'] = signature

        response = self.service.send_recv_plist(request)

        error = response.get('Error')
        if error:
            if error == 'UnknownCommand':
                raise UnsupportedCommandError()
            elif error == 'InternalError':
                raise InternalError()
            else:
                raise NotMountedError()

    def mount(self, image_type: str, signature: bytes, trust_cache: bytes = None, info_plist: Mapping = None) -> None:
        """ Upload image into device. """

        if self.is_image_mounted(image_type):
            raise AlreadyMountedError()

        request = {'Command': 'MountImage',
                   'ImageType': image_type,
                   'ImageSignature': signature}

        if image_type == 'Cryptex':
            if trust_cache is None:
                raise ValueError('Cryptex image requires a ImageTrustCache to be also supplied')

            if info_plist is None:
                raise ValueError('Cryptex image requires a ImageInfoPlist to be also supplied')

            request['ImageTrustCache'] = trust_cache
            request['ImageInfoPlist'] = info_plist

        response = self.service.send_recv_plist(request)

        if 'Developer mode is not enabled' in response.get('DetailedError', ''):
            raise DeveloperModeIsNotEnabledError()

        status = response.get('Status')

        if status != 'Complete':
            raise PyMobileDevice3Exception(f'command MountImage failed with: {response}')

    def upload_image(self, image_type: str, image: bytes, signature: bytes) -> None:
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

    def query_developer_mode_status(self) -> bool:
        response = self.service.send_recv_plist({'Command': 'QueryDeveloperModeStatus'})

        try:
            return response['DeveloperModeStatus']
        except KeyError as e:
            raise MessageNotSupportedError from e

    def query_nonce(self) -> bytes:
        response = self.service.send_recv_plist({'Command': 'QueryNonce'})

        try:
            return response['PersonalizationNonce']
        except KeyError as e:
            raise MessageNotSupportedError from e

    def query_personalization_identifiers(self, image_type: str = None) -> bytes:
        request = {'Command': 'QueryPersonalizationIdentifiers'}

        if image_type is not None:
            request['PersonalizedImageType'] = image_type

        response = self.service.send_recv_plist(request)

        try:
            return response['PersonalizationIdentifiers']
        except KeyError as e:
            raise MessageNotSupportedError from e

    def query_personalization_manifest(self, image_type: str, signature: bytes) -> Mapping:
        request = {'Command': 'QueryPersonalizationManifest', 'PersonalizedImageType': image_type,
                   'ImageType': image_type, 'ImageSignature': signature}

        response = self.service.send_recv_plist(request)

        try:
            # The response is returned as "ImageSignature" which is wrong, but that's what Apple does
            return response['ImageSignature']
        except KeyError as e:
            raise MessageNotSupportedError from e

    def roll_personalization_nonce(self) -> None:
        try:
            self.service.send_recv_plist({'Command': 'RollPersonalizationNonce'})
        except ConnectionAbortedError:
            return

    def roll_cryptex_nonce(self) -> None:
        try:
            self.service.send_recv_plist({'Command': 'RollCryptexNonce'})
        except ConnectionAbortedError:
            return
