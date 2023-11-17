import hashlib
import plistlib
from pathlib import Path
from typing import List, Mapping

from developer_disk_image.repo import DeveloperDiskImageRepository
from packaging.version import Version

from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import AlreadyMountedError, DeveloperDiskImageNotFoundError, \
    DeveloperModeIsNotEnabledError, InternalError, MessageNotSupportedError, MissingManifestError, \
    NoSuchBuildIdentityError, NotMountedError, PyMobileDevice3Exception, UnsupportedCommandError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.restore.tss import TSSRequest
from pymobiledevice3.services.lockdown_service import LockdownService


class MobileImageMounterService(LockdownService):
    # implemented in /usr/libexec/mobile_storage_proxy
    SERVICE_NAME = 'com.apple.mobile.mobile_image_mounter'
    RSD_SERVICE_NAME = 'com.apple.mobile.mobile_image_mounter.shim.remote'
    IMAGE_TYPE: str = None

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    def raise_if_cannot_mount(self) -> None:
        if self.is_image_mounted(self.IMAGE_TYPE):
            raise AlreadyMountedError()
        if Version(self.lockdown.product_version).major >= 16 and not self.lockdown.developer_mode_status:
            raise DeveloperModeIsNotEnabledError()

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

    def unmount_image(self, mount_path: str) -> None:
        """ umount image (Added on iOS 14.0) """
        request = {'Command': 'UnmountImage', 'MountPath': mount_path}
        response = self.service.send_recv_plist(request)

        error = response.get('Error')
        if error:
            if error == 'UnknownCommand':
                raise UnsupportedCommandError()
            elif 'There is no matching entry' in response.get('DetailedError', ''):
                raise NotMountedError(response)
            elif error == 'InternalError':
                raise InternalError(response)
            else:
                raise PyMobileDevice3Exception(response)

    def mount_image(self, image_type: str, signature: bytes, extras: Mapping = None) -> None:
        """ Upload image into device. """

        if self.is_image_mounted(image_type):
            raise AlreadyMountedError()

        request = {'Command': 'MountImage',
                   'ImageType': image_type,
                   'ImageSignature': signature}

        if extras is not None:
            request.update(extras)
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

    def query_nonce(self, personalized_image_type: str = None) -> bytes:
        request = {'Command': 'QueryNonce'}
        if personalized_image_type is not None:
            request['PersonalizedImageType'] = personalized_image_type
        response = self.service.send_recv_plist(request)
        try:
            return response['PersonalizationNonce']
        except KeyError as e:
            raise MessageNotSupportedError from e

    def query_personalization_identifiers(self, image_type: str = None) -> Mapping:
        request = {'Command': 'QueryPersonalizationIdentifiers'}

        if image_type is not None:
            request['PersonalizedImageType'] = image_type

        response = self.service.send_recv_plist(request)

        try:
            return response['PersonalizationIdentifiers']
        except KeyError as e:
            raise MessageNotSupportedError from e

    def query_personalization_manifest(self, image_type: str, signature: bytes) -> bytes:
        response = self.service.send_recv_plist({
            'Command': 'QueryPersonalizationManifest', 'PersonalizedImageType': image_type, 'ImageType': image_type,
            'ImageSignature': signature})
        try:
            # The response "ImageSignature" is actually an IM4M
            return response['ImageSignature']
        except KeyError:
            raise MissingManifestError()

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


class DeveloperDiskImageMounter(MobileImageMounterService):
    IMAGE_TYPE = 'Developer'

    def mount(self, image: Path, signature: Path) -> None:
        self.raise_if_cannot_mount()

        image = Path(image).read_bytes()
        signature = Path(signature).read_bytes()
        self.upload_image(self.IMAGE_TYPE, image, signature)
        self.mount_image(self.IMAGE_TYPE, signature)

    def umount(self) -> None:
        self.unmount_image('/Developer')


class PersonalizedImageMounter(MobileImageMounterService):
    IMAGE_TYPE = 'Personalized'

    def mount(self, image: Path, build_manifest: Path, trust_cache: Path,
              info_plist: Mapping = None) -> None:
        self.raise_if_cannot_mount()

        image = image.read_bytes()
        trust_cache = trust_cache.read_bytes()

        # try to fetch the personalization manifest if the device already has one
        # in case of failure, the service will close the socket, so we'll have to reestablish the connection
        # and query the manifest from Apple's ticket server instead
        try:
            manifest = self.query_personalization_manifest('DeveloperDiskImage', hashlib.sha384(image).digest())
        except MissingManifestError:
            self.service = self.lockdown.start_lockdown_service(self.service_name)
            manifest = self.get_manifest_from_tss(plistlib.loads(build_manifest.read_bytes()))

        self.upload_image(self.IMAGE_TYPE, image, manifest)

        extras = {}
        if info_plist is not None:
            extras['ImageInfoPlist'] = info_plist
        extras['ImageTrustCache'] = trust_cache
        self.mount_image(self.IMAGE_TYPE, manifest, extras=extras)

    def umount(self) -> None:
        self.unmount_image('/System/Developer')

    def get_manifest_from_tss(self, build_manifest: Mapping) -> bytes:
        request = TSSRequest()

        personalization_identifiers = self.query_personalization_identifiers()
        for key, value in personalization_identifiers.items():
            if key.startswith('Ap,'):
                request.update({key: value})

        board_id = personalization_identifiers['BoardId']
        chip_id = personalization_identifiers['ChipID']

        build_identity = None
        for tmp_build_identity in build_manifest['BuildIdentities']:
            if int(tmp_build_identity['ApBoardID'], 0) == board_id and \
                    int(tmp_build_identity['ApChipID'], 0) == chip_id:
                build_identity = tmp_build_identity
                break
        else:
            raise NoSuchBuildIdentityError(f'Could not find the manifest for board {board_id} and chip {chip_id}')
        manifest = build_identity['Manifest']

        parameters = {
            'ApProductionMode': True,
            'ApSecurityDomain': 1,
            'ApSecurityMode': True,
            'ApSupportsImg4': True,
        }

        request.update({
            '@ApImg4Ticket': True,
            '@BBTicket': True,
            'ApBoardID': board_id,
            'ApChipID': chip_id,
            'ApECID': self.lockdown.ecid,
            'ApNonce': self.query_nonce('DeveloperDiskImage'),
            'ApProductionMode': True,
            'ApSecurityDomain': 1,
            'ApSecurityMode': True,
            'SepNonce': b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            'UID_MODE': False,
        })

        for key, manifest_entry in manifest.items():
            info_dict = manifest_entry.get('Info')
            if info_dict is None:
                continue

            if not manifest_entry.get('Trusted', False):
                self.logger.debug(f'skipping {key} as it is not trusted')
                continue

            # copy this entry
            tss_entry = dict(manifest_entry)

            # remove obsolete Info node
            tss_entry.pop('Info')

            # handle RestoreRequestRules
            if 'RestoreRequestRules' in manifest['LoadableTrustCache']['Info']:
                rules = manifest['LoadableTrustCache']['Info']['RestoreRequestRules']
                if rules:
                    self.logger.debug(f'Applying restore request rules for entry {key}')
                    tss_entry = request.apply_restore_request_rules(tss_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            if manifest_entry.get('Digest') is None:
                tss_entry['Digest'] = b''

            request.update({key: tss_entry})

        response = request.send_receive()
        return response['ApImg4Ticket']


def auto_mount_developer(lockdown: LockdownServiceProvider, xcode: str = None, version: str = None) -> None:
    """ auto-detect correct DeveloperDiskImage and mount it """
    if xcode is None:
        # avoid "default"-ing this option, because Windows and Linux won't have this path
        xcode = Path('/Applications/Xcode.app')
        if not (xcode.exists()):
            xcode = get_home_folder() / 'Xcode.app'
            xcode.mkdir(parents=True, exist_ok=True)

    image_mounter = DeveloperDiskImageMounter(lockdown=lockdown)
    if image_mounter.is_image_mounted('Developer'):
        raise AlreadyMountedError()

    if version is None:
        version = Version(lockdown.product_version)
        version = f'{version.major}.{version.minor}'
    image_dir = f'{xcode}/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/{version}'
    image_path = f'{image_dir}/DeveloperDiskImage.dmg'
    signature = f'{image_path}.signature'
    developer_disk_image_dir = Path(image_path).parent

    image_path = Path(image_path)
    signature = Path(signature)

    if not image_path.exists():
        # download the DeveloperDiskImage from our repository
        repo = DeveloperDiskImageRepository.create()
        developer_disk_image = repo.get_developer_disk_image(version)

        if developer_disk_image is None:
            raise DeveloperDiskImageNotFoundError()

        # write it filesystem
        developer_disk_image_dir.mkdir(exist_ok=True, parents=True)
        image_path.write_bytes(developer_disk_image.image)
        signature.write_bytes(developer_disk_image.signature)

    image_mounter.mount(image_path, signature)


def auto_mount_personalized(lockdown: LockdownServiceProvider) -> None:
    local_path = get_home_folder() / 'Xcode_iOS_DDI_Personalized'
    local_path.mkdir(parents=True, exist_ok=True)

    image = local_path / 'Image.dmg'
    build_manifest = local_path / 'BuildManifest.plist'
    trustcache = local_path / 'Image.trustcache'

    if not image.exists():
        # download the Personalized image from our repository
        repo = DeveloperDiskImageRepository.create()
        personalized_image = repo.get_personalized_disk_image()

        image.write_bytes(personalized_image.image)
        build_manifest.write_bytes(personalized_image.build_manifest)
        trustcache.write_bytes(personalized_image.trustcache)

    PersonalizedImageMounter(lockdown=lockdown).mount(image, build_manifest, trustcache)


def auto_mount(lockdown: LockdownServiceProvider, xcode: str = None, version: str = None) -> None:
    if Version(lockdown.product_version) < Version('17.0'):
        auto_mount_developer(lockdown, xcode=xcode, version=version)
    else:
        auto_mount_personalized(lockdown)
