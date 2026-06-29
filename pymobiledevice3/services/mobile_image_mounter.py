import hashlib
import logging
import plistlib
from pathlib import Path
from typing import Optional

from developer_disk_image.repo import DeveloperDiskImageRepository
from packaging.version import Version

from pymobiledevice3.common import get_home_folder
from pymobiledevice3.exceptions import (
    AlreadyMountedError,
    ConnectionTerminatedError,
    DeveloperDiskImageNotFoundError,
    DeveloperModeIsNotEnabledError,
    InternalError,
    MessageNotSupportedError,
    MissingManifestError,
    NoSuchBuildIdentityError,
    NotMountedError,
    PyMobileDevice3Exception,
    UnsupportedCommandError,
)
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.restore.tss import TSSRequest
from pymobiledevice3.services.lockdown_service import LockdownService

logger = logging.getLogger(__name__)

LATEST_DDI_BUILD_ID = "27A5194q"


class MobileImageMounterService(LockdownService):
    """
    Client for the ``com.apple.mobile.mobile_image_mounter`` lockdown service.

    Provides the low-level operations for mounting and unmounting disk images (such as the
    Developer Disk Image) on a device: looking up mounted images, uploading image bytes, mounting
    and unmounting, and the personalization queries used for personalized images. Subclasses
    specialize the behavior for a specific image type via `IMAGE_TYPE`.

    Implemented device-side in ``/usr/libexec/mobile_storage_proxy``.
    """

    # implemented in /usr/libexec/mobile_storage_proxy
    SERVICE_NAME = "com.apple.mobile.mobile_image_mounter"
    RSD_SERVICE_NAME = "com.apple.mobile.mobile_image_mounter.shim.remote"
    IMAGE_TYPE: Optional[str] = None

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def _send_recv(self, request: dict) -> dict:
        return await self.service.send_recv_plist(request)

    async def raise_if_cannot_mount(self) -> None:
        """
        Verify that an image of this mounter's `IMAGE_TYPE` can be mounted.

        :raises AlreadyMountedError: If an image of this type is already mounted.
        :raises DeveloperModeIsNotEnabledError: On iOS 16 and later when Developer Mode is disabled.
        """
        if await self.is_image_mounted(self.IMAGE_TYPE):
            raise AlreadyMountedError()
        if Version(self.lockdown.product_version).major >= 16 and not await self.lockdown.get_developer_mode_status():
            raise DeveloperModeIsNotEnabledError()

    async def copy_devices(self) -> list[dict]:
        """
        List the images currently mounted on the device.

        :returns: List of dictionaries, one per mounted image entry.
        :raises MessageNotSupportedError: If the device does not support the ``CopyDevices`` command.
        """
        try:
            return (await self._send_recv({"Command": "CopyDevices"}))["EntryList"]
        except KeyError as e:
            raise MessageNotSupportedError from e

    async def lookup_image(self, image_type: str) -> bytes:
        """
        Look up the signature of a mounted image by its type.

        :param image_type: Image type to look up (e.g. ``Developer`` or ``Personalized``).
        :returns: The image signature. If the device returns a list of signatures, the first is
            returned.
        :raises NotMountedError: If no image of this type is present.
        """
        response = await self._send_recv({"Command": "LookupImage", "ImageType": image_type})

        if not response or not response.get("ImagePresent", True):
            raise NotMountedError()

        signature = response.get("ImageSignature", [])
        if isinstance(signature, list):
            if not signature:
                raise NotMountedError()
            return signature[0]
        return signature

    async def is_image_mounted(self, image_type: str) -> bool:
        """
        Check whether an image of the given type is mounted.

        :param image_type: Image type to check (e.g. ``Developer`` or ``Personalized``).
        :returns: ``True`` if an image of this type is mounted, ``False`` otherwise.
        """
        try:
            await self.lookup_image(image_type)
        except NotMountedError:
            return False
        return True

    async def unmount_image(self, mount_path: str) -> None:
        """
        Unmount the image mounted at a given path (available since iOS 14.0).

        :param mount_path: Mount point of the image to unmount (e.g. ``/Developer``).
        :raises UnsupportedCommandError: If the device does not support the ``UnmountImage`` command.
        :raises NotMountedError: If no image is mounted at ``mount_path``.
        :raises InternalError: If the device reports an internal error.
        :raises PyMobileDevice3Exception: For any other error reported by the device.
        """
        request = {"Command": "UnmountImage", "MountPath": mount_path}
        response = await self._send_recv(request)

        error = response.get("Error")
        if error:
            if error == "UnknownCommand":
                raise UnsupportedCommandError()
            elif "There is no matching entry" in response.get("DetailedError", ""):
                raise NotMountedError(response)
            elif error == "InternalError":
                raise InternalError(response)
            else:
                raise PyMobileDevice3Exception(response)

    async def mount_image(self, image_type: str, signature: bytes, extras: Optional[dict] = None) -> None:
        """
        Mount an image that has already been uploaded to the device.

        :param image_type: Image type to mount (e.g. ``Developer`` or ``Personalized``).
        :param signature: Image signature (or, for personalized images, the IM4M manifest).
        :param extras: Optional additional fields merged into the ``MountImage`` request, such as
            ``ImageTrustCache`` and ``ImageInfoPlist`` for personalized images.
        :raises AlreadyMountedError: If an image of this type is already mounted.
        :raises DeveloperModeIsNotEnabledError: If the device reports Developer Mode is disabled.
        :raises PyMobileDevice3Exception: If the mount does not complete successfully.
        """

        if await self.is_image_mounted(image_type):
            raise AlreadyMountedError()

        request = {"Command": "MountImage", "ImageType": image_type, "ImageSignature": signature}

        if extras is not None:
            request.update(extras)
        response = await self._send_recv(request)

        if "Developer mode is not enabled" in response.get("DetailedError", ""):
            raise DeveloperModeIsNotEnabledError()

        status = response.get("Status")

        if status != "Complete":
            raise PyMobileDevice3Exception(f"command MountImage failed with: {response}")

    async def upload_image(self, image_type: str, image: bytes, signature: bytes) -> None:
        """
        Upload image bytes to the device in preparation for mounting.

        Issues a ``ReceiveBytes`` command, streams the image bytes once the device acknowledges, and
        waits for completion.

        :param image_type: Image type being uploaded (e.g. ``Developer`` or ``Personalized``).
        :param image: Raw image bytes to upload.
        :param signature: Image signature (or, for personalized images, the IM4M manifest).
        :raises PyMobileDevice3Exception: If the device does not acknowledge or does not complete
            the transfer.
        """
        result = await self.service.send_recv_plist({
            "Command": "ReceiveBytes",
            "ImageType": image_type,
            "ImageSize": len(image),
            "ImageSignature": signature,
        })

        status = result.get("Status")

        if status != "ReceiveBytesAck":
            raise PyMobileDevice3Exception(f"command ReceiveBytes failed with: {result}")

        await self.service.sendall(image)
        result = await self.service.recv_plist()

        status = result.get("Status")

        if status != "Complete":
            raise PyMobileDevice3Exception(f"command ReceiveBytes failed to send bytes with: {result}")

    async def query_developer_mode_status(self) -> bool:
        """
        Query whether Developer Mode is enabled on the device.

        :returns: ``True`` if Developer Mode is enabled, ``False`` otherwise.
        :raises MessageNotSupportedError: If the device does not support this command.
        """
        response = await self._send_recv({"Command": "QueryDeveloperModeStatus"})

        try:
            return response["DeveloperModeStatus"]
        except KeyError as e:
            raise MessageNotSupportedError from e

    async def query_nonce(self, personalized_image_type: Optional[str] = None) -> bytes:
        """
        Query the personalization nonce used for image personalization.

        :param personalized_image_type: Optional image type to scope the nonce to, sent as
            ``PersonalizedImageType``.
        :returns: The personalization nonce bytes.
        :raises MessageNotSupportedError: If the device does not support this command.
        """
        request = {"Command": "QueryNonce"}
        if personalized_image_type is not None:
            request["PersonalizedImageType"] = personalized_image_type
        response = await self._send_recv(request)
        try:
            return response["PersonalizationNonce"]
        except KeyError as e:
            raise MessageNotSupportedError from e

    async def query_personalization_identifiers(self, image_type: Optional[str] = None) -> dict:
        """
        Query the device identifiers required to personalize an image (board ID, chip ID, etc.).

        :param image_type: Optional image type to scope the query to, sent as
            ``PersonalizedImageType``.
        :returns: Mapping of personalization identifiers reported by the device.
        :raises MessageNotSupportedError: If the device does not support this command.
        """
        request = {"Command": "QueryPersonalizationIdentifiers"}

        if image_type is not None:
            request["PersonalizedImageType"] = image_type

        response = await self._send_recv(request)

        try:
            return response["PersonalizationIdentifiers"]
        except KeyError as e:
            raise MessageNotSupportedError from e

    async def query_personalization_manifest(self, image_type: str, signature: bytes) -> bytes:
        """
        Fetch a personalization manifest already stored on the device for an image.

        :param image_type: Image type whose manifest is requested.
        :param signature: Signature/digest of the image being queried.
        :returns: The personalization manifest, returned by the device under ``ImageSignature`` but
            actually an IM4M.
        :raises MissingManifestError: If the device has no manifest for the image.
        """
        response = await self._send_recv({
            "Command": "QueryPersonalizationManifest",
            "PersonalizedImageType": image_type,
            "ImageType": image_type,
            "ImageSignature": signature,
        })
        try:
            # The response "ImageSignature" is actually an IM4M
            return response["ImageSignature"]
        except KeyError as e:
            raise MissingManifestError() from e

    async def roll_personalization_nonce(self) -> None:
        """
        Request the device to roll (regenerate) its personalization nonce.

        The device may close the connection while handling this command; a resulting
        `ConnectionTerminatedError` is swallowed and treated as success.
        """
        try:
            await self._send_recv({"Command": "RollPersonalizationNonce"})
        except ConnectionTerminatedError:
            return

    async def roll_cryptex_nonce(self) -> None:
        """
        Request the device to roll (regenerate) its cryptex nonce.

        The device may close the connection while handling this command; a resulting
        `ConnectionTerminatedError` is swallowed and treated as success.
        """
        try:
            await self._send_recv({"Command": "RollCryptexNonce"})
        except ConnectionTerminatedError:
            return


class DeveloperDiskImageMounter(MobileImageMounterService):
    """Mounter for the classic (pre-iOS 17) ``Developer`` Disk Image."""

    IMAGE_TYPE = "Developer"

    async def mount(self, image: Path, signature: Path) -> None:
        """
        Upload and mount a Developer Disk Image.

        :param image: Path to the ``.dmg`` image file.
        :param signature: Path to the image's signature file.
        :raises AlreadyMountedError: If a Developer image is already mounted.
        :raises DeveloperModeIsNotEnabledError: On iOS 16+ when Developer Mode is disabled.
        """
        await self.raise_if_cannot_mount()

        image = Path(image).read_bytes()
        signature = Path(signature).read_bytes()
        await self.upload_image(self.IMAGE_TYPE, image, signature)
        await self.mount_image(self.IMAGE_TYPE, signature)

    async def umount(self) -> None:
        """Unmount the Developer Disk Image (mounted at ``/Developer``)."""
        await self.unmount_image("/Developer")


class PersonalizedImageMounter(MobileImageMounterService):
    """Mounter for the ``Personalized`` Developer Disk Image used on iOS 17 and later."""

    IMAGE_TYPE = "Personalized"

    async def mount(
        self, image: Path, build_manifest: Path, trust_cache: Path, info_plist: Optional[dict] = None
    ) -> None:
        """
        Upload and mount a personalized Developer Disk Image.

        Attempts to reuse a personalization manifest already stored on the device; if none exists,
        reconnects and requests a fresh ticket from Apple's TSS server based on ``build_manifest``.

        :param image: Path to the ``.dmg`` image file.
        :param build_manifest: Path to the ``BuildManifest.plist`` used to request a TSS ticket.
        :param trust_cache: Path to the image's loadable trust cache.
        :param info_plist: Optional image info plist sent as ``ImageInfoPlist``.
        :raises AlreadyMountedError: If a Personalized image is already mounted.
        :raises DeveloperModeIsNotEnabledError: If Developer Mode is disabled.
        """
        await self.raise_if_cannot_mount()

        image = image.read_bytes()
        trust_cache = trust_cache.read_bytes()

        # try to fetch the personalization manifest if the device already has one
        # in case of failure, the service will close the socket, so we'll have to reestablish the connection
        # and query the manifest from Apple's ticket server instead
        try:
            manifest = await self.query_personalization_manifest("DeveloperDiskImage", hashlib.sha384(image).digest())
        except MissingManifestError:
            self._service = await self.lockdown.start_lockdown_service(self.service_name)
            manifest = await self.get_manifest_from_tss(plistlib.loads(build_manifest.read_bytes()))

        await self.upload_image(self.IMAGE_TYPE, image, manifest)

        extras = {}
        if info_plist is not None:
            extras["ImageInfoPlist"] = info_plist
        extras["ImageTrustCache"] = trust_cache
        await self.mount_image(self.IMAGE_TYPE, manifest, extras=extras)

    async def umount(self) -> None:
        """Unmount the Personalized Developer Disk Image (mounted at ``/System/Developer``)."""
        await self.unmount_image("/System/Developer")

    async def get_manifest_from_tss(self, build_manifest: dict) -> bytes:
        """
        Request an IM4M personalization manifest from Apple's TSS server.

        Selects the build identity in ``build_manifest`` matching the device's board and chip IDs,
        builds a TSS request from the device's personalization identifiers and nonce, and submits it.

        :param build_manifest: Parsed ``BuildManifest.plist`` contents.
        :returns: The signed IM4M ticket (``ApImg4Ticket``) returned by the TSS server.
        :raises NoSuchBuildIdentityError: If no build identity matches the device's board and chip IDs.
        """
        request = TSSRequest()

        personalization_identifiers = await self.query_personalization_identifiers()
        for key, value in personalization_identifiers.items():
            if key.startswith("Ap,"):
                request.update({key: value})

        board_id = personalization_identifiers["BoardId"]
        chip_id = personalization_identifiers["ChipID"]

        build_identity = None
        for tmp_build_identity in build_manifest["BuildIdentities"]:
            if (
                int(tmp_build_identity["ApBoardID"], 0) == board_id
                and int(tmp_build_identity["ApChipID"], 0) == chip_id
            ):
                build_identity = tmp_build_identity
                break
        else:
            raise NoSuchBuildIdentityError(f"Could not find the manifest for board {board_id} and chip {chip_id}")
        manifest = build_identity["Manifest"]

        parameters = {
            "ApProductionMode": True,
            "ApSecurityDomain": 1,
            "ApSecurityMode": True,
            "ApSupportsImg4": True,
        }

        request.update({
            "@ApImg4Ticket": True,
            "@BBTicket": True,
            "ApBoardID": board_id,
            "ApChipID": chip_id,
            "ApECID": self.lockdown.ecid,
            "ApNonce": await self.query_nonce("DeveloperDiskImage"),
            "ApProductionMode": True,
            "ApSecurityDomain": 1,
            "ApSecurityMode": True,
            "SepNonce": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            "UID_MODE": False,
        })

        for key, manifest_entry in manifest.items():
            info_dict = manifest_entry.get("Info")
            if info_dict is None:
                continue

            if not manifest_entry.get("Trusted", False):
                self.logger.debug(f"skipping {key} as it is not trusted")
                continue

            # copy this entry
            tss_entry = dict(manifest_entry)

            # remove obsolete Info node
            tss_entry.pop("Info")

            # handle RestoreRequestRules
            if "RestoreRequestRules" in manifest["LoadableTrustCache"]["Info"]:
                rules = manifest["LoadableTrustCache"]["Info"]["RestoreRequestRules"]
                if rules:
                    self.logger.debug(f"Applying restore request rules for entry {key}")
                    tss_entry = request.apply_restore_request_rules(tss_entry, parameters, rules)

            # Make sure we have a Digest key for Trusted items even if empty
            if manifest_entry.get("Digest") is None:
                tss_entry["Digest"] = b""

            request.update({key: tss_entry})

        response = await request.send_receive()
        return response["ApImg4Ticket"]


async def auto_mount_developer(
    lockdown: LockdownServiceProvider, xcode: Optional[str] = None, version: Optional[str] = None
) -> None:
    """
    Auto-detect, downloading if needed, and mount the classic Developer Disk Image.

    Resolves the image under the given Xcode installation for the device's iOS version; if it is not
    present locally, downloads the matching image from the bundled developer disk image repository
    before mounting.

    :param lockdown: Lockdown service provider for the target device.
    :param xcode: Path to the Xcode app bundle to source images from. Defaults to
        ``/Applications/Xcode.app`` or a created ``Xcode.app`` under the home folder.
    :param version: iOS version (``major.minor``) to select the image for. Defaults to the device's
        product version.
    :raises AlreadyMountedError: If a Developer image is already mounted.
    :raises DeveloperDiskImageNotFoundError: If no matching image is available in the repository.
    """
    if xcode is None:
        # avoid "default"-ing this option, because Windows and Linux won't have this path
        xcode = Path("/Applications/Xcode.app")
        if not (xcode.exists()):
            xcode = get_home_folder() / "Xcode.app"
            xcode.mkdir(parents=True, exist_ok=True)

    image_mounter = DeveloperDiskImageMounter(lockdown=lockdown)
    if await image_mounter.is_image_mounted("Developer"):
        raise AlreadyMountedError()

    if version is None:
        version = Version(lockdown.product_version)
        version = f"{version.major}.{version.minor}"
    image_dir = f"{xcode}/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/{version}"
    image_path = f"{image_dir}/DeveloperDiskImage.dmg"
    signature = f"{image_path}.signature"
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

    await image_mounter.mount(image_path, signature)


async def auto_mount_personalized(lockdown: LockdownServiceProvider) -> None:
    """
    Download (if needed) and mount the Personalized Developer Disk Image.

    Caches the image, build manifest and trust cache under the home folder, re-downloading them from
    the bundled repository when missing or when the cached build id does not match
    `LATEST_DDI_BUILD_ID`, then mounts them via `PersonalizedImageMounter`.

    :param lockdown: Lockdown service provider for the target device.
    """
    local_path = get_home_folder() / "Xcode_iOS_DDI_Personalized"
    local_path.mkdir(parents=True, exist_ok=True)

    image = local_path / "Image.dmg"
    build_manifest = local_path / "BuildManifest.plist"
    trustcache = local_path / "Image.trustcache"

    if (
        not build_manifest.exists()
        or plistlib.loads(build_manifest.read_bytes()).get("ProductBuildVersion") != LATEST_DDI_BUILD_ID
    ):
        # download the Personalized image from our repository
        repo = DeveloperDiskImageRepository.create()
        personalized_image = repo.get_personalized_disk_image()

        image.write_bytes(personalized_image.image)
        build_manifest.write_bytes(personalized_image.build_manifest)
        trustcache.write_bytes(personalized_image.trustcache)
        downloaded_ddi_build_id = plistlib.loads(personalized_image.build_manifest).get("ProductBuildVersion")
        if downloaded_ddi_build_id != LATEST_DDI_BUILD_ID:
            logger.warning(
                "Downloaded personalized image has unexpected ProductBuildVersion "
                f"{downloaded_ddi_build_id}. Please update pymobiledevice3!"
            )

    await PersonalizedImageMounter(lockdown=lockdown).mount(image, build_manifest, trustcache)


async def auto_mount(
    lockdown: LockdownServiceProvider, xcode: Optional[str] = None, version: Optional[str] = None
) -> None:
    """
    Auto-mount the appropriate Developer Disk Image for the device's iOS version.

    Dispatches to `auto_mount_developer` for iOS versions below 17.0 and to
    `auto_mount_personalized` for iOS 17.0 and later.

    :param lockdown: Lockdown service provider for the target device.
    :param xcode: Path to the Xcode app bundle, forwarded to `auto_mount_developer`.
    :param version: iOS version override, forwarded to `auto_mount_developer`.
    """
    if Version(lockdown.product_version) < Version("17.0"):
        await auto_mount_developer(lockdown, xcode=xcode, version=version)
    else:
        await auto_mount_personalized(lockdown)
