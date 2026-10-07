from typing import Any, Optional

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class StorageMounterBridgeError(PyMobileDevice3Exception):
    """The storage mounter bridge answered a command with an error."""

    def __init__(self, command: str, error: str, detailed_error: Optional[str] = None) -> None:
        super().__init__(f"{command} failed: {error}" + (f" ({detailed_error})" if detailed_error else ""))
        #: The device's error code, e.g. ``UnknownCommand`` or ``InternalError``.
        self.error = error
        #: The underlying ``NSError`` description, when the device supplied one.
        self.detailed_error = detailed_error


class StorageMounterBridgeService(RemoteService):
    """
    Query the device's image mounter over RemoteXPC (``com.apple.mobile.storage_mounter_proxy.bridge``).

    This is the RemoteXPC face of ``mobile_storage_proxy``, the daemon behind
    `MobileImageMounterService`. It takes the same commands, wrapped as
    ``{"XPCRequestDictionary": {"Command": <name>, ...}}``, and answers with the reply keys at the top
    level. Everything it reports is also available through `MobileImageMounterService`, which is the
    one to use for mounting; the read-only queries are wrapped here and `invoke` reaches the rest.

    Requires an RSD tunnel. Verified on iOS 27.2. Use as an async context manager.
    """

    SERVICE_NAME = "com.apple.mobile.storage_mounter_proxy.bridge"

    def __init__(self, rsd: RemoteServiceDiscoveryService) -> None:
        """
        :param rsd: RSD provider used to open the RemoteXPC service.
        """
        super().__init__(rsd, self.SERVICE_NAME)

    async def invoke(self, command: str, **arguments: Any) -> dict[str, Any]:
        """
        Send a command and return its reply.

        :param command: command name, e.g. ``CopyDevices``.
        :param arguments: the command's arguments, sent alongside it.
        :raises StorageMounterBridgeError: if the reply carries an ``Error``.
        """
        request: dict[str, Any] = {"Command": command, "HostProcessName": "pymobiledevice3", **arguments}
        response = await self.service.send_receive_request({"XPCRequestDictionary": request})
        error = response.get("Error")
        if error is not None:
            raise StorageMounterBridgeError(command, error, response.get("DetailedError"))
        return response

    async def copy_devices(self) -> list[dict[str, Any]]:
        """List the mounted images, as `MobileImageMounterService.copy_devices` does."""
        return (await self.invoke("CopyDevices"))["EntryList"]

    async def lookup_image(self, image_type: str) -> list[bytes]:
        """
        Get the signatures of the mounted images of a type.

        :param image_type: e.g. ``Personalized`` or ``Developer``.
        """
        return (await self.invoke("LookupImage", ImageType=image_type))["ImageSignature"]

    async def query_developer_mode_status(self) -> bool:
        """Whether Developer Mode is enabled."""
        return (await self.invoke("QueryDeveloperModeStatus"))["DeveloperModeStatus"]

    async def query_personalization_identifiers(self, image_type: Optional[str] = None) -> dict[str, Any]:
        """
        Get the identifiers a personalized image must be signed for (board, chip, ECID...).

        :param image_type: personalized image type, e.g. ``DeveloperDiskImage``.
        """
        arguments = {} if image_type is None else {"PersonalizedImageType": image_type}
        return (await self.invoke("QueryPersonalizationIdentifiers", **arguments))["PersonalizationIdentifiers"]

    async def query_nonce(self, image_type: Optional[str] = None) -> bytes:
        """
        Get the personalization nonce a signing request must carry.

        :param image_type: personalized image type, e.g. ``DeveloperDiskImage``.
        """
        arguments = {} if image_type is None else {"PersonalizedImageType": image_type}
        return (await self.invoke("QueryNonce", **arguments))["PersonalizationNonce"]
