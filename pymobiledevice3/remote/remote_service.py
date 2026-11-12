import logging
from typing import Any, Optional

from pymobiledevice3.exceptions import (
    DeveloperDiskImageServiceError,
    InvalidServiceError,
    NotConnectedError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.remote.ddi_services import DDI_SERVICES, ddi_includes
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.services.mobile_image_mounter import LATEST_DDI_BUILD_ID, PersonalizedImageMounter

DDI_MOUNT_PATH = "/System/Developer"


async def _mounted_ddi_build(rsd: RemoteServiceDiscoveryService) -> Optional[str]:
    """Build id of the mounted DeveloperDiskImage: ``None`` if none is mounted, ``""`` if unreported."""
    async with PersonalizedImageMounter(lockdown=rsd) as mounter:
        images = await mounter.copy_devices()
    for image in images:
        if image.get("MountPath") == DDI_MOUNT_PATH:
            version_info: dict[str, Any] = image.get("PersonalizedImageVersionInfo") or {}
            return str(version_info.get("ProductBuildVersion") or "")
    return None


async def _explain_missing_service(
    rsd: RemoteServiceDiscoveryService, service_name: str, error: InvalidServiceError
) -> InvalidServiceError:
    """Turn the error for a service the device does not offer into one that says why, where that is known."""
    if service_name not in DDI_SERVICES:
        return error
    first_build, last_build = DDI_SERVICES[service_name]
    try:
        mounted_build = await _mounted_ddi_build(rsd)
    except (PyMobileDevice3Exception, OSError):
        # Could not tell what is mounted: the plain error is still true
        return error
    return DeveloperDiskImageServiceError(
        service_name,
        mounted_build,
        ddi_includes(service_name, mounted_build) if mounted_build else None,
        first_build,
        last_build,
        LATEST_DDI_BUILD_ID,
        rsd.udid,
        rsd.product_version,
    )


async def require_service(rsd: RemoteServiceDiscoveryService, service_name: str) -> None:
    """
    Verify the device offers a service, without connecting to it.

    For a caller that would otherwise find out late, or swallow the failure: raises what
    `RemoteService.connect` would.

    :raises DeveloperDiskImageServiceError: if the device does not offer the service and it is
        one its DeveloperDiskImage provides; says which DDI, if any, is mounted.
    :raises InvalidServiceError: if the device does not offer the service.
    """
    try:
        rsd.get_service_port(service_name)
    except InvalidServiceError as e:
        explained = await _explain_missing_service(rsd, service_name, e)
        if explained is e:
            raise
        raise explained from e


class RemoteService:
    def __init__(self, rsd: RemoteServiceDiscoveryService, service_name: str):
        self.service_name = service_name
        self.rsd = rsd
        self._service: Optional[RemoteXPCConnection] = None
        self.logger = logging.getLogger(self.__module__)

    @property
    def service(self) -> RemoteXPCConnection:
        """The underlying RemoteXPC connection.

        :raises NotConnectedError: if accessed before ``connect()`` (or ``async with``) has run.
        """
        if self._service is None:
            raise NotConnectedError(f"{type(self).__name__} is not connected; call connect() first.")
        return self._service

    async def connect(self) -> None:
        """
        Connect to the service.

        :raises DeveloperDiskImageServiceError: if the device does not offer the service and it is
            one its DeveloperDiskImage provides; says which DDI, if any, is mounted.
        :raises InvalidServiceError: if the device does not offer the service.
        """
        try:
            self._service = self.rsd.start_remote_service(self.service_name)
        except InvalidServiceError as e:
            explained = await _explain_missing_service(self.rsd, self.service_name, e)
            if explained is e:
                raise
            raise explained from e
        await self._service.connect()

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        await self.close()

    async def close(self) -> None:
        # Tolerant of never-connected instances (e.g. connect() raised inside __aenter__).
        if self._service is not None:
            await self._service.close()
