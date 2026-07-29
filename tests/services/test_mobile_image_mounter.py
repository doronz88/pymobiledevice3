import pytest

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobile_image_mounter import MobileImageMounterService


@pytest.mark.asyncio
async def test_is_image_mounted_agrees_with_copy_devices(lockdown: LockdownClient) -> None:
    # Regression: LookupImage may return an empty ImageSignature for a mounted Personalized image,
    # making is_image_mounted() miss it and a subsequent MountImage fail with "already mounted"
    async with MobileImageMounterService(lockdown=lockdown) as mounter:
        mounted_types = {device.get("DiskImageType") for device in await mounter.copy_devices()}
        for image_type in ("Developer", "Personalized"):
            assert await mounter.is_image_mounted(image_type) == (image_type in mounted_types)
