import plistlib
from typing import IO, cast

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class ProvisioningProfile:
    """A provisioning profile, exposing the embedded plist parsed from its raw bytes."""

    def __init__(self, buf: bytes):
        self.buf = buf

        xml = b"<?xml" + buf.split(b"<?xml", 1)[1]
        xml = xml.split(b"</plist>")[0] + b"</plist>"
        self.plist = plistlib.loads(xml)

    def __str__(self):
        return str(self.plist)


class MisagentService(LockdownService):
    """
    Manage provisioning profiles installed on the device.

    Wraps the ``com.apple.misagent`` lockdown service to install, remove and enumerate
    provisioning profiles. Being a `LockdownService`, instances may be used as an async
    context manager::

        async with MisagentService(lockdown) as misagent:
            profiles = await misagent.copy_all()
    """

    SERVICE_NAME = "com.apple.misagent"
    RSD_SERVICE_NAME = "com.apple.misagent.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def install(self, plist: IO[bytes]) -> dict:
        """
        Install a provisioning profile on the device.

        :param plist: stream whose contents are the raw provisioning profile to install;
            read in full and sent to the device.
        :returns: the device's response plist.
        :raises PyMobileDevice3Exception: if the device reports a non-zero status.
        """
        response = await self.service.send_recv_plist({
            "MessageType": "Install",
            "Profile": plist.read(),
            "ProfileType": "Provisioning",
        })
        if response["Status"]:
            raise PyMobileDevice3Exception(f"invalid status: {response}")

        return response

    async def remove(self, profile_id: str) -> dict:
        """
        Remove an installed provisioning profile.

        :param profile_id: identifier of the profile to remove.
        :returns: the device's response plist.
        :raises PyMobileDevice3Exception: if the device reports a non-zero status.
        """
        response = await self.service.send_recv_plist({
            "MessageType": "Remove",
            "ProfileID": profile_id,
            "ProfileType": "Provisioning",
        })
        if response["Status"]:
            raise PyMobileDevice3Exception(f"invalid status: {response}")

        return response

    async def copy_all(self) -> list[ProvisioningProfile]:
        """
        Retrieve all provisioning profiles installed on the device.

        :returns: list of `ProvisioningProfile` objects, one per installed profile.
        :raises PyMobileDevice3Exception: if the device reports a non-zero status.
        """
        response = await self.service.send_recv_plist({"MessageType": "CopyAll", "ProfileType": "Provisioning"})
        if response["Status"]:
            raise PyMobileDevice3Exception(f"invalid status: {response}")

        return [ProvisioningProfile(p) for p in cast(list, response["Payload"])]
