import plistlib
from io import BytesIO

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.lockdown_service import LockdownService


class ProvisioningProfile:
    def __init__(self, buf: bytes):
        self.buf = buf

        xml = b"<?xml" + buf.split(b"<?xml", 1)[1]
        xml = xml.split(b"</plist>")[0] + b"</plist>"
        self.plist = plistlib.loads(xml)

    def __str__(self):
        return str(self.plist)


class MisagentService(LockdownService):
    SERVICE_NAME = "com.apple.misagent"
    RSD_SERVICE_NAME = "com.apple.misagent.shim.remote"

    def __init__(self, lockdown: LockdownClient):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    async def install(self, plist: BytesIO) -> dict:
        await self.service.send_plist({
            "MessageType": "Install",
            "Profile": plist.read(),
            "ProfileType": "Provisioning",
        })
        response = await self.service.recv_plist()
        if response["Status"]:
            raise PyMobileDevice3Exception(f"invalid status: {response}")

        return response

    async def remove(self, profile_id: str) -> dict:
        await self.service.send_plist({
            "MessageType": "Remove",
            "ProfileID": profile_id,
            "ProfileType": "Provisioning",
        })
        response = await self.service.recv_plist()
        if response["Status"]:
            raise PyMobileDevice3Exception(f"invalid status: {response}")

        return response

    async def copy_all(self) -> list[ProvisioningProfile]:
        await self.service.send_plist({"MessageType": "CopyAll", "ProfileType": "Provisioning"})
        response = await self.service.recv_plist()
        if response["Status"]:
            raise PyMobileDevice3Exception(f"invalid status: {response}")

        return [ProvisioningProfile(p) for p in response["Payload"]]
