from pymobiledevice3.exceptions import ArbitrationError, DeviceAlreadyInUseError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.lockdown_service import LockdownService


class DtDeviceArbitration(LockdownService):
    SERVICE_NAME = "com.apple.dt.devicearbitration"

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME, is_developer_service=True)

    async def _send_recv(self, request: dict) -> dict:
        await self.service.send_plist(request)
        return await self.service.recv_plist()

    async def version(self) -> dict:
        return await self._send_recv({"command": "version"})

    async def check_in(self, hostname: str, force: bool = False):
        request = {"command": "check-in", "hostname": hostname}
        if force:
            request["command"] = "force-check-in"
        response = await self._send_recv(request)
        if response.get("result") != "success":
            raise DeviceAlreadyInUseError(response)

    async def check_out(self):
        request = {"command": "check-out"}
        response = await self._send_recv(request)
        if response.get("result") != "success":
            raise ArbitrationError(f"failed with: {response}")
