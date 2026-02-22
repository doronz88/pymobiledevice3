from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class ScreenshotService(LockdownService):
    SERVICE_NAME = "com.apple.mobile.screenshotr"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown, self.SERVICE_NAME, is_developer_service=True)
        self._did_handshake = False

    async def _handshake(self) -> None:
        if self._did_handshake:
            return
        dl_message_version_exchange = await self.service.recv_plist()
        version_major = dl_message_version_exchange[1]
        await self.service.send_plist(["DLMessageVersionExchange", "DLVersionsOk", version_major])
        dl_message_device_ready = await self.service.recv_plist()
        if dl_message_device_ready[0] != "DLMessageDeviceReady":
            raise PyMobileDevice3Exception("Screenshotr didn't return ready state")
        self._did_handshake = True

    async def take_screenshot(self) -> bytes:
        await self._handshake()
        await self.service.send_plist(["DLMessageProcessMessage", {"MessageType": "ScreenShotRequest"}])
        response = await self.service.recv_plist()

        assert len(response) == 2
        assert response[0] == "DLMessageProcessMessage"

        if response[1].get("MessageType") == "ScreenShotReply":
            return response[1]["ScreenShotData"]

        raise PyMobileDevice3Exception(f"invalid response: {response}")
