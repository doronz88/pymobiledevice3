from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.lockdown_service import LockdownService


class ScreenshotService(LockdownService):
    SERVICE_NAME = "com.apple.mobile.screenshotr"

    def __init__(self, lockdown: LockdownClient):
        super().__init__(lockdown, self.SERVICE_NAME, is_developer_service=True)

        dl_message_version_exchange = self.service.recv_plist()
        version_major = dl_message_version_exchange[1]
        dl_message_device_ready = self.service.send_recv_plist([
            "DLMessageVersionExchange",
            "DLVersionsOk",
            version_major,
        ])
        if dl_message_device_ready[0] != "DLMessageDeviceReady":
            raise PyMobileDevice3Exception("Screenshotr didn't return ready state")

    def take_screenshot(self) -> bytes:
        self.service.send_plist(["DLMessageProcessMessage", {"MessageType": "ScreenShotRequest"}])
        response = self.service.recv_plist()

        assert len(response) == 2
        assert response[0] == "DLMessageProcessMessage"

        if response[1].get("MessageType") == "ScreenShotReply":
            return response[1]["ScreenShotData"]

        raise PyMobileDevice3Exception(f"invalid response: {response}")
