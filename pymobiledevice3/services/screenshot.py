import logging

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient


class ScreenshotService(object):
    SERVICE_NAME = 'com.apple.mobile.screenshotr'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_developer_service(self.SERVICE_NAME)

        dl_message_version_exchange = self.service.recv_plist()
        version_major = dl_message_version_exchange[1]
        self.service.send_plist(['DLMessageVersionExchange', 'DLVersionsOk', version_major])
        dl_message_device_ready = self.service.recv_plist()
        if dl_message_device_ready[0] != 'DLMessageDeviceReady':
            raise PyMobileDevice3Exception('Screenshotr didn\'t return ready state')

    def take_screenshot(self) -> bytes:
        self.service.send_plist(['DLMessageProcessMessage', {'MessageType': 'ScreenShotRequest'}])
        response = self.service.recv_plist()

        assert len(response) == 2
        assert response[0] == 'DLMessageProcessMessage'

        if response[1].get('MessageType') == 'ScreenShotReply':
            return response[1]['ScreenShotData']

        raise PyMobileDevice3Exception(f'invalid response: {response}')
