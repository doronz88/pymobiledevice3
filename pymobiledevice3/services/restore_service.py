from typing import Mapping

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class RestoreService(RemoteService):
    SERVICE_NAME = 'com.apple.RestoreRemoteServices.restoreserviced'

    def __init__(self, lockdown: RemoteServiceDiscoveryService):
        super().__init__(lockdown, self.SERVICE_NAME)

    def delay_recovery_image(self) -> None:
        self.invoke('delayrecoveryimage')

    def enter_recovery(self) -> None:
        self.invoke('recovery')

    def reboot(self) -> None:
        self.invoke('reboot')

    def get_preflightinfo(self) -> Mapping:
        return self.service.send_receive_request({'command': 'getpreflightinfo'})

    def get_nonces(self) -> Mapping:
        return self.service.send_receive_request({'command': 'getnonces'})

    def invoke(self, command: str) -> Mapping:
        response = self.service.send_receive_request({'command': command})
        if response.get('result') != 'success':
            raise PyMobileDevice3Exception(f'request command: {command} failed with error: {response}')
        return response
