from typing import Mapping

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class RestoreService(RemoteService):
    SERVICE_NAME = 'com.apple.RestoreRemoteServices.restoreserviced'

    def __init__(self, lockdown: RemoteServiceDiscoveryService):
        super().__init__(lockdown, self.SERVICE_NAME)

    def delay_recovery_image(self) -> None:
        """
        Set `delay-recovery-image` on devices of ProductType 0x1677b394. Otherwise, fail
        """
        self.validate_command('delayrecoveryimage')

    def enter_recovery(self) -> None:
        """ Enter recovery """
        self.validate_command('recovery')

    def reboot(self) -> None:
        """ Reboot device """
        self.validate_command('reboot')

    def get_preflightinfo(self) -> Mapping:
        """ Get preflight info """
        return self.service.send_receive_request({'command': 'getpreflightinfo'})

    def get_nonces(self) -> Mapping:
        """ Get ApNonce and SEPNonce """
        return self.service.send_receive_request({'command': 'getnonces'})

    def validate_command(self, command: str) -> Mapping:
        """ Execute command and validate result is `success` """
        response = self.service.send_receive_request({'command': command})
        if response.get('result') != 'success':
            raise PyMobileDevice3Exception(f'request command: {command} failed with error: {response}')
        return response
