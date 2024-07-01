from typing import Mapping

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class RestoreService(RemoteService):
    SERVICE_NAME = 'com.apple.RestoreRemoteServices.restoreserviced'

    def __init__(self, lockdown: RemoteServiceDiscoveryService):
        super().__init__(lockdown, self.SERVICE_NAME)

    async def delay_recovery_image(self) -> None:
        """
        Set `delay-recovery-image` on devices of ProductType 0x1677b394. Otherwise, fail
        """
        await self.validate_command('delayrecoveryimage')

    async def enter_recovery(self) -> None:
        """ Enter recovery """
        await self.validate_command('recovery')

    async def reboot(self) -> None:
        """ Reboot device """
        await self.validate_command('reboot')

    async def get_preflightinfo(self) -> Mapping:
        """ Get preflight info """
        return await self.service.send_receive_request({'command': 'getpreflightinfo'})

    async def get_nonces(self) -> Mapping:
        """ Get ApNonce and SEPNonce """
        return await self.service.send_receive_request({'command': 'getnonces'})

    async def get_app_parameters(self) -> Mapping:
        return await self.validate_command('getappparameters')

    async def restore_lang(self, language: str) -> Mapping:
        return await self.service.send_receive_request({'command': 'restorelang', 'argument': language})

    async def validate_command(self, command: str) -> Mapping:
        """ Execute command and validate result is `success` """
        response = await self.service.send_receive_request({'command': command})
        if response.get('result') != 'success':
            raise PyMobileDevice3Exception(f'request command: {command} failed with error: {response}')
        return response
