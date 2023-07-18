import logging
from abc import abstractmethod

from pymobiledevice3.exceptions import StartServiceError
from pymobiledevice3.service_connection import LockdownServiceConnection


class LockdownServiceProvider:
    @property
    @abstractmethod
    def product_version(self) -> str:
        pass

    @abstractmethod
    def start_lockdown_service(self, name: str, escrow_bag: bytes = None) -> LockdownServiceConnection:
        pass

    @abstractmethod
    async def aio_start_lockdown_service(self, name: str, escrow_bag: bytes = None) -> LockdownServiceConnection:
        pass

    def start_lockdown_developer_service(self, name, escrow_bag: bytes = None) -> LockdownServiceConnection:
        try:
            return self.start_lockdown_service(name, escrow_bag=escrow_bag)
        except StartServiceError:
            logging.getLogger(self.__module__).error(
                'Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. '
                'You can do so using: pymobiledevice3 mounter mount'
            )
            raise
