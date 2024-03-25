import logging
from abc import abstractmethod
from typing import Optional

from pymobiledevice3.exceptions import StartServiceError
from pymobiledevice3.service_connection import ServiceConnection


class LockdownServiceProvider:
    def __init__(self):
        self.udid: Optional[str] = None
        self.product_type: Optional[str] = None

    @property
    @abstractmethod
    def product_version(self) -> str:
        pass

    @property
    @abstractmethod
    def ecid(self) -> int:
        pass

    @property
    @abstractmethod
    def developer_mode_status(self) -> bool:
        pass

    @abstractmethod
    def start_lockdown_service(self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        pass

    @abstractmethod
    async def aio_start_lockdown_service(
            self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        pass

    def start_lockdown_developer_service(
            self, name: str, include_escrow_bag: bool = False) -> ServiceConnection:
        try:
            return self.start_lockdown_service(name, include_escrow_bag=include_escrow_bag)
        except StartServiceError:
            logging.getLogger(self.__module__).error(
                'Failed to connect to required service. Make sure DeveloperDiskImage.dmg has been mounted. '
                'You can do so using: pymobiledevice3 mounter mount'
            )
            raise
