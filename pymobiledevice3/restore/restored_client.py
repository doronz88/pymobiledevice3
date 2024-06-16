import logging
from functools import cached_property
from typing import Any, Mapping, Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedError, NoDeviceConnectedError
from pymobiledevice3.restore.restore_options import RestoreOptions
from pymobiledevice3.service_connection import ServiceConnection


class RestoredClient:
    DEFAULT_CLIENT_NAME = 'pyMobileDevice'
    SERVICE_PORT = 62078

    def __init__(self, udid: Optional[str] = None) -> None:
        self.logger = logging.getLogger(__name__)
        self.udid = udid
        self.version: Optional[str] = None
        self.query_type: Optional[str] = None
        self.label: Optional[str] = None
        self.service: Optional[ServiceConnection] = None

    async def connect(self, client_name: str = DEFAULT_CLIENT_NAME) -> None:
        self.service = ServiceConnection.create_using_usbmux(self.udid, self.SERVICE_PORT,
                                                             connection_type='USB')
        await self.service.aio_start()
        self.label = client_name
        self.query_type = await self.service.aio_send_recv_plist({'Request': 'QueryType'})
        self.version = self.query_type.get('RestoreProtocolVersion')

        assert self.query_type.get('Type') == 'com.apple.mobile.restored', f'wrong query type: {self.query_type}'

    @staticmethod
    def _get_or_verify_udid(udid: Optional[str] = None) -> str:
        device = usbmux.select_device(udid)
        if device is None:
            if udid:
                raise ConnectionFailedError()
            else:
                raise NoDeviceConnectedError()
        return device.serial

    async def query_value(self, key: Optional[str] = None) -> Any:
        req = {'Request': 'QueryValue', 'Label': self.label}

        if key:
            req['QueryKey'] = key

        return await self.service.aio_send_recv_plist(req)

    async def start_restore(self, opts: Optional[RestoreOptions] = None) -> None:
        req = {'Request': 'StartRestore', 'Label': self.label, 'RestoreProtocolVersion': self.version}

        if opts is not None:
            req['RestoreOptions'] = opts.to_dict()

        self.logger.debug(f'start_restore request: {req}')

        return await self.service.aio_send_plist(req)

    async def reboot(self) -> Mapping:
        return await self.service.aio_send_recv_plist({'Request': 'Reboot', 'Label': self.label})

    async def send(self, message: Mapping) -> None:
        await self.service.aio_send_plist(message)

    async def recv(self) -> Mapping:
        return await self.service.aio_recv_plist()

    @cached_property
    async def hardware_info(self) -> Mapping[str, Any]:
        return (await self.query_value('HardwareInfo'))['HardwareInfo']

    @property
    async def saved_debug_info(self) -> Mapping[str, Any]:
        return (await self.query_value('SavedDebugInfo'))['SavedDebugInfo']
