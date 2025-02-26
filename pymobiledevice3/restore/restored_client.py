import logging
from typing import Any, Optional

from pymobiledevice3 import usbmux
from pymobiledevice3.exceptions import ConnectionFailedError, NoDeviceConnectedError
from pymobiledevice3.lockdown import DEFAULT_LABEL
from pymobiledevice3.restore.restore_options import RestoreOptions
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.usbmux import select_devices_by_connection_type

logger = logging.getLogger(__name__)


class RestoredClient:
    DEFAULT_CLIENT_NAME = 'pymobiledevice3'
    SERVICE_PORT = 62078

    @classmethod
    async def create(cls, ecid: str) -> 'RestoredClient':
        for mux_device in select_devices_by_connection_type('USB'):
            logger.debug(f'Iterating: {mux_device}')
            service = ServiceConnection.create_using_usbmux(mux_device.serial, cls.SERVICE_PORT,
                                                            connection_type=mux_device.connection_type)
            await service.aio_start()

            query_type = await service.aio_send_recv_plist({'Request': 'QueryType'})
            version = query_type.get('RestoreProtocolVersion')
            logger.debug(f'RestoreProtocolVersion: {version}')

            if query_type.get('Type') != 'com.apple.mobile.restored':
                logger.debug(f'Skipping: {mux_device.serial} as its not a restored device')
                await service.aio_close()
                continue

            restored_client = cls(mux_device.serial, version, service)
            await restored_client._connect()

            if restored_client.ecid != ecid:
                logger.debug(f'Skipping: {restored_client.ecid} as its not the right ECID ({restored_client.ecid} '
                             f'instead of {ecid})')
                await service.aio_close()
                continue

            return restored_client
        raise NoDeviceConnectedError()

    def __init__(self, udid: str, version: str, service: ServiceConnection) -> None:
        self.udid = udid
        self.version = version
        self.service = service
        self.label = DEFAULT_LABEL

    async def _connect(self) -> None:
        self.hardware_info = (await self.query_value('HardwareInfo'))['HardwareInfo']
        self.ecid = self.hardware_info['UniqueChipID']
        self.saved_debug_info = (await self.query_value('SavedDebugInfo'))['SavedDebugInfo']

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

        logger.debug(f'start_restore request: {req}')

        return await self.service.aio_send_plist(req)

    async def reboot(self) -> dict:
        return await self.service.aio_send_recv_plist({'Request': 'Reboot', 'Label': self.label})

    async def send(self, message: dict) -> None:
        await self.service.aio_send_plist(message)

    async def recv(self) -> dict:
        return await self.service.aio_recv_plist()
