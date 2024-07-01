import asyncio
import struct
import uuid
from enum import IntEnum
from typing import AsyncGenerator, List, Mapping, Optional

from pymobiledevice3.exceptions import CoreDeviceError
from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcUInt64Type


class Domain(IntEnum):
    APP_DATA_CONTAINER = 1
    APP_GROUP_DATA_CONTAINER = 2
    TEMPORARY = 3
    SYSTEM_CRASH_LOGS = 5


APPLE_DOMAIN_DICT = {
    'appDataContainer': Domain.APP_DATA_CONTAINER,
    'appGroupDataContainer': Domain.APP_GROUP_DATA_CONTAINER,
    'temporary': Domain.TEMPORARY,
    'systemCrashLogs': Domain.SYSTEM_CRASH_LOGS
}


class FileServiceService(CoreDeviceService):
    """
    Filesystem control
    """

    CTRL_SERVICE_NAME = 'com.apple.coredevice.fileservice.control'

    def __init__(self, rsd: RemoteServiceDiscoveryService, domain: Domain) -> None:
        super().__init__(rsd, self.CTRL_SERVICE_NAME)
        self.domain: Domain = domain
        self.session: Optional[str] = None

    async def connect(self) -> None:
        await super().connect()
        response = await self.send_receive_request({
            'Cmd': 'CreateSession', 'Domain': XpcUInt64Type(self.domain), 'Identifier': '', 'Session': '',
            'User': 'mobile'})
        self.session = response['NewSessionID']

    async def retrieve_directory_list(self, path: str = '.') -> AsyncGenerator[List[str], None]:
        return (await self.send_receive_request({
            'Cmd': 'RetrieveDirectoryList', 'MessageUUID': str(uuid.uuid4()), 'Path': path, 'SessionID': self.session}
        ))['FileList']

    async def retrieve_file(self, path: str = '.') -> bytes:
        response = await self.send_receive_request({
            'Cmd': 'RetrieveFile', 'Path': path, 'SessionID': self.session}
        )
        data_service = self.rsd.get_service_port('com.apple.coredevice.fileservice.data')
        reader, writer = await asyncio.open_connection(self.service.address[0], data_service)
        writer.write(b'rwb!FILE' + struct.pack('>QQQQ', response['Response'], 0, response['NewFileID'], 0))
        await writer.drain()
        await reader.readexactly(0x24)
        return await reader.readexactly(struct.unpack('>I', await reader.readexactly(4))[0])

    async def send_receive_request(self, request: Mapping) -> Mapping:
        response = await self.service.send_receive_request(request)
        encoded_error = response.get('EncodedError')
        if encoded_error is not None:
            localized_description = response.get('LocalizedDescription')
            if localized_description is not None:
                raise CoreDeviceError(localized_description)
            raise CoreDeviceError(encoded_error)
        return response
