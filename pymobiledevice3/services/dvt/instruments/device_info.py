import plistlib
import typing
from datetime import datetime

from pymobiledevice3.dtx import DTXNsError, DTXService, dtx_method
from pymobiledevice3.dtx.ns_types import NSDate
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.exceptions import DvtDirListError


class _DeviceInfoService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.deviceinfo"

    @dtx_method("directoryListingForPath:")
    async def directory_listing_for_path_(self, path: str) -> list[str]: ...

    @dtx_method("execnameForPid:")
    async def execname_for_pid_(self, pid: int) -> str: ...

    @dtx_method("runningProcesses")
    async def running_processes(self) -> list[dict]: ...

    @dtx_method("isRunningPid:")
    async def is_running_pid_(self, pid: int) -> bool: ...

    @dtx_method("nameForUID:")
    async def name_for_uid_(self, uid: int) -> str: ...

    @dtx_method("nameForGID:")
    async def name_for_gid_(self, gid: int) -> str: ...


class _DeviceInfoChannel(DtxService[_DeviceInfoService]):
    SERVICE_CLASS = _DeviceInfoService


class DeviceInfo:
    IDENTIFIER = _DeviceInfoService.IDENTIFIER

    def __init__(self, dvt: DtxServiceProvider):
        self._provider = dvt
        self._channel: _DeviceInfoChannel | None = None

    async def _service_ref(self) -> _DeviceInfoService:
        if self._channel is None:
            self._channel = _DeviceInfoChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def ls(self, path: str) -> list:
        """
        List a directory.
        :param path: Directory to list.
        :return: Contents of the directory.
        """
        try:
            result = await (await self._service_ref()).directory_listing_for_path_(path)
        except DTXNsError as e:
            raise DvtDirListError() from e
        if result is None:
            raise DvtDirListError()
        return result

    async def execname_for_pid(self, pid: int) -> str:
        """
        get full path for given pid
        :param pid: process pid
        """
        return await (await self._service_ref()).execname_for_pid_(pid)

    async def proclist(self) -> list[dict]:
        """
        Get the process list from the device.
        :return: List of process and their attributes.
        """
        result = await (await self._service_ref()).running_processes()
        assert isinstance(result, list)
        for process in result:
            if "startDate" in process:
                d = process["startDate"]
                process["startDate"] = d.utc if isinstance(d, NSDate) else datetime.fromtimestamp(d)
        return result

    async def is_running_pid(self, pid: int) -> bool:
        """
        check if pid is running
        :param pid: process identifier
        :return: whether if it is running or not
        """
        return await (await self._service_ref()).is_running_pid_(pid)

    async def system_information(self):
        return await self.request_information("systemInformation")

    async def hardware_information(self):
        return await self.request_information("hardwareInformation")

    async def network_information(self):
        return await self.request_information("networkInformation")

    async def mach_time_info(self):
        return await self.request_information("machTimeInfo")

    async def mach_kernel_name(self) -> str:
        return await self.request_information("machKernelName")

    async def kpep_database(self) -> typing.Optional[dict]:
        kpep_database = await self.request_information("kpepDatabase")
        if kpep_database is not None:
            return plistlib.loads(kpep_database)

    async def trace_codes(self):
        codes_file = await self.request_information("traceCodesFile")
        return {int(k, 16): v for k, v in (line.split() for line in codes_file.splitlines())}

    async def request_information(self, selector_name):
        return await (await self._service_ref()).do_invoke(selector_name)

    async def name_for_uid(self, uid: int) -> str:
        return await (await self._service_ref()).name_for_uid_(uid)

    async def name_for_gid(self, gid: int) -> str:
        return await (await self._service_ref()).name_for_gid_(gid)
