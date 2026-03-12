import plistlib
import typing
from datetime import datetime

from pymobiledevice3.dtx import DTXNsError, DTXService, dtx_method
from pymobiledevice3.dtx.ns_types import NSDate
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import DvtDirListError


class DeviceInfoService(DTXService):
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

    @dtx_method("systemInformation")
    async def system_information(self) -> dict: ...

    @dtx_method("hardwareInformation")
    async def hardware_information(self) -> dict: ...

    @dtx_method("networkInformation")
    async def network_information(self) -> dict: ...

    @dtx_method("machTimeInfo")
    async def mach_time_info(self) -> dict: ...

    @dtx_method("machKernelName")
    async def mach_kernel_name(self) -> str: ...

    @dtx_method("kpepDatabase")
    async def kpep_database(self) -> typing.Optional[bytes]: ...

    @dtx_method("traceCodesFile")
    async def trace_codes_file(self) -> str: ...

    @dtx_method("sysmonProcessAttributes")
    async def sysmon_process_attributes(self) -> list[str]: ...

    @dtx_method("sysmonSystemAttributes")
    async def sysmon_system_attributes(self) -> list[str]: ...

    # TODO: parsing: https://github.com/frida/frida-core/blob/1bdf9a2fd3171f83bb3dad0d7293b883bb171557/src/fruity/cs-signature.vala#L233

    @dtx_method("symbolicatorSignatureForPid:trackingSelector:")
    async def symbolicator_signature_for_pid_tracking_selector_(self, pid: int, selector: str) -> typing.Any: ...


class DeviceInfo(DtxService[DeviceInfoService]):
    async def ls(self, path: str) -> list:
        """
        List a directory.
        :param path: Directory to list.
        :return: Contents of the directory.
        """
        try:
            result = await self.service.directory_listing_for_path_(path)
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
        return await self.service.execname_for_pid_(pid)

    async def proclist(self) -> list[dict]:
        """
        Get the process list from the device.
        :return: List of process and their attributes.
        """
        result = await self.service.running_processes()
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
        return await self.service.is_running_pid_(pid)

    async def system_information(self):
        return await self.service.system_information()

    async def hardware_information(self):
        return await self.service.hardware_information()

    async def network_information(self):
        return await self.service.network_information()

    async def mach_time_info(self):
        return await self.service.mach_time_info()

    async def mach_kernel_name(self) -> str:
        return await self.service.mach_kernel_name()

    async def kpep_database(self) -> typing.Optional[dict]:
        kpep_database = await self.service.kpep_database()
        if kpep_database is not None:
            return plistlib.loads(kpep_database)

    async def trace_codes(self):
        codes_file = await self.service.trace_codes_file()
        return {int(k, 16): v for k, v in (line.split() for line in codes_file.splitlines())}

    async def sysmon_process_attributes(self) -> list[str]:
        return await self.service.sysmon_process_attributes()

    async def sysmon_system_attributes(self) -> list[str]:
        return await self.service.sysmon_system_attributes()

    async def name_for_uid(self, uid: int) -> str:
        return await self.service.name_for_uid_(uid)

    async def name_for_gid(self, gid: int) -> str:
        return await self.service.name_for_gid_(gid)
