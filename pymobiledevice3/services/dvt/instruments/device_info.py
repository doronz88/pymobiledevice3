import plistlib
import typing
from datetime import datetime

from pymobiledevice3.exceptions import DvtDirListError
from pymobiledevice3.services.dvt.instruments import ChannelService
from pymobiledevice3.services.remote_server import MessageAux


class DeviceInfo(ChannelService):
    IDENTIFIER = "com.apple.instruments.server.services.deviceinfo"

    async def ls(self, path: str) -> list:
        """
        List a directory.
        :param path: Directory to list.
        :return: Contents of the directory.
        """
        channel = await self._channel_ref()
        await channel.directoryListingForPath_(MessageAux().append_obj(path))
        result = await channel.receive_plist()
        if result is None:
            raise DvtDirListError()
        return result

    async def execname_for_pid(self, pid: int) -> str:
        """
        get full path for given pid
        :param pid: process pid
        """
        channel = await self._channel_ref()
        await channel.execnameForPid_(MessageAux().append_obj(pid))
        return await channel.receive_plist()

    async def proclist(self) -> list[dict]:
        """
        Get the process list from the device.
        :return: List of process and their attributes.
        """
        channel = await self._channel_ref()
        await channel.runningProcesses()
        result = await channel.receive_plist()
        assert isinstance(result, list)
        for process in result:
            if "startDate" in process:
                process["startDate"] = datetime.fromtimestamp(process["startDate"])
        return result

    async def is_running_pid(self, pid: int) -> bool:
        """
        check if pid is running
        :param pid: process identifier
        :return: whether if it is running or not
        """
        channel = await self._channel_ref()
        await channel.isRunningPid_(MessageAux().append_obj(pid))
        return await channel.receive_plist()

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
        channel = await self._channel_ref()
        await channel[selector_name]()
        return await channel.receive_plist()

    async def name_for_uid(self, uid: int) -> str:
        channel = await self._channel_ref()
        await channel.nameForUID_(MessageAux().append_obj(uid))
        return await channel.receive_plist()

    async def name_for_gid(self, gid: int) -> str:
        channel = await self._channel_ref()
        await channel.nameForGID_(MessageAux().append_obj(gid))
        return await channel.receive_plist()
