import plistlib
import typing
from datetime import datetime

from pymobiledevice3.exceptions import DvtDirListError
from pymobiledevice3.services.remote_server import MessageAux


class DeviceInfo:
    IDENTIFIER = "com.apple.instruments.server.services.deviceinfo"

    def __init__(self, dvt):
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def ls(self, path: str) -> list:
        """
        List a directory.
        :param path: Directory to list.
        :return: Contents of the directory.
        """
        self._channel.directoryListingForPath_(MessageAux().append_obj(path))
        result = self._channel.receive_plist()
        if result is None:
            raise DvtDirListError()
        return result

    def execname_for_pid(self, pid: int) -> str:
        """
        get full path for given pid
        :param pid: process pid
        """
        self._channel.execnameForPid_(MessageAux().append_obj(pid))
        return self._channel.receive_plist()

    def proclist(self) -> list[dict]:
        """
        Get the process list from the device.
        :return: List of process and their attributes.
        """
        self._channel.runningProcesses()
        result = self._channel.receive_plist()
        assert isinstance(result, list)
        for process in result:
            if "startDate" in process:
                process["startDate"] = datetime.fromtimestamp(process["startDate"])
        return result

    def is_running_pid(self, pid: int) -> bool:
        """
        check if pid is running
        :param pid: process identifier
        :return: whether if it is running or not
        """
        self._channel.isRunningPid_(MessageAux().append_obj(pid))
        return self._channel.receive_plist()

    def system_information(self):
        return self.request_information("systemInformation")

    def hardware_information(self):
        return self.request_information("hardwareInformation")

    def network_information(self):
        return self.request_information("networkInformation")

    def mach_time_info(self):
        return self.request_information("machTimeInfo")

    def mach_kernel_name(self) -> str:
        return self.request_information("machKernelName")

    def kpep_database(self) -> typing.Optional[dict]:
        kpep_database = self.request_information("kpepDatabase")
        if kpep_database is not None:
            return plistlib.loads(kpep_database)

    def trace_codes(self):
        codes_file = self.request_information("traceCodesFile")
        return {int(k, 16): v for k, v in (line.split() for line in codes_file.splitlines())}

    def request_information(self, selector_name):
        self._channel[selector_name]()
        return self._channel.receive_plist()

    def name_for_uid(self, uid: int) -> str:
        self._channel.nameForUID_(MessageAux().append_obj(uid))
        return self._channel.receive_plist()

    def name_for_gid(self, gid: int) -> str:
        self._channel.nameForGID_(MessageAux().append_obj(gid))
        return self._channel.receive_plist()
