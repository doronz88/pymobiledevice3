import plistlib
from datetime import datetime
from typing import List, Mapping

from pymobiledevice3.exceptions import DvtDirListError
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.remote_server import MessageAux


class DeviceInfo:
    IDENTIFIER = 'com.apple.instruments.server.services.deviceinfo'

    def __init__(self, dvt: DvtSecureSocketProxyService) -> None:
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def ls(self, path: str) -> List:
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

    def proclist(self) -> List:
        """
        Get the process list from the device.

        :return: List of process and their attributes.
        """
        self._channel.runningProcesses()
        result = self._channel.receive_plist()
        assert isinstance(result, list)
        for process in result:
            if 'startDate' in process:
                process['startDate'] = datetime.fromtimestamp(process['startDate'])
        return result

    def system_information(self) -> Mapping:
        return self.request_information('systemInformation')

    def hardware_information(self) -> Mapping:
        return self.request_information('hardwareInformation')

    def network_information(self) -> Mapping:
        return self.request_information('networkInformation')

    def mach_time_info(self) -> Mapping:
        return self.request_information('machTimeInfo')

    def mach_kernel_name(self) -> str:
        return self.request_information('machKernelName')

    def kpep_database(self) -> Mapping:
        return plistlib.loads(self.request_information('kpepDatabase'))

    def trace_codes(self) -> Mapping:
        codes_file = self.request_information('traceCodesFile')
        return {int(k, 16): v for k, v in map(lambda line: line.split(), codes_file.splitlines())}

    def request_information(self, selector_name: str) -> Mapping:
        self._channel[selector_name]()
        return self._channel.receive_plist()

    def name_for_uid(self, uid: int) -> str:
        self._channel.nameForUID_(MessageAux().append_obj(uid))
        return self._channel.receive_plist()

    def name_for_gid(self, gid: int) -> str:
        self._channel.nameForGID_(MessageAux().append_obj(gid))
        return self._channel.receive_plist()
