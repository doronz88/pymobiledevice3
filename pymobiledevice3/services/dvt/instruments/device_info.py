from datetime import datetime

from pymobiledevice3.exceptions import DvtDirListError
from pymobiledevice3.services.dvt.structs import MessageAux


class DeviceInfo:
    IDENTIFIER = 'com.apple.instruments.server.services.deviceinfo'

    def __init__(self, dvt):
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def ls(self, path: str) -> list[str]:
        """
        List a directory.
        :param path: Directory to list.
        :return: Contents of the directory.
        """
        self._channel.directoryListingForPath_(MessageAux().append_obj(path))
        result = self._channel.receive()
        if result is None:
            raise DvtDirListError()
        return result

    def execname_for_pid(self, pid: int) -> str:
        """
        get full path for given pid
        :param pid: process pid
        """
        self._channel.execnameForPid_(MessageAux().append_obj(pid))
        return self._channel.receive()

    def proclist(self) -> list[dict]:
        """
        Get the process list from the device.
        :return: List of process and their attributes.
        """
        self._channel.runningProcesses()
        result = self._channel.receive()
        assert isinstance(result, list)
        for process in result:
            if 'startDate' in process:
                process['startDate'] = datetime.fromtimestamp(process['startDate'])
        return result

    def system_information(self):
        return self.request_information('systemInformation')

    def hardware_information(self):
        return self.request_information('hardwareInformation')

    def network_information(self):
        return self.request_information('networkInformation')

    def request_information(self, selector_name):
        self._channel[selector_name]()
        return self._channel.receive()
