import dataclasses
import datetime
import sys
import typing

from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService
from pymobiledevice3.services.remote_server import MessageAux


@dataclasses.dataclass
class OutputReceivedEvent:
    pid: int
    date: int
    message: str

    @classmethod
    def create(cls, message) -> 'OutputReceivedEvent':
        try:
            if sys.platform == 'win32':
                date = datetime.datetime.fromtimestamp(message[2].value / 1000)
            else:
                date = datetime.datetime.fromtimestamp(message[2].value)
        except (ValueError, OSError):
            date = None

        return cls(pid=message[1].value, date=date, message=message[0].value)


class ProcessControl:
    IDENTIFIER = 'com.apple.instruments.server.services.processcontrol'

    def __init__(self, dvt: DvtSecureSocketProxyService):
        self._channel = dvt.make_channel(self.IDENTIFIER)

    def signal(self, pid: int, sig: int):
        """
        Send signal to process
        :param pid: PID of process to send signal.
        :param sig: SIGNAL to send
        """
        self._channel.sendSignal_toPid_(MessageAux().append_obj(sig).append_obj(pid), expects_reply=True)
        return self._channel.receive_plist()

    def kill(self, pid: int):
        """
        Kill a process.
        :param pid: PID of process to kill.
        """
        self._channel.killPid_(MessageAux().append_obj(pid), expects_reply=False)

    def launch(self, bundle_id: str, arguments=None, kill_existing: bool = True, start_suspended: bool = False,
               environment: typing.Mapping = None, extra_options: typing.Mapping = None) -> int:
        """
        Launch a process.
        :param bundle_id: Bundle id of the process.
        :param list arguments: List of argument to pass to process.
        :param kill_existing: Whether to kill an existing instance of this process.
        :param start_suspended: Same as WaitForDebugger.
        :param environment: Environment variables to pass to process.
        :param extra_options: Extra options to pass to process.
        :return: PID of created process.
        """
        arguments = [] if arguments is None else arguments
        environment = {} if environment is None else environment
        options = {
            'StartSuspendedKey': start_suspended,
            'KillExisting': kill_existing,
        }
        if extra_options:
            options.update(extra_options)
        args = MessageAux().append_obj('').append_obj(bundle_id).append_obj(environment).append_obj(
            arguments).append_obj(options)
        self._channel.launchSuspendedProcessWithDevicePath_bundleIdentifier_environment_arguments_options_(args)
        result = self._channel.receive_plist()
        assert result
        return result

    def __iter__(self) -> typing.Generator[OutputReceivedEvent, None, None]:
        key, value = self._channel.receive_key_value()
        if key == 'outputReceived:fromProcess:atTime:':
            yield OutputReceivedEvent.create(value)
