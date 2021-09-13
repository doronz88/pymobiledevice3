from pymobiledevice3.services.remote_server import MessageAux


class ProcessControl:
    IDENTIFIER = 'com.apple.instruments.server.services.processcontrol'

    def __init__(self, dvt):
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

    def launch(self, bundle_id: str, arguments=None, kill_existing: bool = True, start_suspended: bool = False) -> int:
        """
        Launch a process.
        :param bundle_id: Bundle id of the process.
        :param list arguments: List of argument to pass to process.
        :param kill_existing: Whether to kill an existing instance of this process.
        :param start_suspended: Same as WaitForDebugger.
        :return: PID of created process.
        """
        arguments = [] if arguments is None else arguments
        args = MessageAux().append_obj('').append_obj(bundle_id).append_obj({}).append_obj(arguments).append_obj({
            'StartSuspendedKey': start_suspended,
            'KillExisting': kill_existing,
        })
        self._channel.launchSuspendedProcessWithDevicePath_bundleIdentifier_environment_arguments_options_(args)
        result = self._channel.receive_plist()
        assert result
        return result
