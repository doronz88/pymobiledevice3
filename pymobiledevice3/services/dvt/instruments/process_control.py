import dataclasses
import logging
import typing
from datetime import datetime
from typing import Any, Optional

from pymobiledevice3.dtx import DTXQueue, DTXService, PInt32, dtx_method, dtx_on_invoke
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import DisableMemoryLimitError
from pymobiledevice3.osu.os_utils import get_os_utils

OSUTIL = get_os_utils()

# SIGKILL on Darwin and every Apple platform pymobiledevice3 targets. Hardcoded rather than
# signal.SIGKILL because that constant does not exist on Windows hosts, which can still drive a
# connected device.
SIGKILL = 9


@dataclasses.dataclass
class OutputReceivedEvent:
    pid: int
    date: Optional[datetime]
    message: str

    @classmethod
    def create(cls, message: list[Any]) -> "OutputReceivedEvent":
        def _value(v: Any) -> Any:
            return getattr(v, "value", v)

        msg_value = _value(message[0])
        pid_value = _value(message[1])
        timestamp_value = _value(message[2])
        try:
            date = OSUTIL.parse_timestamp(timestamp_value)
        except (ValueError, OSError):
            date = None

        return cls(pid=pid_value, date=date, message=msg_value)


class ProcessControlService(DTXService):
    IDENTIFIER = "com.apple.instruments.server.services.processcontrol"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.output_events: DTXQueue[list[Any]] = DTXQueue()

    def on_closed(self, reason: str = "") -> None:
        self.shutdown_queue(self.output_events)
        super().on_closed(reason)

    @dtx_method("sendSignal:toPid:")
    async def send_signal_to_pid_(self, sig: int, pid: int) -> Any: ...

    @dtx_method("requestDisableMemoryLimitsForPid:")
    async def request_disable_memory_limits_for_pid_(self, pid: PInt32) -> bool: ...

    @dtx_method("killPid:", expects_reply=False)
    async def kill_pid_(self, pid: int) -> None: ...

    @dtx_method("processIdentifierForBundleIdentifier:")
    async def process_identifier_for_bundle_identifier_(self, app_bundle_identifier: str) -> int: ...

    @dtx_method("launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:")
    async def launch_suspended_process_with_device_path_bundle_identifier_environment_arguments_options_(
        self, device_path: str, bundle_id: str, environment: dict, arguments: list, options: dict
    ) -> int: ...

    @dtx_on_invoke("outputReceived:fromProcess:atTime:")
    async def _on_output_received(self, message: str, pid: int, timestamp: Any) -> None:
        await self.output_events.put([message, pid, timestamp])

    @dtx_method
    async def startObservingPid_(self, pid: int) -> None: ...

    @dtx_method
    async def stopObservingPid_(self, pid: int) -> None: ...

    @dtx_on_invoke("processWithPID:terminatedWithExitCode:orCrashingSignal:")
    async def _on_process_terminated(self, pid: int, exit_code: Optional[int], crashing_signal: Optional[int]) -> None:
        logger = self._ctx.get("logger") or logging.getLogger(__name__)
        logger.warning(
            f"Process with PID {pid} terminated with exit code {exit_code} or crashing signal {crashing_signal}"
        )


class ProcessControl(DtxService[ProcessControlService]):
    """
    Launch, terminate and observe processes on the device through the DVT
    ``processcontrol`` instruments service.

    Backed by `ProcessControlService`, this wraps the remote
    process-control DTX channel and exposes high-level operations such as
    launching an app, killing it, sending signals and waiving its memory limit.
    Iterating over an instance yields `OutputReceivedEvent` objects for
    stdout/stderr output emitted by observed processes.
    """

    async def connect(self):
        await super().connect()
        self._provider.dtx.ctx["logger"] = self.logger.getChild("dtx")

    async def signal(self, pid: int, sig: int):
        """
        Send a signal to a running process.

        :param pid: PID of the process to signal.
        :param sig: Signal number to send.
        """
        return await self.service.send_signal_to_pid_(sig, pid)

    async def disable_memory_limit_for_pid(self, pid: int) -> None:
        """
        Waive the memory limit (jetsam limit) for a given process.

        :param pid: PID of the process whose memory limit should be lifted.
        :raises DisableMemoryLimitError: If the device declines the request.
        """
        if not await self.service.request_disable_memory_limits_for_pid_(PInt32(pid)):
            raise DisableMemoryLimitError()

    async def kill(self, pid: int):
        """
        Kill a process by sending it SIGKILL.

        Implemented via ``sendSignal:toPid:`` (which awaits a reply) rather than the
        fire-and-forget ``killPid:``: the round-trip guarantees the device has acted on the
        request before the DTX channel — and, on iOS 17+, the tunnel — is torn down. A bare
        ``killPid:`` is silently dropped when the channel closes immediately after sending it
        (observed over the default userspace tunnel), leaving the target process alive.

        :param pid: PID of the process to kill.
        """
        await self.signal(pid, SIGKILL)

    async def process_identifier_for_bundle_identifier(self, app_bundle_identifier: str) -> int:
        """
        Resolve the PID of a currently running process by its bundle identifier.

        :param app_bundle_identifier: Bundle identifier of the running app.
        :returns: PID of the matching process, or 0 if no such process is running.
        """
        return await self.service.process_identifier_for_bundle_identifier_(app_bundle_identifier)

    async def launch(
        self,
        bundle_id: str,
        arguments=None,
        kill_existing: bool = True,
        start_suspended: bool = False,
        environment: Optional[dict] = None,
        extra_options: Optional[dict] = None,
    ) -> int:
        """
        Launch an installed application by its bundle identifier.

        :param bundle_id: Bundle identifier of the app to launch.
        :param arguments: List of command-line arguments to pass to the process.
            Defaults to an empty list when ``None``.
        :param kill_existing: Whether to kill an already-running instance of the app
            before launching (sent as the ``KillExisting`` launch option).
        :param start_suspended: Start the process suspended, waiting for a debugger to
            attach (sent as the ``StartSuspendedKey`` launch option).
        :param environment: Environment variables to set for the process. Defaults to an
            empty dict when ``None``.
        :param extra_options: Additional launch options merged into the options dict sent
            to the device, overriding the defaults on key collision.
        :returns: PID of the newly launched process.
        :raises AssertionError: If the device returns a falsy PID (launch failure).
        """
        arguments = [] if arguments is None else arguments
        environment = {} if environment is None else environment
        options = {
            "StartSuspendedKey": start_suspended,
            "KillExisting": kill_existing,
        }
        if extra_options:
            options.update(extra_options)
        result = await self.service.launch_suspended_process_with_device_path_bundle_identifier_environment_arguments_options_(
            "", bundle_id, environment, arguments, options
        )
        assert result
        return result

    async def __aiter__(self) -> typing.AsyncGenerator[OutputReceivedEvent, None]:
        while True:
            value = await self.service.output_events.get()
            yield OutputReceivedEvent.create(value)
