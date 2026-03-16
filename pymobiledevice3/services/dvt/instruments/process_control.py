import asyncio
import dataclasses
import logging
import typing
from typing import Any, Optional

from pymobiledevice3.dtx import DTXService, PInt32, dtx_method, dtx_on_invoke
from pymobiledevice3.dtx_service import DtxService
from pymobiledevice3.exceptions import DisableMemoryLimitError
from pymobiledevice3.osu.os_utils import get_os_utils

OSUTIL = get_os_utils()


@dataclasses.dataclass
class OutputReceivedEvent:
    pid: int
    date: int
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
        self.output_events: asyncio.Queue[list[Any]] = asyncio.Queue()

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
    async def connect(self):
        await super().connect()
        self._provider.dtx.ctx["logger"] = self.logger.getChild("dtx")

    async def signal(self, pid: int, sig: int):
        """
        Send signal to process
        :param pid: PID of process to send signal.
        :param sig: SIGNAL to send
        """
        return await self.service.send_signal_to_pid_(sig, pid)

    async def disable_memory_limit_for_pid(self, pid: int) -> None:
        """
        Waive memory limit for a given pid
        :param pid: process id.
        """
        if not await self.service.request_disable_memory_limits_for_pid_(pid):
            raise DisableMemoryLimitError()

    async def kill(self, pid: int):
        """
        Kill a process.
        :param pid: PID of process to kill.
        """
        await self.service.kill_pid_(pid)

    async def process_identifier_for_bundle_identifier(self, app_bundle_identifier: str) -> int:
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
