# Developer / DVT

DVT (DTX Instruments) services power the `developer dvt` CLI commands. They need Developer Mode; on iOS < 17 also a mounted Developer Disk Image, and on iOS 17+ a tunnel-backed service provider; see [iOS 17+ tunnels](https://doronz88.github.io/pymobiledevice3/latest/guides/ios17-tunnels/index.md).

Open a `DvtProvider` on a service provider, then construct each instrument with it. Both are async context managers, and several instruments are async-iterable and yield telemetry/events:

```
async with DvtProvider(service_provider) as dvt, ProcessControl(dvt) as process_control:
    await process_control.launch("com.apple.mobilesafari")
```

## Provider

## pymobiledevice3.services.dvt.instruments.dvt_provider.DvtProvider

Bases: `DtxServiceProvider`

Provides access to the DVT (DTX Instruments) services exposed by Apple's `instruments` daemon.

The provider opens a `DTXConnection` on top of a given service provider and is the entry point used by the individual DVT `DTXService` subclasses (process control, device info, screenshot, etc.).

The underlying service is reached differently depending on the transport:

- over lockdown (`SERVICE_NAME` /`OLD_SERVICE_NAME` ) on older iOS versions
- over an RSD tunnel (`RSD_SERVICE_NAME` ) on iOS 17 and later

The provider is meant to be used as an async context manager, which connects the DTX transport on entry and closes it on exit::

```
async with DvtProvider(lockdown) as provider:
    ...
```

It additionally advertises the process-control `terminationCallback` capability so that the device reports process termination events.

Source code in `pymobiledevice3/services/dvt/instruments/dvt_provider.py`

```
class DvtProvider(DtxServiceProvider):
    """
    Provides access to the DVT (DTX Instruments) services exposed by Apple's
    ``instruments`` daemon.

    The provider opens a `DTXConnection` on top of a
    given service provider and is the entry point used by the individual DVT
    `DTXService` subclasses (process control, device
    info, screenshot, etc.).

    The underlying service is reached differently depending on the transport:

    - over lockdown (``SERVICE_NAME`` /``OLD_SERVICE_NAME`` ) on older iOS versions
    - over an RSD tunnel (``RSD_SERVICE_NAME`` ) on iOS 17 and later

    The provider is meant to be used as an async context manager, which connects
    the DTX transport on entry and closes it on exit::

        async with DvtProvider(lockdown) as provider:
            ...

    It additionally advertises the process-control ``terminationCallback``
    capability so that the device reports process termination events.
    """

    SERVICE_NAME = "com.apple.instruments.remoteserver.DVTSecureSocketProxy"
    RSD_SERVICE_NAME = "com.apple.instruments.dtservicehub"
    OLD_SERVICE_NAME = "com.apple.instruments.remoteserver"

    def __init__(
        self,
        lockdown: LockdownServiceProvider,
        strip_ssl: Optional[bool] = None,
        dtx: Optional[DTXConnection] = None,
    ) -> None:
        """
        :param lockdown: Lockdown or RSD service provider used to reach the DVT service.
        :param strip_ssl: Override the SSL-stripping behaviour. ``None`` (default) lets
            the base provider decide based on the transport.
        :param dtx: Pre-built `DTXConnection` to reuse instead
            of opening a new one (shares a single transport across callers).
        """
        super().__init__(lockdown, strip_ssl, dtx)
        # the base provider always initializes sent_capabilities to a dict
        assert self.sent_capabilities is not None
        self.sent_capabilities["com.apple.instruments.client.processcontrol.capability.terminationCallback"] = 1
```

## Process control

## pymobiledevice3.services.dvt.instruments.process_control.ProcessControl

Bases: `DtxService[ProcessControlService]`

Launch, terminate and observe processes on the device through the DVT `processcontrol` instruments service.

Backed by `ProcessControlService`, this wraps the remote process-control DTX channel and exposes high-level operations such as launching an app, killing it, sending signals and waiving its memory limit. Iterating over an instance yields `OutputReceivedEvent` objects for stdout/stderr output emitted by observed processes.

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
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
        """Open the instrument's DTX channel and route its message log to this instrument's logger."""
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

    async def is_debuggable(self, pid: int) -> bool:
        """
        Tell whether the device lets developer tools inspect a process.

        That is the case for development-signed apps (those with ``get-task-allow``), which the
        memory instruments are limited to on a production device.

        :param pid: PID of the process to check.
        """
        return await self.service.is_pid_debuggable_(pid)

    async def suspend(self, pid: int) -> None:
        """
        Suspend a process until `resume` is called for it.

        :param pid: PID of the process to suspend.
        """
        await self.service.suspend_pid_(pid)

    async def resume(self, pid: int) -> None:
        """
        Resume a process that was suspended with `suspend` or launched suspended.

        :param pid: PID of the process to resume.
        """
        await self.service.resume_pid_(pid)

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
        arguments: Optional[list[str]] = None,
        kill_existing: bool = True,
        start_suspended: bool = False,
        environment: Optional[dict[str, Any]] = None,
        extra_options: Optional[dict[str, Any]] = None,
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
```

### connect

```
connect()
```

Open the instrument's DTX channel and route its message log to this instrument's logger.

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
async def connect(self):
    """Open the instrument's DTX channel and route its message log to this instrument's logger."""
    await super().connect()
    self._provider.dtx.ctx["logger"] = self.logger.getChild("dtx")
```

### signal

```
signal(pid: int, sig: int)
```

Send a signal to a running process.

Parameters:

| Name  | Type  | Description                   | Default    |
| ----- | ----- | ----------------------------- | ---------- |
| `pid` | `int` | PID of the process to signal. | *required* |
| `sig` | `int` | Signal number to send.        | *required* |

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
async def signal(self, pid: int, sig: int):
    """
    Send a signal to a running process.

    :param pid: PID of the process to signal.
    :param sig: Signal number to send.
    """
    return await self.service.send_signal_to_pid_(sig, pid)
```

### disable_memory_limit_for_pid

```
disable_memory_limit_for_pid(pid: int) -> None
```

Waive the memory limit (jetsam limit) for a given process.

Parameters:

| Name  | Type  | Description                                             | Default    |
| ----- | ----- | ------------------------------------------------------- | ---------- |
| `pid` | `int` | PID of the process whose memory limit should be lifted. | *required* |

Raises:

| Type                      | Description                         |
| ------------------------- | ----------------------------------- |
| `DisableMemoryLimitError` | If the device declines the request. |

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
async def disable_memory_limit_for_pid(self, pid: int) -> None:
    """
    Waive the memory limit (jetsam limit) for a given process.

    :param pid: PID of the process whose memory limit should be lifted.
    :raises DisableMemoryLimitError: If the device declines the request.
    """
    if not await self.service.request_disable_memory_limits_for_pid_(PInt32(pid)):
        raise DisableMemoryLimitError()
```

### kill

```
kill(pid: int)
```

Kill a process by sending it SIGKILL.

Implemented via `sendSignal:toPid:` (which awaits a reply) rather than the fire-and-forget `killPid:`: the round-trip guarantees the device has acted on the request before the DTX channel — and, on iOS 17+, the tunnel — is torn down. A bare `killPid:` is silently dropped when the channel closes immediately after sending it (observed over the default userspace tunnel), leaving the target process alive.

Parameters:

| Name  | Type  | Description                 | Default    |
| ----- | ----- | --------------------------- | ---------- |
| `pid` | `int` | PID of the process to kill. | *required* |

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
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
```

### is_debuggable

```
is_debuggable(pid: int) -> bool
```

Tell whether the device lets developer tools inspect a process.

That is the case for development-signed apps (those with `get-task-allow`), which the memory instruments are limited to on a production device.

Parameters:

| Name  | Type  | Description                  | Default    |
| ----- | ----- | ---------------------------- | ---------- |
| `pid` | `int` | PID of the process to check. | *required* |

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
async def is_debuggable(self, pid: int) -> bool:
    """
    Tell whether the device lets developer tools inspect a process.

    That is the case for development-signed apps (those with ``get-task-allow``), which the
    memory instruments are limited to on a production device.

    :param pid: PID of the process to check.
    """
    return await self.service.is_pid_debuggable_(pid)
```

### suspend

```
suspend(pid: int) -> None
```

Suspend a process until `resume` is called for it.

Parameters:

| Name  | Type  | Description                    | Default    |
| ----- | ----- | ------------------------------ | ---------- |
| `pid` | `int` | PID of the process to suspend. | *required* |

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
async def suspend(self, pid: int) -> None:
    """
    Suspend a process until `resume` is called for it.

    :param pid: PID of the process to suspend.
    """
    await self.service.suspend_pid_(pid)
```

### resume

```
resume(pid: int) -> None
```

Resume a process that was suspended with `suspend` or launched suspended.

Parameters:

| Name  | Type  | Description                   | Default    |
| ----- | ----- | ----------------------------- | ---------- |
| `pid` | `int` | PID of the process to resume. | *required* |

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
async def resume(self, pid: int) -> None:
    """
    Resume a process that was suspended with `suspend` or launched suspended.

    :param pid: PID of the process to resume.
    """
    await self.service.resume_pid_(pid)
```

### process_identifier_for_bundle_identifier

```
process_identifier_for_bundle_identifier(app_bundle_identifier: str) -> int
```

Resolve the PID of a currently running process by its bundle identifier.

Parameters:

| Name                    | Type  | Description                           | Default    |
| ----------------------- | ----- | ------------------------------------- | ---------- |
| `app_bundle_identifier` | `str` | Bundle identifier of the running app. | *required* |

Returns:

| Type  | Description                                                      |
| ----- | ---------------------------------------------------------------- |
| `int` | PID of the matching process, or 0 if no such process is running. |

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
async def process_identifier_for_bundle_identifier(self, app_bundle_identifier: str) -> int:
    """
    Resolve the PID of a currently running process by its bundle identifier.

    :param app_bundle_identifier: Bundle identifier of the running app.
    :returns: PID of the matching process, or 0 if no such process is running.
    """
    return await self.service.process_identifier_for_bundle_identifier_(app_bundle_identifier)
```

### launch

```
launch(bundle_id: str, arguments: Optional[list[str]] = None, kill_existing: bool = True, start_suspended: bool = False, environment: Optional[dict[str, Any]] = None, extra_options: Optional[dict[str, Any]] = None) -> int
```

Launch an installed application by its bundle identifier.

Parameters:

| Name              | Type                       | Description                                                                                                          | Default    |
| ----------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------- | ---------- |
| `bundle_id`       | `str`                      | Bundle identifier of the app to launch.                                                                              | *required* |
| `arguments`       | `Optional[list[str]]`      | List of command-line arguments to pass to the process. Defaults to an empty list when None.                          | `None`     |
| `kill_existing`   | `bool`                     | Whether to kill an already-running instance of the app before launching (sent as the KillExisting launch option).    | `True`     |
| `start_suspended` | `bool`                     | Start the process suspended, waiting for a debugger to attach (sent as the StartSuspendedKey launch option).         | `False`    |
| `environment`     | `Optional[dict[str, Any]]` | Environment variables to set for the process. Defaults to an empty dict when None.                                   | `None`     |
| `extra_options`   | `Optional[dict[str, Any]]` | Additional launch options merged into the options dict sent to the device, overriding the defaults on key collision. | `None`     |

Returns:

| Type  | Description                        |
| ----- | ---------------------------------- |
| `int` | PID of the newly launched process. |

Raises:

| Type             | Description                                         |
| ---------------- | --------------------------------------------------- |
| `AssertionError` | If the device returns a falsy PID (launch failure). |

Source code in `pymobiledevice3/services/dvt/instruments/process_control.py`

```
async def launch(
    self,
    bundle_id: str,
    arguments: Optional[list[str]] = None,
    kill_existing: bool = True,
    start_suspended: bool = False,
    environment: Optional[dict[str, Any]] = None,
    extra_options: Optional[dict[str, Any]] = None,
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
```

## Device & application info

## pymobiledevice3.services.dvt.instruments.device_info.DeviceInfo

Bases: `DtxService[DeviceInfoService]`

Query device, process, filesystem and kernel information over the `com.apple.instruments.server.services.deviceinfo` DTX channel.

Constructed with a `DvtProvider`, e.g. `DeviceInfo(DvtProvider(service_provider))`, and used as an async context manager to open the channel.

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
class DeviceInfo(DtxService[DeviceInfoService]):
    """
    Query device, process, filesystem and kernel information over the
    `com.apple.instruments.server.services.deviceinfo` DTX channel.

    Constructed with a `DvtProvider`, e.g. ``DeviceInfo(DvtProvider(service_provider))``,
    and used as an async context manager to open the channel.
    """

    async def ls(self, path: str) -> list[str]:
        """
        List the contents of a directory on the device.

        Invokes the `directoryListingForPath:` selector.

        :param path: Absolute path of the directory to list.
        :returns: The directory entries.
        :raises DvtDirListError: If the listing fails or the device returns no result.
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
        Get the executable path of a running process.

        Invokes the `execnameForPid:` selector.

        :param pid: Process identifier.
        :returns: Full executable path of the process.
        """
        return await self.service.execname_for_pid_(pid)

    async def proclist(self) -> list[dict[str, typing.Any]]:
        """
        Get the list of running processes from the device.

        Invokes the `runningProcesses` selector. Any per-process ``startDate``
        field is normalized to a `datetime`.

        :returns: One dict of attributes per running process.
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
        Check whether a process is currently running.

        Invokes the `isRunningPid:` selector.

        :param pid: Process identifier.
        :returns: ``True`` if the process is running, ``False`` otherwise.
        """
        return await self.service.is_running_pid_(pid)

    async def system_information(self):
        """
        Get general system information.

        Invokes the `systemInformation` selector.

        :returns: Mapping of system attributes (OS build, device name, etc.).
        """
        return await self.service.system_information()

    async def hardware_information(self):
        """
        Get hardware information.

        Invokes the `hardwareInformation` selector.

        :returns: Mapping of hardware attributes (CPU count, model, etc.).
        """
        return await self.service.hardware_information()

    async def network_information(self):
        """
        Get network interface information.

        Invokes the `networkInformation` selector.

        :returns: Mapping describing the device's network interfaces.
        """
        return await self.service.network_information()

    async def mach_time_info(self):
        """
        Get the Mach absolute-time clock parameters.

        Invokes the `machTimeInfo` selector.

        :returns: Mapping with the Mach timebase and current time values.
        """
        return await self.service.mach_time_info()

    async def mach_kernel_name(self) -> str:
        """
        Get the running Mach kernel name.

        Invokes the `machKernelName` selector.

        :returns: The kernel name string.
        """
        return await self.service.mach_kernel_name()

    async def kpep_database(self) -> typing.Optional[dict[str, typing.Any]]:
        """
        Get the KPEP (kernel performance event) database.

        Invokes the `kpepDatabase` selector and parses the returned plist bytes.

        :returns: The parsed KPEP database, or ``None`` if the device returns no data.
        """
        kpep_database = await self.service.kpep_database()
        if kpep_database is not None:
            return plistlib.loads(kpep_database)

    async def trace_codes(self):
        """
        Get the kernel trace-code table.

        Invokes the `traceCodesFile` selector and parses the whitespace-separated
        ``<hex-code> <name>`` lines.

        :returns: Mapping of integer trace code to its symbolic name.
        """
        codes_file = await self.service.trace_codes_file()
        return {int(k, 16): v for k, v in (line.split() for line in codes_file.splitlines())}

    async def sysmon_process_attributes(self) -> list[str]:
        """
        Get the per-process attribute names supported by sysmontap.

        Invokes the `sysmonProcessAttributes` selector.

        :returns: The supported process attribute names.
        """
        return await self.service.sysmon_process_attributes()

    async def sysmon_system_attributes(self) -> list[str]:
        """
        Get the system-wide attribute names supported by sysmontap.

        Invokes the `sysmonSystemAttributes` selector.

        :returns: The supported system attribute names.
        """
        return await self.service.sysmon_system_attributes()

    async def name_for_uid(self, uid: int) -> str:
        """
        Resolve a user id to its user name.

        Invokes the `nameForUID:` selector.

        :param uid: Numeric user id.
        :returns: The corresponding user name.
        """
        return await self.service.name_for_uid_(uid)

    async def name_for_gid(self, gid: int) -> str:
        """
        Resolve a group id to its group name.

        Invokes the `nameForGID:` selector.

        :param gid: Numeric group id.
        :returns: The corresponding group name.
        """
        return await self.service.name_for_gid_(gid)
```

### ls

```
ls(path: str) -> list[str]
```

List the contents of a directory on the device.

Invokes the `directoryListingForPath:` selector.

Parameters:

| Name   | Type  | Description                             | Default    |
| ------ | ----- | --------------------------------------- | ---------- |
| `path` | `str` | Absolute path of the directory to list. | *required* |

Returns:

| Type        | Description            |
| ----------- | ---------------------- |
| `list[str]` | The directory entries. |

Raises:

| Type              | Description                                           |
| ----------------- | ----------------------------------------------------- |
| `DvtDirListError` | If the listing fails or the device returns no result. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def ls(self, path: str) -> list[str]:
    """
    List the contents of a directory on the device.

    Invokes the `directoryListingForPath:` selector.

    :param path: Absolute path of the directory to list.
    :returns: The directory entries.
    :raises DvtDirListError: If the listing fails or the device returns no result.
    """
    try:
        result = await self.service.directory_listing_for_path_(path)
    except DTXNsError as e:
        raise DvtDirListError() from e
    if result is None:
        raise DvtDirListError()
    return result
```

### execname_for_pid

```
execname_for_pid(pid: int) -> str
```

Get the executable path of a running process.

Invokes the `execnameForPid:` selector.

Parameters:

| Name  | Type  | Description         | Default    |
| ----- | ----- | ------------------- | ---------- |
| `pid` | `int` | Process identifier. | *required* |

Returns:

| Type  | Description                          |
| ----- | ------------------------------------ |
| `str` | Full executable path of the process. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def execname_for_pid(self, pid: int) -> str:
    """
    Get the executable path of a running process.

    Invokes the `execnameForPid:` selector.

    :param pid: Process identifier.
    :returns: Full executable path of the process.
    """
    return await self.service.execname_for_pid_(pid)
```

### proclist

```
proclist() -> list[dict[str, typing.Any]]
```

Get the list of running processes from the device.

Invokes the `runningProcesses` selector. Any per-process `startDate` field is normalized to a `datetime`.

Returns:

| Type                   | Description                                 |
| ---------------------- | ------------------------------------------- |
| `list[dict[str, Any]]` | One dict of attributes per running process. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def proclist(self) -> list[dict[str, typing.Any]]:
    """
    Get the list of running processes from the device.

    Invokes the `runningProcesses` selector. Any per-process ``startDate``
    field is normalized to a `datetime`.

    :returns: One dict of attributes per running process.
    """
    result = await self.service.running_processes()
    assert isinstance(result, list)
    for process in result:
        if "startDate" in process:
            d = process["startDate"]
            process["startDate"] = d.utc if isinstance(d, NSDate) else datetime.fromtimestamp(d)
    return result
```

### is_running_pid

```
is_running_pid(pid: int) -> bool
```

Check whether a process is currently running.

Invokes the `isRunningPid:` selector.

Parameters:

| Name  | Type  | Description         | Default    |
| ----- | ----- | ------------------- | ---------- |
| `pid` | `int` | Process identifier. | *required* |

Returns:

| Type   | Description                                      |
| ------ | ------------------------------------------------ |
| `bool` | True if the process is running, False otherwise. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def is_running_pid(self, pid: int) -> bool:
    """
    Check whether a process is currently running.

    Invokes the `isRunningPid:` selector.

    :param pid: Process identifier.
    :returns: ``True`` if the process is running, ``False`` otherwise.
    """
    return await self.service.is_running_pid_(pid)
```

### system_information

```
system_information()
```

Get general system information.

Invokes the `systemInformation` selector.

Returns:

| Type | Description                                                 |
| ---- | ----------------------------------------------------------- |
|      | Mapping of system attributes (OS build, device name, etc.). |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def system_information(self):
    """
    Get general system information.

    Invokes the `systemInformation` selector.

    :returns: Mapping of system attributes (OS build, device name, etc.).
    """
    return await self.service.system_information()
```

### hardware_information

```
hardware_information()
```

Get hardware information.

Invokes the `hardwareInformation` selector.

Returns:

| Type | Description                                              |
| ---- | -------------------------------------------------------- |
|      | Mapping of hardware attributes (CPU count, model, etc.). |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def hardware_information(self):
    """
    Get hardware information.

    Invokes the `hardwareInformation` selector.

    :returns: Mapping of hardware attributes (CPU count, model, etc.).
    """
    return await self.service.hardware_information()
```

### network_information

```
network_information()
```

Get network interface information.

Invokes the `networkInformation` selector.

Returns:

| Type | Description                                         |
| ---- | --------------------------------------------------- |
|      | Mapping describing the device's network interfaces. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def network_information(self):
    """
    Get network interface information.

    Invokes the `networkInformation` selector.

    :returns: Mapping describing the device's network interfaces.
    """
    return await self.service.network_information()
```

### mach_time_info

```
mach_time_info()
```

Get the Mach absolute-time clock parameters.

Invokes the `machTimeInfo` selector.

Returns:

| Type | Description                                             |
| ---- | ------------------------------------------------------- |
|      | Mapping with the Mach timebase and current time values. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def mach_time_info(self):
    """
    Get the Mach absolute-time clock parameters.

    Invokes the `machTimeInfo` selector.

    :returns: Mapping with the Mach timebase and current time values.
    """
    return await self.service.mach_time_info()
```

### mach_kernel_name

```
mach_kernel_name() -> str
```

Get the running Mach kernel name.

Invokes the `machKernelName` selector.

Returns:

| Type  | Description             |
| ----- | ----------------------- |
| `str` | The kernel name string. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def mach_kernel_name(self) -> str:
    """
    Get the running Mach kernel name.

    Invokes the `machKernelName` selector.

    :returns: The kernel name string.
    """
    return await self.service.mach_kernel_name()
```

### kpep_database

```
kpep_database() -> typing.Optional[dict[str, typing.Any]]
```

Get the KPEP (kernel performance event) database.

Invokes the `kpepDatabase` selector and parses the returned plist bytes.

Returns:

| Type                       | Description                                                      |
| -------------------------- | ---------------------------------------------------------------- |
| `Optional[dict[str, Any]]` | The parsed KPEP database, or None if the device returns no data. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def kpep_database(self) -> typing.Optional[dict[str, typing.Any]]:
    """
    Get the KPEP (kernel performance event) database.

    Invokes the `kpepDatabase` selector and parses the returned plist bytes.

    :returns: The parsed KPEP database, or ``None`` if the device returns no data.
    """
    kpep_database = await self.service.kpep_database()
    if kpep_database is not None:
        return plistlib.loads(kpep_database)
```

### trace_codes

```
trace_codes()
```

Get the kernel trace-code table.

Invokes the `traceCodesFile` selector and parses the whitespace-separated `<hex-code> <name>` lines.

Returns:

| Type | Description                                         |
| ---- | --------------------------------------------------- |
|      | Mapping of integer trace code to its symbolic name. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def trace_codes(self):
    """
    Get the kernel trace-code table.

    Invokes the `traceCodesFile` selector and parses the whitespace-separated
    ``<hex-code> <name>`` lines.

    :returns: Mapping of integer trace code to its symbolic name.
    """
    codes_file = await self.service.trace_codes_file()
    return {int(k, 16): v for k, v in (line.split() for line in codes_file.splitlines())}
```

### sysmon_process_attributes

```
sysmon_process_attributes() -> list[str]
```

Get the per-process attribute names supported by sysmontap.

Invokes the `sysmonProcessAttributes` selector.

Returns:

| Type        | Description                            |
| ----------- | -------------------------------------- |
| `list[str]` | The supported process attribute names. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def sysmon_process_attributes(self) -> list[str]:
    """
    Get the per-process attribute names supported by sysmontap.

    Invokes the `sysmonProcessAttributes` selector.

    :returns: The supported process attribute names.
    """
    return await self.service.sysmon_process_attributes()
```

### sysmon_system_attributes

```
sysmon_system_attributes() -> list[str]
```

Get the system-wide attribute names supported by sysmontap.

Invokes the `sysmonSystemAttributes` selector.

Returns:

| Type        | Description                           |
| ----------- | ------------------------------------- |
| `list[str]` | The supported system attribute names. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def sysmon_system_attributes(self) -> list[str]:
    """
    Get the system-wide attribute names supported by sysmontap.

    Invokes the `sysmonSystemAttributes` selector.

    :returns: The supported system attribute names.
    """
    return await self.service.sysmon_system_attributes()
```

### name_for_uid

```
name_for_uid(uid: int) -> str
```

Resolve a user id to its user name.

Invokes the `nameForUID:` selector.

Parameters:

| Name  | Type  | Description      | Default    |
| ----- | ----- | ---------------- | ---------- |
| `uid` | `int` | Numeric user id. | *required* |

Returns:

| Type  | Description                  |
| ----- | ---------------------------- |
| `str` | The corresponding user name. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def name_for_uid(self, uid: int) -> str:
    """
    Resolve a user id to its user name.

    Invokes the `nameForUID:` selector.

    :param uid: Numeric user id.
    :returns: The corresponding user name.
    """
    return await self.service.name_for_uid_(uid)
```

### name_for_gid

```
name_for_gid(gid: int) -> str
```

Resolve a group id to its group name.

Invokes the `nameForGID:` selector.

Parameters:

| Name  | Type  | Description       | Default    |
| ----- | ----- | ----------------- | ---------- |
| `gid` | `int` | Numeric group id. | *required* |

Returns:

| Type  | Description                   |
| ----- | ----------------------------- |
| `str` | The corresponding group name. |

Source code in `pymobiledevice3/services/dvt/instruments/device_info.py`

```
async def name_for_gid(self, gid: int) -> str:
    """
    Resolve a group id to its group name.

    Invokes the `nameForGID:` selector.

    :param gid: Numeric group id.
    :returns: The corresponding group name.
    """
    return await self.service.name_for_gid_(gid)
```

## pymobiledevice3.services.dvt.instruments.application_listing.ApplicationListing

Bases: `DtxService[ApplicationListingService]`

Enumerate the applications installed on the device over the `com.apple.instruments.server.services.device.applictionListing` DTX channel.

Constructed with a `DvtProvider`, e.g. `ApplicationListing(DvtProvider(service_provider))`, and used as an async context manager to open the channel.

Source code in `pymobiledevice3/services/dvt/instruments/application_listing.py`

```
class ApplicationListing(DtxService[ApplicationListingService]):
    """
    Enumerate the applications installed on the device over the
    `com.apple.instruments.server.services.device.applictionListing` DTX channel.

    Constructed with a `DvtProvider`, e.g. ``ApplicationListing(DvtProvider(service_provider))``,
    and used as an async context manager to open the channel.
    """

    async def applist(self) -> list[dict[str, Any]]:
        """
        Get the list of installed applications.

        Invokes `installedApplicationsMatching:registerUpdateToken:` with an empty
        match filter and no update token, so every installed application is returned.

        :returns: One dict of attributes per installed application.
        """
        result = await self.service.installed_applications_matching_register_update_token_({}, "")
        assert isinstance(result, list)
        return result
```

### applist

```
applist() -> list[dict[str, Any]]
```

Get the list of installed applications.

Invokes `installedApplicationsMatching:registerUpdateToken:` with an empty match filter and no update token, so every installed application is returned.

Returns:

| Type                   | Description                                       |
| ---------------------- | ------------------------------------------------- |
| `list[dict[str, Any]]` | One dict of attributes per installed application. |

Source code in `pymobiledevice3/services/dvt/instruments/application_listing.py`

```
async def applist(self) -> list[dict[str, Any]]:
    """
    Get the list of installed applications.

    Invokes `installedApplicationsMatching:registerUpdateToken:` with an empty
    match filter and no update token, so every installed application is returned.

    :returns: One dict of attributes per installed application.
    """
    result = await self.service.installed_applications_matching_register_update_token_({}, "")
    assert isinstance(result, list)
    return result
```

## Capture & telemetry

## pymobiledevice3.services.dvt.instruments.screenshot.Screenshot

Bases: `DtxService[ScreenshotService]`

Capture a screenshot of the device's screen over the `com.apple.instruments.server.services.screenshot` DTX channel.

Constructed with a `DvtProvider`, e.g. `Screenshot(DvtProvider(service_provider))`, and used as an async context manager to open the channel.

Source code in `pymobiledevice3/services/dvt/instruments/screenshot.py`

```
class Screenshot(DtxService[ScreenshotService]):
    """
    Capture a screenshot of the device's screen over the
    `com.apple.instruments.server.services.screenshot` DTX channel.

    Constructed with a `DvtProvider`, e.g. ``Screenshot(DvtProvider(service_provider))``,
    and used as an async context manager to open the channel.
    """

    async def get_screenshot(self) -> bytes:
        """
        Capture a screenshot of the current screen.

        Invokes the `takeScreenshot` selector.

        :returns: The screenshot image as raw bytes.
        """
        return await self.service.take_screenshot()
```

### get_screenshot

```
get_screenshot() -> bytes
```

Capture a screenshot of the current screen.

Invokes the `takeScreenshot` selector.

Returns:

| Type    | Description                        |
| ------- | ---------------------------------- |
| `bytes` | The screenshot image as raw bytes. |

Source code in `pymobiledevice3/services/dvt/instruments/screenshot.py`

```
async def get_screenshot(self) -> bytes:
    """
    Capture a screenshot of the current screen.

    Invokes the `takeScreenshot` selector.

    :returns: The screenshot image as raw bytes.
    """
    return await self.service.take_screenshot()
```

## pymobiledevice3.services.dvt.instruments.sysmontap.Sysmontap

Bases: `Tap`

Sample per-process and system-wide telemetry (CPU, memory, etc.) over the `com.apple.instruments.server.services.sysmontap` DTX channel.

Constructed with a `DvtProvider` (passed as `dvt`) plus the attribute lists to sample; prefer the `create` factory, which discovers the supported attributes automatically. Used as an async context manager, and is async-iterable: iterating yields the raw sample rows pushed by the device.

Source code in `pymobiledevice3/services/dvt/instruments/sysmontap.py`

```
class Sysmontap(Tap):
    """
    Sample per-process and system-wide telemetry (CPU, memory, etc.) over the
    `com.apple.instruments.server.services.sysmontap` DTX channel.

    Constructed with a `DvtProvider` (passed as ``dvt``) plus the attribute lists
    to sample; prefer the `create` factory, which discovers the supported
    attributes automatically. Used as an async context manager, and is async-iterable:
    iterating yields the raw sample rows pushed by the device.
    """

    IDENTIFIER = "com.apple.instruments.server.services.sysmontap"
    DEFAULT_INTERVAL_MS = 500
    MINIMUM_INTERVAL_MS = 1

    def __init__(
        self,
        dvt: DtxServiceProvider,
        process_attributes: list[str],
        system_attributes: list[str],
        interval_ms: int = DEFAULT_INTERVAL_MS,
    ) -> None:
        """
        :param dvt: The `DvtProvider` owning the underlying DTX connection.
        :param process_attributes: Per-process attribute names to sample (request as ``procAttrs``).
        :param system_attributes: System-wide attribute names to sample (request as ``sysAttrs``).
        :param interval_ms: Sampling interval in milliseconds.
        """
        self.process_attributes_cls = dataclasses.make_dataclass("SysmonProcessAttributes", process_attributes)
        self.system_attributes_cls = dataclasses.make_dataclass("SysmonSystemAttributes", system_attributes)

        config: dict[str, Any] = {
            # Output rate (ms): how often the device pushes a message. Matching the sampling interval
            # makes it emit once per sample instead of flooding mostly-empty updates every millisecond.
            "ur": interval_ms,
            "bm": 0,
            "procAttrs": process_attributes,
            "sysAttrs": system_attributes,
            "cpuUsage": True,
            "physFootprint": True,  # memory value
            "sampleInterval": interval_ms * 1_000_000,
        }

        super().__init__(dvt, self.IDENTIFIER, config)

    @classmethod
    async def create(cls, dvt: DtxServiceProvider, interval: int = DEFAULT_INTERVAL_MS) -> "Sysmontap":
        """
        Build a `Sysmontap` with the device's full set of supported attributes.

        Queries `DeviceInfo` for the supported sysmon process and system attribute
        names and uses them to construct the instance.

        :param dvt: The `DvtProvider` owning the underlying DTX connection.
        :param interval: Sampling interval in milliseconds.
        :returns: A configured `Sysmontap` instance, not yet connected.
        """
        async with DeviceInfo(dvt) as device_info:
            process_attributes = list(await device_info.sysmon_process_attributes())
            system_attributes = list(await device_info.sysmon_system_attributes())
        return cls(dvt, process_attributes, system_attributes, interval_ms=interval)

    async def iter_processes(self) -> AsyncGenerator[list[dict[str, Any]], None]:
        """
        Iterate per-process samples, decoded into attribute dicts.

        Consumes the raw sample rows, keeps only those carrying a ``Processes``
        entry, and maps each process's values onto the requested process
        attribute names.

        :yields: For each sample, the list of per-process attribute dicts.
        """
        async for row in self:
            if "Processes" not in row:
                continue

            entries: list[dict[str, Any]] = []

            processes = row["Processes"].items()
            for _pid, process_info in processes:
                entry = dataclasses.asdict(self.process_attributes_cls(*process_info))
                entries.append(entry)

            yield entries
```

### create

```
create(dvt: DtxServiceProvider, interval: int = DEFAULT_INTERVAL_MS) -> Sysmontap
```

Build a `Sysmontap` with the device's full set of supported attributes.

Queries `DeviceInfo` for the supported sysmon process and system attribute names and uses them to construct the instance.

Parameters:

| Name       | Type                 | Description                                           | Default               |
| ---------- | -------------------- | ----------------------------------------------------- | --------------------- |
| `dvt`      | `DtxServiceProvider` | The DvtProvider owning the underlying DTX connection. | *required*            |
| `interval` | `int`                | Sampling interval in milliseconds.                    | `DEFAULT_INTERVAL_MS` |

Returns:

| Type        | Description                                         |
| ----------- | --------------------------------------------------- |
| `Sysmontap` | A configured Sysmontap instance, not yet connected. |

Source code in `pymobiledevice3/services/dvt/instruments/sysmontap.py`

```
@classmethod
async def create(cls, dvt: DtxServiceProvider, interval: int = DEFAULT_INTERVAL_MS) -> "Sysmontap":
    """
    Build a `Sysmontap` with the device's full set of supported attributes.

    Queries `DeviceInfo` for the supported sysmon process and system attribute
    names and uses them to construct the instance.

    :param dvt: The `DvtProvider` owning the underlying DTX connection.
    :param interval: Sampling interval in milliseconds.
    :returns: A configured `Sysmontap` instance, not yet connected.
    """
    async with DeviceInfo(dvt) as device_info:
        process_attributes = list(await device_info.sysmon_process_attributes())
        system_attributes = list(await device_info.sysmon_system_attributes())
    return cls(dvt, process_attributes, system_attributes, interval_ms=interval)
```

### iter_processes

```
iter_processes() -> AsyncGenerator[list[dict[str, Any]], None]
```

Iterate per-process samples, decoded into attribute dicts.

Consumes the raw sample rows, keeps only those carrying a `Processes` entry, and maps each process's values onto the requested process attribute names.

:yields: For each sample, the list of per-process attribute dicts.

Source code in `pymobiledevice3/services/dvt/instruments/sysmontap.py`

```
async def iter_processes(self) -> AsyncGenerator[list[dict[str, Any]], None]:
    """
    Iterate per-process samples, decoded into attribute dicts.

    Consumes the raw sample rows, keeps only those carrying a ``Processes``
    entry, and maps each process's values onto the requested process
    attribute names.

    :yields: For each sample, the list of per-process attribute dicts.
    """
    async for row in self:
        if "Processes" not in row:
            continue

        entries: list[dict[str, Any]] = []

        processes = row["Processes"].items()
        for _pid, process_info in processes:
            entry = dataclasses.asdict(self.process_attributes_cls(*process_info))
            entries.append(entry)

        yield entries
```

## pymobiledevice3.services.dvt.instruments.network_monitor.NetworkMonitor

Bases: `DtxService[NetworkMonitorService]`

Monitor device network activity over the Instruments networking channel.

Constructed with a `DvtProvider`. Use as an async context manager: entering starts monitoring and exiting stops it. The object is async-iterable, yielding decoded `InterfaceDetectionEvent`, `ConnectionDetectionEvent` and `ConnectionUpdateEvent` instances as they arrive.

Source code in `pymobiledevice3/services/dvt/instruments/network_monitor.py`

```
class NetworkMonitor(DtxService[NetworkMonitorService]):
    """
    Monitor device network activity over the Instruments networking channel.

    Constructed with a `DvtProvider`. Use as an async context manager: entering starts
    monitoring and exiting stops it. The object is async-iterable, yielding decoded
    `InterfaceDetectionEvent`, `ConnectionDetectionEvent` and `ConnectionUpdateEvent`
    instances as they arrive.
    """

    def __init__(self, dvt: DtxServiceProvider):
        super().__init__(dvt)
        self.logger = logging.getLogger(__name__)

    async def __aenter__(self) -> "NetworkMonitor":
        await self.connect()
        await self.service.start_monitoring()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.service.stop_monitoring()

    async def __aiter__(self) -> AsyncIterator[Optional[NetworkMonitorEvent]]:
        """
        Decode and yield network events as they arrive from the service.

        Each raw message is dispatched by its leading message-type code. Socket addresses on
        connection-detection events are parsed into `SocketAddress` structures. Unrecognized
        or malformed payloads are logged and skipped (no event is yielded for them).

        :yields: The decoded event, or `None` when a known message type carried no payload.
        """
        while True:
            message = await self._receive_message()

            event = None

            if message is None:
                continue
            if not isinstance(message, (list, tuple)) or len(cast(Sequence[Any], message)) < 2:
                self.logger.warning(f"unsupported event payload: {message!r}")
                continue

            if message[0] == MESSAGE_TYPE_INTERFACE_DETECTION:
                event = InterfaceDetectionEvent(*cast(tuple[Any, ...], message[1]))
            elif message[0] == MESSAGE_TYPE_CONNECTION_DETECTION:
                (
                    local_address,
                    remote_address,
                    interface_index,
                    pid,
                    recv_buffer_size,
                    recv_buffer_used,
                    serial_number,
                    kind,
                ) = cast(tuple[Any, ...], message[1])
                event = ConnectionDetectionEvent(
                    local_address=SocketAddress.parse(local_address),
                    remote_address=SocketAddress.parse(remote_address),
                    interface_index=interface_index,
                    pid=pid,
                    recv_buffer_size=recv_buffer_size,
                    recv_buffer_used=recv_buffer_used,
                    serial_number=serial_number,
                    kind=kind,
                )
            elif message[0] == MESSAGE_TYPE_CONNECTION_UPDATE:
                event = ConnectionUpdateEvent(*cast(tuple[Any, ...], message[1]))
            else:
                self.logger.warning(f"unsupported event type: {message[0]}")
            yield event

    async def _receive_message(self):
        return await self.service.events.get()
```

## pymobiledevice3.services.dvt.instruments.energy_monitor.EnergyMonitor

Bases: `DtxService[EnergyMonitorService]`

Sample per-process energy usage from the Xcode debug-gauge energy provider.

Constructed with a `DvtProvider` and the list of PIDs to monitor. Use as an async context manager: entering starts sampling for those PIDs and exiting stops it. The object is async-iterable, yielding one energy-attribute sample for the monitored PIDs per iteration.

Source code in `pymobiledevice3/services/dvt/instruments/energy_monitor.py`

```
class EnergyMonitor(DtxService[EnergyMonitorService]):
    """
    Sample per-process energy usage from the Xcode debug-gauge energy provider.

    Constructed with a `DvtProvider` and the list of PIDs to monitor. Use as an async context
    manager: entering starts sampling for those PIDs and exiting stops it. The object is
    async-iterable, yielding one energy-attribute sample for the monitored PIDs per iteration.
    """

    def __init__(self, dvt: DtxServiceProvider, pid_list: list[int]) -> None:
        """
        :param dvt: The `DvtProvider` used to open the Instruments channel.
        :param pid_list: The process IDs to sample energy usage for.
        """
        super().__init__(dvt)
        self._pid_list = pid_list

    async def __aenter__(self):
        await self.connect()
        # stop monitoring if already monitored
        await self.service.stop_sampling_for_pids_(self._pid_list)

        await self.service.start_sampling_for_pids_(self._pid_list)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        await self.service.stop_sampling_for_pids_(self._pid_list)

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        """
        Sample energy attributes for the monitored PIDs indefinitely.

        :yields: The device's energy-attributes reply for the monitored PIDs, one per iteration.
        """
        while True:
            yield await self._sample_once()

    async def _sample_once(self):
        return await self.service.sample_attributes_for_pids_({}, self._pid_list)
```

## pymobiledevice3.services.dvt.instruments.network_statistics.NetworkStatistics

Bases: `DtxService[NetworkStatisticsService]`

Sample per-process network traffic from the Xcode debug-gauge network provider.

Constructed with a `DvtProvider` and the list of PIDs to monitor. Use as an async context manager: entering starts sampling for those PIDs and exiting stops it. The object is async-iterable, yielding one sample per interval that maps each PID to its counters: cumulative `net.bytes`/`net.packets` totals plus their `net.rx.*`/`net.tx.*` split, a `.delta` of each, the `pid` and the sample `time`.

Source code in `pymobiledevice3/services/dvt/instruments/network_statistics.py`

```
class NetworkStatistics(DtxService[NetworkStatisticsService]):
    """
    Sample per-process network traffic from the Xcode debug-gauge network provider.

    Constructed with a `DvtProvider` and the list of PIDs to monitor. Use as an async context
    manager: entering starts sampling for those PIDs and exiting stops it. The object is
    async-iterable, yielding one sample per interval that maps each PID to its counters:
    cumulative ``net.bytes``/``net.packets`` totals plus their ``net.rx.*``/``net.tx.*`` split,
    a ``.delta`` of each, the ``pid`` and the sample ``time``.
    """

    DEFAULT_INTERVAL_MS = 1000

    def __init__(self, dvt: DtxServiceProvider, pid_list: list[int], interval_ms: int = DEFAULT_INTERVAL_MS) -> None:
        """
        :param dvt: The `DvtProvider` used to open the Instruments channel.
        :param pid_list: The process IDs to sample network usage for.
        :param interval_ms: Interval in milliseconds between samples.
        """
        super().__init__(dvt)
        self._pid_list = pid_list
        self._interval_ms = interval_ms

    async def __aenter__(self) -> "NetworkStatistics":
        await self.connect()
        await self.service.start_sampling_for_pids_(self._pid_list)
        # Each reply carries the sample taken at the previous call, so the first one is left over
        # from whichever client sampled last.
        await self._sample_once()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.service.stop_sampling_for_pids_(self._pid_list)

    async def __aiter__(self) -> AsyncGenerator[dict[int, dict[str, Any]], None]:
        """
        Sample network counters for the monitored PIDs indefinitely.

        :yields: A mapping of PID to that process's counters, one per interval.
        """
        while True:
            await asyncio.sleep(self._interval_ms / 1000)
            sample = await self._sample_once()
            if sample:
                yield sample

    async def _sample_once(self) -> Optional[dict[int, dict[str, Any]]]:
        sample: Optional[dict[int, dict[str, Any]]] = await self.service.sample_attributes_for_pids_({}, self._pid_list)
        if sample is None:
            return None
        for record in sample.values():
            timestamp = record.get("time")
            if isinstance(timestamp, NSDate):
                record["time"] = timestamp.utc
        return sample
```

## pymobiledevice3.services.dvt.instruments.graphics.Graphics

Bases: `DtxService[GraphicsService]`

Sample GPU/OpenGL graphics performance counters over the Instruments channel.

Constructed with a `DvtProvider`. Use as an async context manager: entering starts sampling and exiting stops it. The object is async-iterable, yielding graphics sample events as they arrive from the device. `fps()` yields just the frame rate.

Source code in `pymobiledevice3/services/dvt/instruments/graphics.py`

```
class Graphics(DtxService[GraphicsService]):
    """
    Sample GPU/OpenGL graphics performance counters over the Instruments channel.

    Constructed with a `DvtProvider`. Use as an async context manager: entering starts sampling
    and exiting stops it. The object is async-iterable, yielding graphics sample events as they
    arrive from the device. `fps()` yields just the frame rate.
    """

    async def __aenter__(self):
        await self.connect()
        await self.service.start_sampling_at_time_interval_(0.0)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        await self.service.stop_sampling()

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        """
        Yield graphics sample events as they arrive from the service.

        :yields: A graphics performance sample emitted by the device.
        """
        while True:
            yield await self.service.events.get()

    async def fps(self) -> AsyncGenerator[int, None]:
        """
        Yield the Core Animation frame rate of the whole display, about once a second.

        Call it in place of iterating the object directly. The first sample arrives right after
        sampling starts and doesn't cover a full second, so it is skipped.

        :yields: Frames per second; 0 while nothing on screen changes.
        """
        first = True
        async for sample in self:
            if not isinstance(sample, dict):
                continue
            if first:
                first = False
                continue
            yield sample["CoreAnimationFramesPerSecond"]
```

### fps

```
fps() -> AsyncGenerator[int, None]
```

Yield the Core Animation frame rate of the whole display, about once a second.

Call it in place of iterating the object directly. The first sample arrives right after sampling starts and doesn't cover a full second, so it is skipped.

:yields: Frames per second; 0 while nothing on screen changes.

Source code in `pymobiledevice3/services/dvt/instruments/graphics.py`

```
async def fps(self) -> AsyncGenerator[int, None]:
    """
    Yield the Core Animation frame rate of the whole display, about once a second.

    Call it in place of iterating the object directly. The first sample arrives right after
    sampling starts and doesn't cover a full second, so it is skipped.

    :yields: Frames per second; 0 while nothing on screen changes.
    """
    first = True
    async for sample in self:
        if not isinstance(sample, dict):
            continue
        if first:
            first = False
            continue
        yield sample["CoreAnimationFramesPerSecond"]
```

## pymobiledevice3.services.dvt.instruments.activity_trace_tap.ActivityTraceTap

Bases: `Tap`

Tap the device's unified-logging / activity-trace stream over the Instruments channel.

Constructed with a `DvtProvider`. It is an async-iterable `Tap`: iterating yields decoded log entries (signposts and os_log messages) as `message` dataclass instances whose fields follow the table columns advertised by the device, plus `device_time`: the row's `time` on the device's clock as a `datetime`, or None if the device has not sent its time mapping (it does so before the first row). The underlying wire format is a stack-based opcode stream parsed incrementally; opcodes split across DTX frames are carried over and reassembled.

Source code in `pymobiledevice3/services/dvt/instruments/activity_trace_tap.py`

```
class ActivityTraceTap(Tap):
    """
    Tap the device's unified-logging / activity-trace stream over the Instruments channel.

    Constructed with a `DvtProvider`. It is an async-iterable `Tap`: iterating yields decoded
    log entries (signposts and os_log messages) as `message` dataclass instances whose fields
    follow the table columns advertised by the device, plus `device_time`: the row's `time` on the
    device's clock as a `datetime`, or None if the device has not sent its time mapping (it does so
    before the first row). The underlying wire format is a stack-based opcode stream parsed
    incrementally; opcodes split across DTX frames are carried over and reassembled.
    """

    IDENTIFIER = "com.apple.instruments.server.services.activitytracetap"

    def __init__(self, dvt: DtxServiceProvider, enable_http_archive_logging: bool = False):
        """
        :param dvt: The `DvtProvider` used to open the Instruments channel.
        :param enable_http_archive_logging: When True, request that the device also include HTTP
            archive (HAR) logging in the stream.
        """
        # TODO:
        #   reverse: [DTOSLogLoader _handleRecord:], DTTableRowEncoder::*
        #   to understand each row's structure.

        config: dict[str, Any] = {
            "bm": 0,  # buffer mode
            "combineDataScope": 0,
            "machTimebaseDenom": 3,
            "machTimebaseNumer": 125,
            "onlySignposts": 0,
            "pidToInjectCombineDYLIB": "-1",
            "predicate": "(messageType == info OR messageType == debug OR messageType == default OR "
            "messageType == error OR messageType == fault)",
            "signpostsAndLogs": 1,
            "trackPidToExecNameMapping": True,
            "enableHTTPArchiveLogging": enable_http_archive_logging,
            "targetPID": -3,  # all Process
            "trackExpiredPIDs": 1,
            "ur": 500,
        }

        super().__init__(dvt, self.IDENTIFIER, config)

        self.stack: list[Any] = []
        self.generation = 0
        self.background = 0
        self.tables: list[Table] = []
        # trailing bytes of an opcode that was split across two DTX frames
        self._carry = b""
        # the device's wall clock at one mach continuous time, from the "Time Mapping" notice
        self._time_mapping: Optional[tuple[int, float, int, int]] = None

    async def _get_next_message(self):
        message = b""
        while message.startswith(b"bplist") or len(message) == 0:
            # skip heartbeats, but keep the time mapping to stamp the rows with
            message = await self.channel.receive_message()
            if message.startswith(b"bplist"):
                self._time_mapping = _parse_time_mapping(message) or self._time_mapping
        # an opcode (and its immediate words) may be split across frames; prepend the leftover
        self._set_current_message(self._carry + message)
        self._carry = b""

    def _device_time(self, mach_continuous_time: Any) -> Optional[datetime]:
        if self._time_mapping is None or not isinstance(mach_continuous_time, bytes):
            return None
        continuous, since1970, numerator, denominator = self._time_mapping
        try:
            seconds = (int.from_bytes(mach_continuous_time, "little") - continuous) * numerator / denominator / 1e9
            return datetime.fromtimestamp(since1970 + seconds)
        except (OverflowError, OSError, ValueError):
            return None

    def _set_current_message(self, message: bytes):
        self._message = BytesIO(message)

    def _seek_relative(self, offset: int):
        self._message.seek(offset, os.SEEK_CUR)

    def _read_word(self) -> int:
        buf = self._message.read(2)
        if len(buf) != 2:
            raise EOFError()
        (word,) = struct.unpack("<H", buf)
        return word

    def _handle_push(self, word: int):
        assert word >> 14 in (0b10, 0b11), f"invalid magic for pushed item. word: {hex(word)}"

        count = 0
        imm = 0
        bit_count = 0
        while word >> 14 != 0b11:
            # not end word
            imm = (imm << 14) | (word & 0x3FFF)
            word = self._read_word()
            count += 1
            bit_count += 14

        imm = (imm << 14) | (word & 0x3FFF)
        bit_count += 14

        imm <<= 8 - bit_count % 8
        bit_count += 8 - bit_count % 8

        result = imm.to_bytes(math.ceil(bit_count / 8), "big")
        self.stack.append(result)

        return result

    def _handle_table_reset(self, word: int):
        """start new table vector"""
        self.generation += 1
        self.background = 0
        self.stack = []

    def _handle_sentinel(self, word: int):
        """push a dummy"""
        self.stack.append(None)

    def _handle_struct(self, word: int):
        """replace last `distance` items with a single one which represents them as a tuple"""
        distance = word & 0xFF

        if distance == 0xFF:
            raise NotImplementedError("long struct")

        new_item = self.stack[-distance:]

        del self.stack[-distance:]
        self.stack.append(new_item)

    def _handle_define_table(self, word: int):
        """define a table struct"""
        distance = 4

        table_raw = Table(*self.stack[-distance:])
        table = Table(
            # the raw table fields hold the undecoded bytes off the stack
            name=cast(bytes, table_raw.name).split(b"\x00", 1)[0].decode(),
            columns=[c.split(b"\x00", 1)[0].decode() for c in table_raw.columns],
            unknown0=table_raw.unknown0,
            unknown2=table_raw.unknown2,
        )
        # only the tables with a message are yielded; the rest are signpost intervals
        if "message" in table.columns:
            table.row_class = dataclasses.make_dataclass(
                "message",
                [c.replace("-", "_") for c in table.columns]
                + [("device_time", Optional[datetime], dataclasses.field(default=None))],
            )

        del self.stack[-distance:]
        self.tables.append(table)

    def _handle_debug(self, word: int):
        """pop last pushed item from stack"""
        debug_id = word & 0xFF
        item = self.stack[-1]

        reference = int.from_bytes(item, byteorder="little")

        assert reference == len(self.stack) - 1, (
            f"assert debug {debug_id} got reference: {hex(reference)} instead of: {len(self.stack) - 1}  {item}"
        )
        del self.stack[-1]

    def _handle_copy(self, word: int):
        """copy item at distance from stack"""
        distance = word & 0xFF
        if distance != 0xFF:
            item = self.stack[-distance - 1]
            self.stack.append(item)
        else:
            # long struct - pop distance from stack
            item = self.stack[-1]
            reference = int.from_bytes(item, byteorder="little") - 1
            del self.stack[-1]
            self.stack.append(self.stack[reference])

    def _handle_end_row(self, word: int):
        """flush current row"""
        generation = word & 0xFF
        table = self.tables[generation]
        row = self.stack[-len(table.columns) :]
        del self.stack[-len(table.columns) :]

        if table.row_class is None:
            return None
        message = table.row_class(*row)
        # a pushed value loses its trailing zero bits and comes back padded to whole bytes, so an integer
        # is 2 to 9 bytes long (a thread id of 0x1000000 or more decodes to 6 bytes or more)
        message.process = 0 if message.process is None else int.from_bytes(message.process[0], "little")
        message.thread = int.from_bytes(message.thread[0], "little")

        string_fields = (
            "message_type",
            "format_string",
            "subsystem",
            "category",
            "sender_image_path",
            "event_type",
            "name",
        )
        for f in string_fields:
            if hasattr(message, f):
                v = getattr(message, f)
                setattr(message, f, decode_str(v) if v else v)

        message.device_time = self._device_time(message.time)
        return message

    def _handle_placeholder_count(self, word: int):
        """remove `count` last items from stack"""
        count = word & 0xFF
        if count > 0:
            del self.stack[-count:]

    def _handle_convert_mach_continuous(self, word: int):
        """push an item and pop it. effectively do nothing"""
        pass

    def _parse(self) -> Generator[Any, None, None]:
        operations: dict[int, Callable[[int], Any]] = {
            CMD_TABLE_RESET: self._handle_table_reset,
            CMD_SENTINEL: self._handle_sentinel,
            CMD_STRUCT: self._handle_struct,
            CMD_DEFINE_TABLE: self._handle_define_table,
            CMD_DEBUG: self._handle_debug,
            CMD_COPY: self._handle_copy,
            CMD_END_ROW: self._handle_end_row,
            CMD_PLACEHOLDER_COUNT: self._handle_placeholder_count,
            CMD_CONVERT_MACH_CONTINUOUS: self._handle_convert_mach_continuous,
        }

        while True:
            # remember where this opcode begins, in case the frame ends mid-opcode
            start = self._message.tell()
            try:
                word = self._read_word()
                opcode = word >> 8

                if opcode in operations:
                    result = operations[opcode](word)
                else:
                    self._handle_push(word)
                    result = None
            except EOFError:
                # the frame ended in the middle of an opcode (e.g. a multi-word push);
                # carry the remaining bytes over to the next frame instead of crashing
                self._message.seek(start)
                self._carry = self._message.read()
                break

            if opcode == CMD_END_ROW and result is not None:
                yield result

    async def __aiter__(self) -> AsyncGenerator[Any, None]:
        """
        Continuously receive frames and yield the decoded log entries they contain.

        :yields: A dynamically generated `message` dataclass per completed row, with fields named
            after the device-advertised table columns.
        """
        while True:
            await self._get_next_message()
            for message in self._parse():
                yield message
```

## pymobiledevice3.services.dvt.instruments.core_profile_session_tap.CoreProfileSessionTap

Kdebug is a kernel facility for tracing events occurring on a system. This header defines reserved debugids, which are 32-bit values that describe each event:

+----------------+----------------+----------------------------+----+ | Class (8) | Subclass (8) | Code (14) |Func| | | | |(2) | +----------------+----------------+----------------------------+----+ \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\____/ ClassSubclass (CSC) _***************************************************************00*/ Eventid \_**************************************************************____/ Debugid

The eventid is a hierarchical ID, indicating which components an event is referring to. The debugid includes an eventid and two function qualifier bits, to determine the structural significance of an event (whether it starts or ends an interval).

This tap yields kdebug events.

Constructed with a `DvtProvider`. Use as an async context manager (`async with`): entering configures and starts the session, exiting stops it. While active it can produce a one-time stackshot and stream raw kdebug buffer chunks.

Source code in `pymobiledevice3/services/dvt/instruments/core_profile_session_tap.py`

```
class CoreProfileSessionTap:
    r"""
    Kdebug is a kernel facility for tracing events occurring on a system.
    This header defines reserved debugids, which are 32-bit values that describe
    each event:

    +----------------+----------------+----------------------------+----+
    |   Class (8)    |  Subclass (8)  |          Code (14)         |Func|
    |                |                |                            |(2) |
    +----------------+----------------+----------------------------+----+
    \_________________________________/
            ClassSubclass (CSC)
    \________________________________________________________________00_/
                                    Eventid
    \___________________________________________________________________/
                                    Debugid

    The eventid is a hierarchical ID, indicating which components an event is
    referring to.  The debugid includes an eventid and two function qualifier
    bits, to determine the structural significance of an event (whether it
    starts or ends an interval).

    This tap yields kdebug events.

    Constructed with a `DvtProvider`. Use as an async context manager (``async with``): entering
    configures and starts the session, exiting stops it. While active it can produce a one-time
    stackshot and stream raw kdebug buffer chunks.
    """

    IDENTIFIER = CoreProfileSessionTapService.IDENTIFIER

    def __init__(
        self,
        dvt: DtxServiceProvider,
        time_config: dict[str, typing.Any],
        filters: typing.Optional[set[int]] = None,
        sample_callstacks: bool = True,
    ):
        """
        :param dvt: Instruments service proxy.
        :param time_config: Timing information - numer, denom, mach_absolute_time and matching usecs_since_epoch,
        timezone.
        :param filters: Event filters to include, Include all if empty.
        :param sample_callstacks: Sample a user callstack on the filtered events. This also makes the device add
            MACH scheduler events to the trace and emit kperf sample events, which can outnumber the requested
            events by 10x and make the device drop some of them; pass ``False`` to trace only the filtered events.
        """
        self._provider = dvt
        self.time_config = time_config
        self._channel: typing.Optional[CoreProfileSessionTapChannel] = None
        self.channel: typing.Optional[TapMessageChannel] = None
        self.stack_shot: typing.Optional[dict[str, typing.Any]] = None
        self.uuid = str(uuid.uuid4())

        if filters is None:
            filters = {0xFFFFFFFF}
        trigger: dict[str, typing.Any] = {
            "kdf2": filters,  # Kdebug filter: (class << 24) | (subclass << 16), subclass 0xFF for a whole class.
            # Actions; [0] and [2] are no-ops that Instruments always sends.
            "ta": [[0], [2]],
            "tk": 3,  # Kind: kdebug trigger.
            "uuid": self.uuid,
        }
        if sample_callstacks:
            # [3]: sample on the default backtrace events of the filter (adds MACH scheduler events to the
            # trace), [1, 1, 0]: collect user (not kernel) callstacks of up to 128 frames.
            trigger["ta"] = [[3], [0], [2], [1, 1, 0]]
            trigger["csd"] = 128
        config: dict[str, typing.Any] = {
            "tc": [trigger],  # Triggers configs
            "rp": 100,  # Recording priority
            "bm": 0,  # Buffer mode.
            # Update rate (ms): how often the device flushes buffered events. Without it the device flushes
            # only every few seconds; lower values bottom out at about 200 ms of delivery latency.
            "ur": 100,
        }
        self._config = config

    async def _service_ref(self) -> CoreProfileSessionTapService:
        if self._channel is None:
            self._channel = CoreProfileSessionTapChannel(self._provider)
        await self._channel.connect()
        return self._channel.service

    async def _next_message(self) -> bytes:
        if self.channel is not None:
            return await self.channel.receive_message()
        service = await self._service_ref()
        return await service.messages.get()

    def __enter__(self):
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aenter__(self):
        service = await self._service_ref()
        await service.set_config_(self._config)
        await service.start()
        # first message is an ack
        await service.messages.get()
        return self

    async def __aexit__(self, exc_type: typing.Any, exc_val: typing.Any, exc_tb: typing.Any):
        await (await self._service_ref()).stop()

    @staticmethod
    def _raise_if_tap_start_failed(data: bytes) -> None:
        if not data.startswith(b"bplist"):
            return

        try:
            decoded = archiver.unarchive(data)
        except Exception:
            return

        if not isinstance(decoded, dict):
            return

        decoded = typing.cast(dict[typing.Any, typing.Any], decoded)
        notice = decoded.get("notice")
        status = decoded.get("status")
        if not notice:
            return

        # CoreProfile TAP emits a notice when kperf is already owned by another session.
        if isinstance(status, int) and status != 0:
            raise DvtException(f"The device could not start the core profile session: {notice}")

    async def get_stackshot(self, timeout: typing.Optional[float] = 10.0) -> dict[str, typing.Any]:
        """
        Wait for and parse the stackshot the device emits once per tap creation.

        Non-stackshot messages are discarded while waiting. The result is parsed and cached, so
        subsequent calls return the cached value immediately. Loaded images in the parsed
        stackshot are annotated with their shared-cache paths where resolvable.

        :param timeout: Seconds to wait for stackshot data; `None` waits indefinitely.
        :returns: The parsed stackshot dictionary.
        :raises ExtractingStackshotError: If the timeout elapses, or the device sends a raw
            kdebug (version 2) buffer instead of a stackshot.
        :raises DvtException: If the device reports that kperf is already owned by another session.
        """
        if self.stack_shot is not None:
            # The stackshot is sent one per TAP creation, so we cache it.
            return self.stack_shot
        started_at = time.monotonic()
        data = b""

        while not data.startswith(STACKSHOT_HEADER) and not data.startswith(RAW_VERSION2_BYTES):
            if timeout is None:
                data = await self._next_message()
            else:
                remaining = timeout - (time.monotonic() - started_at)
                if remaining <= 0:
                    raise ExtractingStackshotError("Timed out waiting for the device to send a stackshot.")
                data = await asyncio.wait_for(self._next_message(), timeout=remaining)
            self._raise_if_tap_start_failed(data)

        if data.startswith(RAW_VERSION2_BYTES):
            raise ExtractingStackshotError()

        stackshot = self.parse_stackshot(data)

        # Some stackshots (e.g. iOS 17.1) carry no system-wide shared cache entry; tasks may carry their own.
        system_shared_cache = stackshot.get("shared_cache_dyld_load_info")
        dsc_maps: dict[str, typing.Any] = {}

        for _pid, snapshot in typing.cast(dict[typing.Any, typing.Any], stackshot["task_snapshots"]).items():
            shared_cache = snapshot.get("shared_cache_dyld_load_info", system_shared_cache)
            if shared_cache is None:
                continue
            dsc_uuid = str(shared_cache["imageUUID"])
            if dsc_uuid not in dsc_maps:
                dsc_maps[dsc_uuid] = get_dsc_map(dsc_uuid)
            dsc_map = dsc_maps[dsc_uuid]
            for loaded_image in typing.cast(list[typing.Any], snapshot.get("dyld_load_info", [])):
                image_uuid = str(loaded_image["imageUUID"])
                if isinstance(dsc_map, dict) and image_uuid in dsc_map:
                    loaded_image["imagePath"] = dsc_map[image_uuid]

        self.stack_shot = stackshot

        return self.stack_shot

    async def dump(self, out: typing.BinaryIO, timeout: typing.Optional[float] = None):
        """
        Stream raw kdebug trace data from the session to a file.

        Stackshot and bplist messages are skipped; only kernel trace chunks are written.

        :param out: Binary file object to write the trace data to.
        :param timeout: Seconds to keep dumping; `None` dumps indefinitely.
        """
        start = time.time()
        while timeout is None or time.time() <= start + timeout:
            data = await self._next_message()
            if data.startswith(STACKSHOT_HEADER) or data.startswith(b"bplist"):
                # Skip not kernel trace data.
                continue
            logger.info(f"Receiving trace data ({len(data)}B)")
            out.write(data)
            out.flush()

    async def pump_kdbuf_chunks(self, chunk_queue: queue.Queue[typing.Any]) -> None:
        """
        Continuously forward received messages into a queue for consumption by a `KdBufStream`.

        Runs until cancelled or the connection ends. On termination or error the offending
        exception is placed on the queue; a `None` sentinel is always enqueued last.

        :param chunk_queue: Queue that receives each raw chunk, then any exception, then a final
            `None` sentinel.
        """
        try:
            while True:
                chunk_queue.put(await self._next_message())
        except asyncio.CancelledError:
            raise
        except ConnectionTerminatedError as e:
            chunk_queue.put(e)
        except Exception as e:
            chunk_queue.put(e)
            raise
        finally:
            chunk_queue.put(None)

    def get_kdbuf_stream(
        self,
        chunk_queue: queue.Queue[typing.Any],
        max_lag: typing.Optional[float] = None,
        on_skip: typing.Optional[typing.Callable[[int, float], None]] = None,
        on_wait: typing.Optional[typing.Callable[[], None]] = None,
        skip_behind: bool = True,
    ) -> KdBufStream:
        """
        Wrap a chunk queue in a file-like `KdBufStream` for reading the kd_buf trace.

        :param chunk_queue: Queue being fed by `pump_kdbuf_chunks`.
        :param max_lag: Skip events more than this many seconds behind real time (see `KdBufStream`); needs the
            ``numer``/``denom`` timebase in this tap's ``time_config``. `None` never skips.
        :param on_skip: Called with the number of skipped events and the lag in seconds, once per catch-up.
        :param on_wait: Called before the stream waits for the next chunk (see `KdBufStream`).
        :param skip_behind: Whether to skip the events more than `max_lag` behind, or raise `TraceLagError`.
        :returns: A seekable, readable stream over the queued kd_buf chunks.
        """
        event_seconds: typing.Optional[typing.Callable[[int], float]] = None
        if max_lag is not None:
            seconds_per_tick = int(self.time_config["numer"]) / int(self.time_config["denom"]) / 1e9

            def ticks_to_seconds(timestamp: int) -> float:
                return timestamp * seconds_per_tick

            event_seconds = ticks_to_seconds
        return KdBufStream(
            chunk_queue,
            max_lag=max_lag,
            event_seconds=event_seconds,
            on_skip=on_skip,
            on_wait=on_wait,
            skip_behind=skip_behind,
        )

    @staticmethod
    def parse_stackshot(data: bytes) -> dict[str, typing.Any]:
        """
        Parse raw KCDATA stackshot bytes into a nested dictionary.

        :param data: Raw stackshot buffer beginning with the stackshot KCDATA header.
        :returns: The stackshot contents as a dictionary.
        """
        parsed_stack_shot: dict[str, typing.Any] = {}
        jsonify_parsed_stackshot(parse_kcdata(data), parsed_stack_shot)
        return parsed_stack_shot[predefined_names["KCDATA_BUFFER_BEGIN_STACKSHOT"]]

    @staticmethod
    async def get_time_config(dvt: DtxServiceProvider) -> dict[str, typing.Any]:
        """
        Build the `time_config` mapping required to construct a `CoreProfileSessionTap`.

        Combines the device's mach timebase and absolute time with the host-visible wall-clock
        epoch and timezone offset taken from lockdown values.

        :param dvt: The `DvtProvider` used to query device info.
        :returns: A dict with `numer`, `denom`, `mach_absolute_time`, `usecs_since_epoch` and
            `timezone`.
        """
        async with DeviceInfo(dvt) as device_info:
            time_info = typing.cast(list[typing.Any], await device_info.mach_time_info())
        mach_absolute_time = time_info[0]
        numer = time_info[1]
        denom = time_info[2]

        usecs_since_epoch = dvt.lockdown.all_values.get("TimeIntervalSince1970", 0) * 1000000
        timezone_ = timezone(timedelta(seconds=dvt.lockdown.all_values.get("TimeZoneOffsetFromUTC", 0)))

        return {
            "numer": numer,
            "denom": denom,
            "mach_absolute_time": mach_absolute_time,
            "usecs_since_epoch": usecs_since_epoch,
            "timezone": timezone_,
        }

    @staticmethod
    async def get_trace_codes(dvt: DtxServiceProvider) -> dict[int, str]:
        """
        Fetch the device's kdebug trace-code table, mapping numeric debugids to symbol names.

        :param dvt: The `DvtProvider` used to query device info.
        :returns: A mapping of debugid code to its trace-code name.
        """
        async with DeviceInfo(dvt) as device_info:
            return await device_info.trace_codes()
```

### get_stackshot

```
get_stackshot(timeout: Optional[float] = 10.0) -> dict[str, typing.Any]
```

Wait for and parse the stackshot the device emits once per tap creation.

Non-stackshot messages are discarded while waiting. The result is parsed and cached, so subsequent calls return the cached value immediately. Loaded images in the parsed stackshot are annotated with their shared-cache paths where resolvable.

Parameters:

| Name      | Type              | Description                                                  | Default |
| --------- | ----------------- | ------------------------------------------------------------ | ------- |
| `timeout` | `Optional[float]` | Seconds to wait for stackshot data; None waits indefinitely. | `10.0`  |

Returns:

| Type             | Description                      |
| ---------------- | -------------------------------- |
| `dict[str, Any]` | The parsed stackshot dictionary. |

Raises:

| Type                       | Description                                                                                         |
| -------------------------- | --------------------------------------------------------------------------------------------------- |
| `ExtractingStackshotError` | If the timeout elapses, or the device sends a raw kdebug (version 2) buffer instead of a stackshot. |
| `DvtException`             | If the device reports that kperf is already owned by another session.                               |

Source code in `pymobiledevice3/services/dvt/instruments/core_profile_session_tap.py`

```
async def get_stackshot(self, timeout: typing.Optional[float] = 10.0) -> dict[str, typing.Any]:
    """
    Wait for and parse the stackshot the device emits once per tap creation.

    Non-stackshot messages are discarded while waiting. The result is parsed and cached, so
    subsequent calls return the cached value immediately. Loaded images in the parsed
    stackshot are annotated with their shared-cache paths where resolvable.

    :param timeout: Seconds to wait for stackshot data; `None` waits indefinitely.
    :returns: The parsed stackshot dictionary.
    :raises ExtractingStackshotError: If the timeout elapses, or the device sends a raw
        kdebug (version 2) buffer instead of a stackshot.
    :raises DvtException: If the device reports that kperf is already owned by another session.
    """
    if self.stack_shot is not None:
        # The stackshot is sent one per TAP creation, so we cache it.
        return self.stack_shot
    started_at = time.monotonic()
    data = b""

    while not data.startswith(STACKSHOT_HEADER) and not data.startswith(RAW_VERSION2_BYTES):
        if timeout is None:
            data = await self._next_message()
        else:
            remaining = timeout - (time.monotonic() - started_at)
            if remaining <= 0:
                raise ExtractingStackshotError("Timed out waiting for the device to send a stackshot.")
            data = await asyncio.wait_for(self._next_message(), timeout=remaining)
        self._raise_if_tap_start_failed(data)

    if data.startswith(RAW_VERSION2_BYTES):
        raise ExtractingStackshotError()

    stackshot = self.parse_stackshot(data)

    # Some stackshots (e.g. iOS 17.1) carry no system-wide shared cache entry; tasks may carry their own.
    system_shared_cache = stackshot.get("shared_cache_dyld_load_info")
    dsc_maps: dict[str, typing.Any] = {}

    for _pid, snapshot in typing.cast(dict[typing.Any, typing.Any], stackshot["task_snapshots"]).items():
        shared_cache = snapshot.get("shared_cache_dyld_load_info", system_shared_cache)
        if shared_cache is None:
            continue
        dsc_uuid = str(shared_cache["imageUUID"])
        if dsc_uuid not in dsc_maps:
            dsc_maps[dsc_uuid] = get_dsc_map(dsc_uuid)
        dsc_map = dsc_maps[dsc_uuid]
        for loaded_image in typing.cast(list[typing.Any], snapshot.get("dyld_load_info", [])):
            image_uuid = str(loaded_image["imageUUID"])
            if isinstance(dsc_map, dict) and image_uuid in dsc_map:
                loaded_image["imagePath"] = dsc_map[image_uuid]

    self.stack_shot = stackshot

    return self.stack_shot
```

### dump

```
dump(out: BinaryIO, timeout: Optional[float] = None)
```

Stream raw kdebug trace data from the session to a file.

Stackshot and bplist messages are skipped; only kernel trace chunks are written.

Parameters:

| Name      | Type              | Description                                       | Default    |
| --------- | ----------------- | ------------------------------------------------- | ---------- |
| `out`     | `BinaryIO`        | Binary file object to write the trace data to.    | *required* |
| `timeout` | `Optional[float]` | Seconds to keep dumping; None dumps indefinitely. | `None`     |

Source code in `pymobiledevice3/services/dvt/instruments/core_profile_session_tap.py`

```
async def dump(self, out: typing.BinaryIO, timeout: typing.Optional[float] = None):
    """
    Stream raw kdebug trace data from the session to a file.

    Stackshot and bplist messages are skipped; only kernel trace chunks are written.

    :param out: Binary file object to write the trace data to.
    :param timeout: Seconds to keep dumping; `None` dumps indefinitely.
    """
    start = time.time()
    while timeout is None or time.time() <= start + timeout:
        data = await self._next_message()
        if data.startswith(STACKSHOT_HEADER) or data.startswith(b"bplist"):
            # Skip not kernel trace data.
            continue
        logger.info(f"Receiving trace data ({len(data)}B)")
        out.write(data)
        out.flush()
```

### pump_kdbuf_chunks

```
pump_kdbuf_chunks(chunk_queue: Queue[Any]) -> None
```

Continuously forward received messages into a queue for consumption by a `KdBufStream`.

Runs until cancelled or the connection ends. On termination or error the offending exception is placed on the queue; a `None` sentinel is always enqueued last.

Parameters:

| Name          | Type         | Description                                                                         | Default    |
| ------------- | ------------ | ----------------------------------------------------------------------------------- | ---------- |
| `chunk_queue` | `Queue[Any]` | Queue that receives each raw chunk, then any exception, then a final None sentinel. | *required* |

Source code in `pymobiledevice3/services/dvt/instruments/core_profile_session_tap.py`

```
async def pump_kdbuf_chunks(self, chunk_queue: queue.Queue[typing.Any]) -> None:
    """
    Continuously forward received messages into a queue for consumption by a `KdBufStream`.

    Runs until cancelled or the connection ends. On termination or error the offending
    exception is placed on the queue; a `None` sentinel is always enqueued last.

    :param chunk_queue: Queue that receives each raw chunk, then any exception, then a final
        `None` sentinel.
    """
    try:
        while True:
            chunk_queue.put(await self._next_message())
    except asyncio.CancelledError:
        raise
    except ConnectionTerminatedError as e:
        chunk_queue.put(e)
    except Exception as e:
        chunk_queue.put(e)
        raise
    finally:
        chunk_queue.put(None)
```

### get_kdbuf_stream

```
get_kdbuf_stream(chunk_queue: Queue[Any], max_lag: Optional[float] = None, on_skip: Optional[Callable[[int, float], None]] = None, on_wait: Optional[Callable[[], None]] = None, skip_behind: bool = True) -> KdBufStream
```

Wrap a chunk queue in a file-like `KdBufStream` for reading the kd_buf trace.

Parameters:

| Name          | Type                                     | Description                                                                                                                                             | Default    |
| ------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `chunk_queue` | `Queue[Any]`                             | Queue being fed by pump_kdbuf_chunks.                                                                                                                   | *required* |
| `max_lag`     | `Optional[float]`                        | Skip events more than this many seconds behind real time (see KdBufStream); needs the numer/denom timebase in this tap's time_config. None never skips. | `None`     |
| `on_skip`     | `Optional[Callable[[int, float], None]]` | Called with the number of skipped events and the lag in seconds, once per catch-up.                                                                     | `None`     |
| `on_wait`     | `Optional[Callable[[], None]]`           | Called before the stream waits for the next chunk (see KdBufStream).                                                                                    | `None`     |
| `skip_behind` | `bool`                                   | Whether to skip the events more than max_lag behind, or raise TraceLagError.                                                                            | `True`     |

Returns:

| Type          | Description                                                |
| ------------- | ---------------------------------------------------------- |
| `KdBufStream` | A seekable, readable stream over the queued kd_buf chunks. |

Source code in `pymobiledevice3/services/dvt/instruments/core_profile_session_tap.py`

```
def get_kdbuf_stream(
    self,
    chunk_queue: queue.Queue[typing.Any],
    max_lag: typing.Optional[float] = None,
    on_skip: typing.Optional[typing.Callable[[int, float], None]] = None,
    on_wait: typing.Optional[typing.Callable[[], None]] = None,
    skip_behind: bool = True,
) -> KdBufStream:
    """
    Wrap a chunk queue in a file-like `KdBufStream` for reading the kd_buf trace.

    :param chunk_queue: Queue being fed by `pump_kdbuf_chunks`.
    :param max_lag: Skip events more than this many seconds behind real time (see `KdBufStream`); needs the
        ``numer``/``denom`` timebase in this tap's ``time_config``. `None` never skips.
    :param on_skip: Called with the number of skipped events and the lag in seconds, once per catch-up.
    :param on_wait: Called before the stream waits for the next chunk (see `KdBufStream`).
    :param skip_behind: Whether to skip the events more than `max_lag` behind, or raise `TraceLagError`.
    :returns: A seekable, readable stream over the queued kd_buf chunks.
    """
    event_seconds: typing.Optional[typing.Callable[[int], float]] = None
    if max_lag is not None:
        seconds_per_tick = int(self.time_config["numer"]) / int(self.time_config["denom"]) / 1e9

        def ticks_to_seconds(timestamp: int) -> float:
            return timestamp * seconds_per_tick

        event_seconds = ticks_to_seconds
    return KdBufStream(
        chunk_queue,
        max_lag=max_lag,
        event_seconds=event_seconds,
        on_skip=on_skip,
        on_wait=on_wait,
        skip_behind=skip_behind,
    )
```

### parse_stackshot

```
parse_stackshot(data: bytes) -> dict[str, typing.Any]
```

Parse raw KCDATA stackshot bytes into a nested dictionary.

Parameters:

| Name   | Type    | Description                                                      | Default    |
| ------ | ------- | ---------------------------------------------------------------- | ---------- |
| `data` | `bytes` | Raw stackshot buffer beginning with the stackshot KCDATA header. | *required* |

Returns:

| Type             | Description                             |
| ---------------- | --------------------------------------- |
| `dict[str, Any]` | The stackshot contents as a dictionary. |

Source code in `pymobiledevice3/services/dvt/instruments/core_profile_session_tap.py`

```
@staticmethod
def parse_stackshot(data: bytes) -> dict[str, typing.Any]:
    """
    Parse raw KCDATA stackshot bytes into a nested dictionary.

    :param data: Raw stackshot buffer beginning with the stackshot KCDATA header.
    :returns: The stackshot contents as a dictionary.
    """
    parsed_stack_shot: dict[str, typing.Any] = {}
    jsonify_parsed_stackshot(parse_kcdata(data), parsed_stack_shot)
    return parsed_stack_shot[predefined_names["KCDATA_BUFFER_BEGIN_STACKSHOT"]]
```

### get_time_config

```
get_time_config(dvt: DtxServiceProvider) -> dict[str, typing.Any]
```

Build the `time_config` mapping required to construct a `CoreProfileSessionTap`.

Combines the device's mach timebase and absolute time with the host-visible wall-clock epoch and timezone offset taken from lockdown values.

Parameters:

| Name  | Type                 | Description                                | Default    |
| ----- | -------------------- | ------------------------------------------ | ---------- |
| `dvt` | `DtxServiceProvider` | The DvtProvider used to query device info. | *required* |

Returns:

| Type             | Description                                                                   |
| ---------------- | ----------------------------------------------------------------------------- |
| `dict[str, Any]` | A dict with numer, denom, mach_absolute_time, usecs_since_epoch and timezone. |

Source code in `pymobiledevice3/services/dvt/instruments/core_profile_session_tap.py`

```
@staticmethod
async def get_time_config(dvt: DtxServiceProvider) -> dict[str, typing.Any]:
    """
    Build the `time_config` mapping required to construct a `CoreProfileSessionTap`.

    Combines the device's mach timebase and absolute time with the host-visible wall-clock
    epoch and timezone offset taken from lockdown values.

    :param dvt: The `DvtProvider` used to query device info.
    :returns: A dict with `numer`, `denom`, `mach_absolute_time`, `usecs_since_epoch` and
        `timezone`.
    """
    async with DeviceInfo(dvt) as device_info:
        time_info = typing.cast(list[typing.Any], await device_info.mach_time_info())
    mach_absolute_time = time_info[0]
    numer = time_info[1]
    denom = time_info[2]

    usecs_since_epoch = dvt.lockdown.all_values.get("TimeIntervalSince1970", 0) * 1000000
    timezone_ = timezone(timedelta(seconds=dvt.lockdown.all_values.get("TimeZoneOffsetFromUTC", 0)))

    return {
        "numer": numer,
        "denom": denom,
        "mach_absolute_time": mach_absolute_time,
        "usecs_since_epoch": usecs_since_epoch,
        "timezone": timezone_,
    }
```

### get_trace_codes

```
get_trace_codes(dvt: DtxServiceProvider) -> dict[int, str]
```

Fetch the device's kdebug trace-code table, mapping numeric debugids to symbol names.

Parameters:

| Name  | Type                 | Description                                | Default    |
| ----- | -------------------- | ------------------------------------------ | ---------- |
| `dvt` | `DtxServiceProvider` | The DvtProvider used to query device info. | *required* |

Returns:

| Type             | Description                                       |
| ---------------- | ------------------------------------------------- |
| `dict[int, str]` | A mapping of debugid code to its trace-code name. |

Source code in `pymobiledevice3/services/dvt/instruments/core_profile_session_tap.py`

```
@staticmethod
async def get_trace_codes(dvt: DtxServiceProvider) -> dict[int, str]:
    """
    Fetch the device's kdebug trace-code table, mapping numeric debugids to symbol names.

    :param dvt: The `DvtProvider` used to query device info.
    :returns: A mapping of debugid code to its trace-code name.
    """
    async with DeviceInfo(dvt) as device_info:
        return await device_info.trace_codes()
```

## pymobiledevice3.services.dvt.instruments.notifications.Notifications

Bases: `DtxService[NotificationsService]`

Stream application-state and memory notifications from the device over the `com.apple.instruments.server.services.mobilenotifications` DTX channel.

Constructed with a `DvtProvider`, e.g. `Notifications(DvtProvider(service_provider))`. Entering the async context manager opens the channel and enables both application-state and memory notifications; exiting disables them. The class is async-iterable: iterating yields each notification payload as the device pushes it.

Source code in `pymobiledevice3/services/dvt/instruments/notifications.py`

```
class Notifications(DtxService[NotificationsService]):
    """
    Stream application-state and memory notifications from the device over the
    `com.apple.instruments.server.services.mobilenotifications` DTX channel.

    Constructed with a `DvtProvider`, e.g. ``Notifications(DvtProvider(service_provider))``.
    Entering the async context manager opens the channel and enables both
    application-state and memory notifications; exiting disables them. The class
    is async-iterable: iterating yields each notification payload as the device
    pushes it.
    """

    async def __aenter__(self):
        await self.connect()
        await self.service.set_application_state_notifications_enabled_(True)
        await self.service.set_memory_notifications_enabled_(True)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any):
        await self.service.set_application_state_notifications_enabled_(False)
        await self.service.set_memory_notifications_enabled_(False)

    async def __aiter__(self) -> typing.AsyncGenerator[Any, None]:
        while True:
            yield await self.service.events.get()
```

## Conditions & location

## pymobiledevice3.services.dvt.instruments.condition_inducer.ConditionInducer

Bases: `DtxService[ConditionInducerService]`

Induce simulated device conditions (such as degraded network or thermal states) via the Instruments ConditionInducer channel.

Constructed with a `DvtProvider`. A single condition can be active at a time; enabling one replaces any previously active condition.

Source code in `pymobiledevice3/services/dvt/instruments/condition_inducer.py`

```
class ConditionInducer(DtxService[ConditionInducerService]):
    """
    Induce simulated device conditions (such as degraded network or thermal states) via the
    Instruments ConditionInducer channel.

    Constructed with a `DvtProvider`. A single condition can be active at a time; enabling one
    replaces any previously active condition.
    """

    def __init__(self, dvt: DtxServiceProvider):
        super().__init__(dvt)
        self.logger = logging.getLogger(__name__)

    async def list(self) -> list[dict[str, Any]]:
        """
        List the condition groups available on the device.

        :returns: The available condition inducers, each a group dict containing an `identifier`
            and a list of selectable `profiles`.
        """
        return await self.service.available_condition_inducers()

    async def set(self, profile_identifier: str):
        """
        Activate the condition profile with the given identifier.

        Searches every available group for a profile whose identifier matches, then enables it.

        :param profile_identifier: Identifier of the profile to activate.
        :raises PyMobileDevice3Exception: If no available profile matches `profile_identifier`.
        """
        for group in await self.list():
            for profile in cast(list[dict[str, Any]], group.get("profiles")):
                if profile_identifier == profile.get("identifier"):
                    self.logger.info(profile.get("description"))
                    await self.service.enable_condition_with_identifier_profile_identifier_(
                        cast(str, group.get("identifier")), cast(str, profile.get("identifier"))
                    )
                    return
        raise PyMobileDevice3Exception(
            f"No condition profile is named {profile_identifier!r}. Run `developer dvt condition list` to see the available ones."
        )

    async def clear(self):
        """Disable the currently active condition, returning the device to normal behavior."""
        await self.service.disable_active_condition()
```

### list

```
list() -> list[dict[str, Any]]
```

List the condition groups available on the device.

Returns:

| Type                   | Description                                                                                                     |
| ---------------------- | --------------------------------------------------------------------------------------------------------------- |
| `list[dict[str, Any]]` | The available condition inducers, each a group dict containing an identifier and a list of selectable profiles. |

Source code in `pymobiledevice3/services/dvt/instruments/condition_inducer.py`

```
async def list(self) -> list[dict[str, Any]]:
    """
    List the condition groups available on the device.

    :returns: The available condition inducers, each a group dict containing an `identifier`
        and a list of selectable `profiles`.
    """
    return await self.service.available_condition_inducers()
```

### set

```
set(profile_identifier: str)
```

Activate the condition profile with the given identifier.

Searches every available group for a profile whose identifier matches, then enables it.

Parameters:

| Name                 | Type  | Description                            | Default    |
| -------------------- | ----- | -------------------------------------- | ---------- |
| `profile_identifier` | `str` | Identifier of the profile to activate. | *required* |

Raises:

| Type                       | Description                                         |
| -------------------------- | --------------------------------------------------- |
| `PyMobileDevice3Exception` | If no available profile matches profile_identifier. |

Source code in `pymobiledevice3/services/dvt/instruments/condition_inducer.py`

```
async def set(self, profile_identifier: str):
    """
    Activate the condition profile with the given identifier.

    Searches every available group for a profile whose identifier matches, then enables it.

    :param profile_identifier: Identifier of the profile to activate.
    :raises PyMobileDevice3Exception: If no available profile matches `profile_identifier`.
    """
    for group in await self.list():
        for profile in cast(list[dict[str, Any]], group.get("profiles")):
            if profile_identifier == profile.get("identifier"):
                self.logger.info(profile.get("description"))
                await self.service.enable_condition_with_identifier_profile_identifier_(
                    cast(str, group.get("identifier")), cast(str, profile.get("identifier"))
                )
                return
    raise PyMobileDevice3Exception(
        f"No condition profile is named {profile_identifier!r}. Run `developer dvt condition list` to see the available ones."
    )
```

### clear

```
clear()
```

Disable the currently active condition, returning the device to normal behavior.

Source code in `pymobiledevice3/services/dvt/instruments/condition_inducer.py`

```
async def clear(self):
    """Disable the currently active condition, returning the device to normal behavior."""
    await self.service.disable_active_condition()
```

## pymobiledevice3.services.dvt.instruments.location_simulation.LocationSimulation

Bases: `DtxService[LocationSimulationService]`, `LocationSimulationBase`

Override the device's reported GPS location over the `com.apple.instruments.server.services.LocationSimulation` DTX channel.

Constructed with a `DvtProvider`, e.g. `LocationSimulation(DvtProvider(service_provider))`, and used as an async context manager to open the channel.

Source code in `pymobiledevice3/services/dvt/instruments/location_simulation.py`

```
class LocationSimulation(DtxService[LocationSimulationService], LocationSimulationBase):
    """
    Override the device's reported GPS location over the
    `com.apple.instruments.server.services.LocationSimulation` DTX channel.

    Constructed with a `DvtProvider`, e.g. ``LocationSimulation(DvtProvider(service_provider))``,
    and used as an async context manager to open the channel.
    """

    def __init__(self, dvt: DtxServiceProvider):
        super().__init__(dvt)
        LocationSimulationBase.__init__(self)

    async def set(self, latitude: float, longitude: float) -> None:
        """
        Simulate the device being at the given coordinates.

        Invokes the `simulateLocationWithLatitude:longitude:` selector.

        :param latitude: Latitude in decimal degrees.
        :param longitude: Longitude in decimal degrees.
        """
        await self.service.simulate_location_with_latitude_longitude_(latitude, longitude)

    async def clear(self) -> None:
        """
        Stop simulating the location and restore the device's real GPS.

        Invokes the `stopLocationSimulation` selector.
        """
        await self.service.stop_location_simulation()
```

### set

```
set(latitude: float, longitude: float) -> None
```

Simulate the device being at the given coordinates.

Invokes the `simulateLocationWithLatitude:longitude:` selector.

Parameters:

| Name        | Type    | Description                   | Default    |
| ----------- | ------- | ----------------------------- | ---------- |
| `latitude`  | `float` | Latitude in decimal degrees.  | *required* |
| `longitude` | `float` | Longitude in decimal degrees. | *required* |

Source code in `pymobiledevice3/services/dvt/instruments/location_simulation.py`

```
async def set(self, latitude: float, longitude: float) -> None:
    """
    Simulate the device being at the given coordinates.

    Invokes the `simulateLocationWithLatitude:longitude:` selector.

    :param latitude: Latitude in decimal degrees.
    :param longitude: Longitude in decimal degrees.
    """
    await self.service.simulate_location_with_latitude_longitude_(latitude, longitude)
```

### clear

```
clear() -> None
```

Stop simulating the location and restore the device's real GPS.

Invokes the `stopLocationSimulation` selector.

Source code in `pymobiledevice3/services/dvt/instruments/location_simulation.py`

```
async def clear(self) -> None:
    """
    Stop simulating the location and restore the device's real GPS.

    Invokes the `stopLocationSimulation` selector.
    """
    await self.service.stop_location_simulation()
```
