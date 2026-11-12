# Lockdown services

Every service takes a service provider and is used as an async context manager. Most derive from `LockdownService`; `CrashReportsManager` instead wraps other services. See the [Python API guide](https://doronz88.github.io/pymobiledevice3/latest/guides/python-api/#2-the-service-pattern) for the pattern.

## Base class

## pymobiledevice3.services.lockdown_service.LockdownService

Base class for all services that wrap a single lockdown service on the device.

A subclass binds to a named lockdown service (`service_name`) and is constructed with a `LockdownServiceProvider` (a lockdown client or an RSD/tunnel provider) that knows how to reach the device. The underlying service connection is established lazily: it is opened on first use, on an explicit `connect` call, or on entering the async context manager, and is closed on `close` or on exit.

Instances are intended to be used as async context managers::

```
async with SomeService(lockdown) as service:
    ...
```

Attributes:

| Name           | Type                      | Description                                                      |
| -------------- | ------------------------- | ---------------------------------------------------------------- |
| `service_name` | `str`                     | name of the wrapped lockdown service.                            |
| `lockdown`     | `LockdownServiceProvider` | service provider used to start the service and reach the device. |
| `logger`       | `Logger`                  | logger named after the subclass module.                          |

Source code in `pymobiledevice3/services/lockdown_service.py`

```
class LockdownService:
    """
    Base class for all services that wrap a single lockdown service on the device.

    A subclass binds to a named lockdown service (``service_name``) and is constructed with a
    `LockdownServiceProvider` (a lockdown client
    or an RSD/tunnel provider) that knows how to reach the device. The underlying service
    connection is established lazily: it is opened on first use, on an explicit `connect`
    call, or on entering the async context manager, and is closed on `close` or on exit.

    Instances are intended to be used as async context managers::

        async with SomeService(lockdown) as service:
            ...

    :ivar service_name: name of the wrapped lockdown service.
    :ivar lockdown: service provider used to start the service and reach the device.
    :ivar logger: logger named after the subclass module.
    """

    # The service's name over a direct lockdown connection, and over RSD; used when no
    # ``service_name`` is given.
    SERVICE_NAME: ClassVar[str]
    RSD_SERVICE_NAME: ClassVar[str]

    def __init__(
        self,
        lockdown: LockdownServiceProvider,
        service_name: Optional[str] = None,
        is_developer_service: bool = False,
        service: Optional[ServiceConnection] = None,
        include_escrow_bag: bool = False,
    ) -> None:
        """
        :param lockdown: service provider used to start the service and communicate with the device.
        :param service_name: name of the lockdown service to wrap; started lazily on first connection.
            Defaults to ``SERVICE_NAME`` over a `LockdownClient` and ``RSD_SERVICE_NAME`` otherwise.
        :param is_developer_service: when True, the service is started via the developer-service path,
            which requires the DeveloperDiskImage to be mounted.
        :param service: an already-established service connection. When provided, no connection is
            started; otherwise a connection to ``service_name`` is opened lazily.
        :param include_escrow_bag: when True, include the host escrow bag when starting the service.
        """
        self._is_developer_service = is_developer_service
        self._include_escrow_bag = include_escrow_bag
        if service_name is None:
            service_name = self.SERVICE_NAME if isinstance(lockdown, LockdownClient) else self.RSD_SERVICE_NAME
        self.service_name: str = service_name
        self.lockdown: LockdownServiceProvider = lockdown
        self._service: Optional[ServiceConnection] = service
        self._service_proxy = _LazyServiceConnection(self)
        self.logger: logging.Logger = logging.getLogger(self.__module__)
        # Shared Future: the first connect() call creates it; concurrent callers join it
        # instead of racing to call start_lockdown_service() multiple times.
        self._connect_future: Optional[asyncio.Future[None]] = None

    @property
    def service(self) -> Union[ServiceConnection, _LazyServiceConnection]:
        """
        The wrapped service connection.

        :returns: the established `ServiceConnection`
            if already connected, otherwise a lazy proxy that connects on first awaited use.
        """
        if self._service is not None:
            return self._service
        return self._service_proxy

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        await self.close()

    async def close(self) -> None:
        """Close the underlying service connection (if any) and reset connection state."""
        if self._service is not None:
            await self._service.close()
            self._service = None
        self._connect_future = None

    async def connect(self) -> None:
        """
        Start and connect the wrapped service if not already connected.

        Does nothing when a connection already exists. Concurrent callers share a single
        in-flight connection attempt rather than starting the service multiple times; on
        failure the attempt is reset so it may be retried.

        :raises StartServiceError: if the service fails to start.
        """
        if self._service is not None:
            return
        if self._connect_future is not None:
            return await self._connect_future
        fut = asyncio.get_running_loop().create_future()
        self._connect_future = fut
        start_service = (
            self.lockdown.start_lockdown_developer_service
            if self._is_developer_service
            else self.lockdown.start_lockdown_service
        )
        try:
            self._service = await start_service(self.service_name, include_escrow_bag=self._include_escrow_bag)
            fut.set_result(None)
        except BaseException as e:
            self._connect_future = None  # allow retry
            if isinstance(e, asyncio.CancelledError):
                fut.cancel()
            else:
                fut.set_exception(e)
                fut.exception()  # prevent "Future exception was never retrieved" warning
            raise
```

### service

```
service: Union[ServiceConnection, _LazyServiceConnection]
```

The wrapped service connection.

Returns:

| Type                                               | Description                                                                                                        |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `Union[ServiceConnection, _LazyServiceConnection]` | the established ServiceConnection if already connected, otherwise a lazy proxy that connects on first awaited use. |

### close

```
close() -> None
```

Close the underlying service connection (if any) and reset connection state.

Source code in `pymobiledevice3/services/lockdown_service.py`

```
async def close(self) -> None:
    """Close the underlying service connection (if any) and reset connection state."""
    if self._service is not None:
        await self._service.close()
        self._service = None
    self._connect_future = None
```

### connect

```
connect() -> None
```

Start and connect the wrapped service if not already connected.

Does nothing when a connection already exists. Concurrent callers share a single in-flight connection attempt rather than starting the service multiple times; on failure the attempt is reset so it may be retried.

Raises:

| Type                | Description                    |
| ------------------- | ------------------------------ |
| `StartServiceError` | if the service fails to start. |

Source code in `pymobiledevice3/services/lockdown_service.py`

```
async def connect(self) -> None:
    """
    Start and connect the wrapped service if not already connected.

    Does nothing when a connection already exists. Concurrent callers share a single
    in-flight connection attempt rather than starting the service multiple times; on
    failure the attempt is reset so it may be retried.

    :raises StartServiceError: if the service fails to start.
    """
    if self._service is not None:
        return
    if self._connect_future is not None:
        return await self._connect_future
    fut = asyncio.get_running_loop().create_future()
    self._connect_future = fut
    start_service = (
        self.lockdown.start_lockdown_developer_service
        if self._is_developer_service
        else self.lockdown.start_lockdown_service
    )
    try:
        self._service = await start_service(self.service_name, include_escrow_bag=self._include_escrow_bag)
        fut.set_result(None)
    except BaseException as e:
        self._connect_future = None  # allow retry
        if isinstance(e, asyncio.CancelledError):
            fut.cancel()
        else:
            fut.set_exception(e)
            fut.exception()  # prevent "Future exception was never retrieved" warning
        raise
```

## Common services

## pymobiledevice3.services.os_trace.OsTraceService

Bases: `LockdownService`

Client for the device's `com.apple.os_trace_relay` service.

Provides API for the following operations:

- List the running processes (pid to process name mapping).
- Stream live syslog entries in binary form, optionally filtered by pid.
- Retrieve the device's stored log archive (the contents of the `/var/db/diagnostics` directory), either as a raw PAX-format tar stream or extracted into a `.logarchive` directory consumable by `log` / Console.

The service is reached over the classic lockdown service on `SERVICE_NAME`, or over the RemoteServiceDiscovery shim (`RSD_SERVICE_NAME`) when a non-`LockdownClient` provider is supplied.

Source code in `pymobiledevice3/services/os_trace.py`

```
class OsTraceService(LockdownService):
    """
    Client for the device's ``com.apple.os_trace_relay`` service.

    Provides API for the following operations:

    * List the running processes (pid to process name mapping).
    * Stream live syslog entries in binary form, optionally filtered by pid.
    * Retrieve the device's stored log archive (the contents of the ``/var/db/diagnostics``
      directory), either as a raw PAX-format tar stream or extracted into a ``.logarchive``
      directory consumable by ``log`` / Console.

    The service is reached over the classic lockdown service on `SERVICE_NAME`, or over the
    RemoteServiceDiscovery shim (`RSD_SERVICE_NAME`) when a non-`LockdownClient`
    provider is supplied.
    """

    SERVICE_NAME = "com.apple.os_trace_relay"
    RSD_SERVICE_NAME = "com.apple.os_trace_relay.shim.remote"

    async def get_pid_list(self):
        """
        Request the device's process list.

        :returns: The decoded ``PidList`` response plist. Its ``Payload`` entry maps each pid to a
            dict of per-process metadata (such as ``ProcessName``).
        """
        await self.connect()
        await self.service.send_plist({"Request": "PidList"})

        # ignore first received unknown byte
        await self.service.recvall(1)

        response = await self.service.recv_prefixed()
        return plistlib.loads(response)

    async def create_archive(
        self,
        out: typing.IO[bytes],
        size_limit: typing.Optional[int] = None,
        age_limit: typing.Optional[int] = None,
        start_time: typing.Optional[int] = None,
    ):
        """
        Request a log archive from the device and stream its raw bytes into ``out``.

        The device returns the archive as a PAX-format tar stream (the contents of
        ``/var/db/diagnostics``), which is written to ``out`` in chunks until the connection is
        terminated. Use `collect` instead to obtain an extracted ``.logarchive`` directory.

        :param out: A writable binary file-like object to receive the archive bytes.
        :param size_limit: Optional maximum archive size in bytes.
        :param age_limit: Optional maximum age, in days, of entries to include.
        :param start_time: Optional earliest entry time, as a unix timestamp.
        :raises ProtocolError: If the device does not acknowledge the request with a successful status.
        """
        request: dict[str, typing.Any] = {"Request": "CreateArchive"}

        if size_limit is not None:
            request.update({"SizeLimit": size_limit})

        if age_limit is not None:
            request.update({"AgeLimit": age_limit})

        if start_time is not None:
            request.update({"StartTime": start_time})

        await self.connect()
        await self.service.send_plist(request)

        response = await self.service.recvall(1)
        if response[0] != 1:
            raise ProtocolError(f"The device sent an unexpected reply to the log archive request: {response.hex()}")

        status = plistlib.loads(await self.service.recv_prefixed()).get("Status")
        if status != "RequestSuccessful":
            raise ProtocolError(f"The device refused to create the log archive: {status}")

        while True:
            try:
                magic = await self.service.recvall(1)
            except ConnectionTerminatedError:
                break
            if magic[0] != 3:
                raise ProtocolError(f"The device sent a malformed log stream (unexpected chunk marker): {magic.hex()}")
            out.write(await self.service.recv_prefixed(endianity="<"))

    async def collect(
        self,
        out: str,
        size_limit: typing.Optional[int] = None,
        age_limit: typing.Optional[int] = None,
        start_time: typing.Optional[int] = None,
    ) -> None:
        """
        Collect the device's system logs into a ``.logarchive`` that can be inspected later with
        tools such as ``log`` or Console.

        Internally calls `create_archive` to fetch the tar stream into a temporary file, then
        extracts it into the ``out`` directory.

        :param out: Destination directory path into which the archive is extracted.
        :param size_limit: Optional maximum archive size in bytes.
        :param age_limit: Optional maximum age, in days, of entries to include.
        :param start_time: Optional earliest entry time, as a unix timestamp.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            file = Path(temp_dir) / "foo.tar"
            with open(file, "wb") as f:
                await self.create_archive(f, size_limit=size_limit, age_limit=age_limit, start_time=start_time)
            # Extract only ordinary files and directories, each kept beneath `out`. extractall()
            # is unsafe with a device-supplied archive before Python 3.14 (absolute names, `..`,
            # links), and a logarchive holds nothing but files and directories anyway.
            out_path = Path(out)
            with TarFile(file) as archive:
                for member in archive:
                    destination = resolve_device_path(out_path, member.name)
                    if member.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                    elif member.isreg():
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        source = archive.extractfile(member)
                        if source is None:
                            raise DevicePathError(f"the log archive entry has no data: {member.name!r}")
                        with source, destination.open("wb") as target:
                            shutil.copyfileobj(source, target)
                    else:
                        raise DevicePathError(
                            f"the log archive holds an entry that is neither a file nor a directory: {member.name!r}"
                        )

    async def syslog(
        self,
        pid: int = -1,
        message_filter: int = OS_TRACE_RELAY_MESSAGE_FILTER_ALL,
        stream_flags: int = OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT,
    ) -> typing.AsyncGenerator[SyslogEntry, None]:
        """
        Stream live syslog entries from the device.

        Starts an activity stream on the device and yields each incoming record, parsed via
        `parse_syslog_entry`, indefinitely until the caller stops iterating or the connection
        drops.

        :param pid: Restrict the stream to a single process by pid; ``-1`` (the default) streams
            entries from all processes.
        :param message_filter: Bitmask selecting which message levels to receive; defaults to
            `OS_TRACE_RELAY_MESSAGE_FILTER_ALL` (all levels).
        :param stream_flags: Bitmask of `OsActivityStreamFlag` values controlling stream
            contents and decoding; defaults to `OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT`.
        :yields: Each decoded log entry as it arrives.
        :raises ProtocolError: If the device rejects the stream-start request.
        """
        await self.connect()
        await self.service.send_plist({
            "Request": "StartActivity",
            "MessageFilter": message_filter,
            "Pid": pid,
            "StreamFlags": stream_flags,
        })

        (length_length,) = struct.unpack("<I", await self.service.recvall(4))
        length = int((await self.service.recvall(length_length))[::-1].hex(), 16)
        response = plistlib.loads(await self.service.recvall(length))

        if response.get("Status") != "RequestSuccessful":
            raise ProtocolError(f"The device refused to start the log stream: {response}")

        while True:
            magic = await self.service.recvall(1)
            if magic != b"\x02":
                raise ProtocolError(f"The device sent a malformed log stream (unexpected chunk marker): {magic.hex()}")
            (length,) = struct.unpack("<I", await self.service.recvall(4))
            line = await self.service.recvall(length)
            yield parse_syslog_entry(line)
```

### get_pid_list

```
get_pid_list()
```

Request the device's process list.

Returns:

| Type | Description                                                                                                                  |
| ---- | ---------------------------------------------------------------------------------------------------------------------------- |
|      | The decoded PidList response plist. Its Payload entry maps each pid to a dict of per-process metadata (such as ProcessName). |

Source code in `pymobiledevice3/services/os_trace.py`

```
async def get_pid_list(self):
    """
    Request the device's process list.

    :returns: The decoded ``PidList`` response plist. Its ``Payload`` entry maps each pid to a
        dict of per-process metadata (such as ``ProcessName``).
    """
    await self.connect()
    await self.service.send_plist({"Request": "PidList"})

    # ignore first received unknown byte
    await self.service.recvall(1)

    response = await self.service.recv_prefixed()
    return plistlib.loads(response)
```

### create_archive

```
create_archive(out: IO[bytes], size_limit: Optional[int] = None, age_limit: Optional[int] = None, start_time: Optional[int] = None)
```

Request a log archive from the device and stream its raw bytes into `out`.

The device returns the archive as a PAX-format tar stream (the contents of `/var/db/diagnostics`), which is written to `out` in chunks until the connection is terminated. Use `collect` instead to obtain an extracted `.logarchive` directory.

Parameters:

| Name         | Type            | Description                                                      | Default    |
| ------------ | --------------- | ---------------------------------------------------------------- | ---------- |
| `out`        | `IO[bytes]`     | A writable binary file-like object to receive the archive bytes. | *required* |
| `size_limit` | `Optional[int]` | Optional maximum archive size in bytes.                          | `None`     |
| `age_limit`  | `Optional[int]` | Optional maximum age, in days, of entries to include.            | `None`     |
| `start_time` | `Optional[int]` | Optional earliest entry time, as a unix timestamp.               | `None`     |

Raises:

| Type            | Description                                                              |
| --------------- | ------------------------------------------------------------------------ |
| `ProtocolError` | If the device does not acknowledge the request with a successful status. |

Source code in `pymobiledevice3/services/os_trace.py`

```
async def create_archive(
    self,
    out: typing.IO[bytes],
    size_limit: typing.Optional[int] = None,
    age_limit: typing.Optional[int] = None,
    start_time: typing.Optional[int] = None,
):
    """
    Request a log archive from the device and stream its raw bytes into ``out``.

    The device returns the archive as a PAX-format tar stream (the contents of
    ``/var/db/diagnostics``), which is written to ``out`` in chunks until the connection is
    terminated. Use `collect` instead to obtain an extracted ``.logarchive`` directory.

    :param out: A writable binary file-like object to receive the archive bytes.
    :param size_limit: Optional maximum archive size in bytes.
    :param age_limit: Optional maximum age, in days, of entries to include.
    :param start_time: Optional earliest entry time, as a unix timestamp.
    :raises ProtocolError: If the device does not acknowledge the request with a successful status.
    """
    request: dict[str, typing.Any] = {"Request": "CreateArchive"}

    if size_limit is not None:
        request.update({"SizeLimit": size_limit})

    if age_limit is not None:
        request.update({"AgeLimit": age_limit})

    if start_time is not None:
        request.update({"StartTime": start_time})

    await self.connect()
    await self.service.send_plist(request)

    response = await self.service.recvall(1)
    if response[0] != 1:
        raise ProtocolError(f"The device sent an unexpected reply to the log archive request: {response.hex()}")

    status = plistlib.loads(await self.service.recv_prefixed()).get("Status")
    if status != "RequestSuccessful":
        raise ProtocolError(f"The device refused to create the log archive: {status}")

    while True:
        try:
            magic = await self.service.recvall(1)
        except ConnectionTerminatedError:
            break
        if magic[0] != 3:
            raise ProtocolError(f"The device sent a malformed log stream (unexpected chunk marker): {magic.hex()}")
        out.write(await self.service.recv_prefixed(endianity="<"))
```

### collect

```
collect(out: str, size_limit: Optional[int] = None, age_limit: Optional[int] = None, start_time: Optional[int] = None) -> None
```

Collect the device's system logs into a `.logarchive` that can be inspected later with tools such as `log` or Console.

Internally calls `create_archive` to fetch the tar stream into a temporary file, then extracts it into the `out` directory.

Parameters:

| Name         | Type            | Description                                                     | Default    |
| ------------ | --------------- | --------------------------------------------------------------- | ---------- |
| `out`        | `str`           | Destination directory path into which the archive is extracted. | *required* |
| `size_limit` | `Optional[int]` | Optional maximum archive size in bytes.                         | `None`     |
| `age_limit`  | `Optional[int]` | Optional maximum age, in days, of entries to include.           | `None`     |
| `start_time` | `Optional[int]` | Optional earliest entry time, as a unix timestamp.              | `None`     |

Source code in `pymobiledevice3/services/os_trace.py`

```
async def collect(
    self,
    out: str,
    size_limit: typing.Optional[int] = None,
    age_limit: typing.Optional[int] = None,
    start_time: typing.Optional[int] = None,
) -> None:
    """
    Collect the device's system logs into a ``.logarchive`` that can be inspected later with
    tools such as ``log`` or Console.

    Internally calls `create_archive` to fetch the tar stream into a temporary file, then
    extracts it into the ``out`` directory.

    :param out: Destination directory path into which the archive is extracted.
    :param size_limit: Optional maximum archive size in bytes.
    :param age_limit: Optional maximum age, in days, of entries to include.
    :param start_time: Optional earliest entry time, as a unix timestamp.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        file = Path(temp_dir) / "foo.tar"
        with open(file, "wb") as f:
            await self.create_archive(f, size_limit=size_limit, age_limit=age_limit, start_time=start_time)
        # Extract only ordinary files and directories, each kept beneath `out`. extractall()
        # is unsafe with a device-supplied archive before Python 3.14 (absolute names, `..`,
        # links), and a logarchive holds nothing but files and directories anyway.
        out_path = Path(out)
        with TarFile(file) as archive:
            for member in archive:
                destination = resolve_device_path(out_path, member.name)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                elif member.isreg():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise DevicePathError(f"the log archive entry has no data: {member.name!r}")
                    with source, destination.open("wb") as target:
                        shutil.copyfileobj(source, target)
                else:
                    raise DevicePathError(
                        f"the log archive holds an entry that is neither a file nor a directory: {member.name!r}"
                    )
```

### syslog

```
syslog(pid: int = -1, message_filter: int = OS_TRACE_RELAY_MESSAGE_FILTER_ALL, stream_flags: int = OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT) -> typing.AsyncGenerator[SyslogEntry, None]
```

Stream live syslog entries from the device.

Starts an activity stream on the device and yields each incoming record, parsed via `parse_syslog_entry`, indefinitely until the caller stops iterating or the connection drops.

:yields: Each decoded log entry as it arrives.

Parameters:

| Name             | Type  | Description                                                                                                                       | Default                               |
| ---------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `pid`            | `int` | Restrict the stream to a single process by pid; -1 (the default) streams entries from all processes.                              | `-1`                                  |
| `message_filter` | `int` | Bitmask selecting which message levels to receive; defaults to OS_TRACE_RELAY_MESSAGE_FILTER_ALL (all levels).                    | `OS_TRACE_RELAY_MESSAGE_FILTER_ALL`   |
| `stream_flags`   | `int` | Bitmask of OsActivityStreamFlag values controlling stream contents and decoding; defaults to OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT. | `OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT` |

Raises:

| Type            | Description                                     |
| --------------- | ----------------------------------------------- |
| `ProtocolError` | If the device rejects the stream-start request. |

Source code in `pymobiledevice3/services/os_trace.py`

```
async def syslog(
    self,
    pid: int = -1,
    message_filter: int = OS_TRACE_RELAY_MESSAGE_FILTER_ALL,
    stream_flags: int = OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT,
) -> typing.AsyncGenerator[SyslogEntry, None]:
    """
    Stream live syslog entries from the device.

    Starts an activity stream on the device and yields each incoming record, parsed via
    `parse_syslog_entry`, indefinitely until the caller stops iterating or the connection
    drops.

    :param pid: Restrict the stream to a single process by pid; ``-1`` (the default) streams
        entries from all processes.
    :param message_filter: Bitmask selecting which message levels to receive; defaults to
        `OS_TRACE_RELAY_MESSAGE_FILTER_ALL` (all levels).
    :param stream_flags: Bitmask of `OsActivityStreamFlag` values controlling stream
        contents and decoding; defaults to `OS_TRACE_RELAY_STREAM_FLAGS_DEFAULT`.
    :yields: Each decoded log entry as it arrives.
    :raises ProtocolError: If the device rejects the stream-start request.
    """
    await self.connect()
    await self.service.send_plist({
        "Request": "StartActivity",
        "MessageFilter": message_filter,
        "Pid": pid,
        "StreamFlags": stream_flags,
    })

    (length_length,) = struct.unpack("<I", await self.service.recvall(4))
    length = int((await self.service.recvall(length_length))[::-1].hex(), 16)
    response = plistlib.loads(await self.service.recvall(length))

    if response.get("Status") != "RequestSuccessful":
        raise ProtocolError(f"The device refused to start the log stream: {response}")

    while True:
        magic = await self.service.recvall(1)
        if magic != b"\x02":
            raise ProtocolError(f"The device sent a malformed log stream (unexpected chunk marker): {magic.hex()}")
        (length,) = struct.unpack("<I", await self.service.recvall(4))
        line = await self.service.recvall(length)
        yield parse_syslog_entry(line)
```

## pymobiledevice3.services.installation_proxy.InstallationProxyService

Bases: `LockdownService`

Client for the `com.apple.mobile.installation_proxy` lockdown service.

Provides access to the device's application installation database: installing, upgrading, uninstalling, archiving/restoring, browsing and looking up apps, as well as uploading carrier bundles (IPCC). Most operations send a plist command over the service connection and stream back progress and status responses.

Source code in `pymobiledevice3/services/installation_proxy.py`

```
class InstallationProxyService(LockdownService):
    """
    Client for the ``com.apple.mobile.installation_proxy`` lockdown service.

    Provides access to the device's application installation database: installing,
    upgrading, uninstalling, archiving/restoring, browsing and looking up apps, as well
    as uploading carrier bundles (IPCC). Most operations send a plist command over the
    service connection and stream back progress and status responses.
    """

    SERVICE_NAME = "com.apple.mobile.installation_proxy"
    RSD_SERVICE_NAME = "com.apple.mobile.installation_proxy.shim.remote"

    async def _watch_completion(
        self, handler: Optional[Callable[..., Any]] = None, *args: Any, desc: str = "install"
    ) -> None:
        stage: Optional[str] = None
        with ProgressBar(total=100, desc=desc) as bar:
            while True:
                response = await self.service.recv_plist()
                if not response:
                    raise AppInstallError()
                error = response.get("Error")
                if error:
                    raise AppInstallError(f"{error}: {response.get('ErrorDescription')}")
                status = response.get("Status")
                if isinstance(status, str) and status != "Complete" and status != stage:
                    stage = status
                    self.logger.info(f"Stage: {status}")
                completion = response.get("PercentComplete")
                if isinstance(completion, (int, float)):
                    bar.n = completion
                    if completion and handler:
                        self.logger.debug("calling handler")
                        handler(completion, *args)
                if status == "Complete":
                    break
        self.logger.info("Installation succeed.")

    async def send_cmd_for_bundle_identifier(
        self,
        bundle_identifier: str,
        cmd: str = "Archive",
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Send a command that targets an installed app by its bundle identifier and wait for completion.

        Sends a plist of the form ``{"Command": cmd, "ApplicationIdentifier": bundle_identifier,
        "ClientOptions": options}`` to the service, then consumes progress/status responses until
        the operation completes. Used to back `restore` and `uninstall`.

        :param bundle_identifier: Bundle identifier of the target app, sent as ``ApplicationIdentifier``.
        :param cmd: Installation-proxy command name, sent as ``Command``. Defaults to ``"Archive"``.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the service reports an error or finishes without a ``Complete`` status.
        """
        request: dict[str, Any] = {"Command": cmd, "ApplicationIdentifier": bundle_identifier}

        if options is None:
            options = {}

        request.update({"ClientOptions": options})
        await self.service.send_plist(request)
        await self._watch_completion(handler, *args, desc=cmd.lower())

    async def upgrade(
        self,
        ipa_path: str,
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Upgrade an installed app from a local package.

        Delegates to `install_from_local` with the ``"Upgrade"`` command.

        :param ipa_path: Local path to the package (``.ipa``/``.ipcc`` or an app directory).
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the upgrade fails.
        """
        await self.install_from_local(Path(ipa_path), "Upgrade", options, handler, False, *args)

    async def restore(
        self,
        bundle_identifier: str,
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Restore a previously archived app, identified by its bundle identifier.

        Sends the ``"Restore"`` command via `send_cmd_for_bundle_identifier`.

        :param bundle_identifier: Bundle identifier of the app to restore.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the restore fails.
        """
        await self.send_cmd_for_bundle_identifier(bundle_identifier, "Restore", options, handler, *args)

    async def uninstall(
        self,
        bundle_identifier: str,
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Uninstall an app, identified by its bundle identifier.

        Sends the ``"Uninstall"`` command via `send_cmd_for_bundle_identifier`.

        :param bundle_identifier: Bundle identifier of the app to uninstall.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the uninstall fails.
        """
        await self.send_cmd_for_bundle_identifier(bundle_identifier, "Uninstall", options, handler, *args)

    async def install_from_bytes(
        self,
        package_bytes: bytes,
        cmd: str = "Install",
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        *args: Any,
    ) -> None:
        """
        Install an app or carrier bundle from a zipped package held in memory.

        The package type is detected from the zip contents (see `classify_zip_file`): a
        ``.app`` payload is treated as an ``.ipa``, a ``.bundle`` payload as an ``.ipcc``. For
        IPCC packages, ``PackageType`` is forced to ``"CarrierBundle"`` in the options. The bytes
        are uploaded to a temporary path under ``/PublicStaging/pymobiledevice3`` via AFC, the
        command is dispatched with `send_package`, and the temporary file is removed
        afterwards.

        :param package_bytes: Raw bytes of the ``.ipa``/``.ipcc`` zip package.
        :param cmd: Installation-proxy command name, sent as ``Command``. Defaults to ``"Install"``.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the bytes are not a valid package, lack a ``Payload`` directory,
            or if the installation fails.
        """
        ipcc_mode = classify_zip_file(package_bytes).is_ipcc()

        if options is None:
            options = {}

        if ipcc_mode:
            options["PackageType"] = "CarrierBundle"

        async with AfcService(self.lockdown) as afc:
            fpath = f"{TEMP_REMOTE_BASEDIR}/{uuid.uuid4()}.{'ipcc' if ipcc_mode else 'ipa'}"
            try:
                if not ipcc_mode:
                    await afc.makedirs(TEMP_REMOTE_BASEDIR)
                    await self._upload_package(afc, fpath, package_bytes, "package")
                else:
                    await self.upload_ipcc_from_bytes(package_bytes, fpath, afc)

                await self.send_package(cmd, options, handler, fpath, *args)
            finally:
                await afc.rm_single(fpath, force=True)

    async def _upload_package(self, afc: AfcService, remote_path: str, data: bytes, name: str) -> None:
        self.logger.info(f"Uploading {name}...")
        with ProgressBar(total=len(data), desc=name, unit=BYTES_UNIT) as bar:
            await afc.set_file_contents(remote_path, data, progress=bar)
        self.logger.info("Upload complete.")

    @str_to_path("package_path")
    async def install_from_local(
        self,
        package_path: Path,
        cmd: str = "Install",
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[..., Any]] = None,
        developer: bool = False,
        *args: Any,
    ) -> None:
        """
        Install an app or carrier bundle from a local path.

        Dispatches on ``package_path``: a ``.ipcc`` suffix is treated as a carrier bundle
        (``PackageType`` forced to ``"CarrierBundle"``); a directory is treated as an unpackaged
        app and zipped into an ``.ipa`` via `create_ipa_contents_from_directory`; any other
        path is read as ``.ipa`` bytes. When ``developer`` is set, ``PackageType`` is forced to
        ``"Developer"``. The payload is uploaded to a temporary path under
        ``/PublicStaging/pymobiledevice3`` via AFC, the command is dispatched with
        `send_package`, and the temporary file is removed afterwards.

        :param package_path: Local path to a ``.ipa`` file, a ``.ipcc`` file, or an app directory.
            String values are coerced to `Path`.
        :param cmd: Installation-proxy command name, sent as ``Command``. Defaults to ``"Install"``.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param developer: When ``True``, sets ``PackageType`` to ``"Developer"`` in the options.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the installation fails.
        """
        ipcc_mode = package_path.suffix == ".ipcc"

        if options is None:
            options = {}

        ipa_contents = b""
        if ipcc_mode:
            options["PackageType"] = "CarrierBundle"
        else:
            if package_path.is_dir():
                # treat as app, convert into an ipa
                ipa_contents = create_ipa_contents_from_directory(str(package_path))
            else:
                # treat as ipa
                ipa_contents = package_path.read_bytes()

        if developer:
            options["PackageType"] = "Developer"

        async with AfcService(self.lockdown) as afc:
            fname = f"{TEMP_REMOTE_BASEDIR}/{uuid.uuid4()}.{'ipcc' if ipcc_mode else 'ipa'}"
            try:
                if not ipcc_mode:
                    await afc.makedirs(TEMP_REMOTE_BASEDIR)
                    await self._upload_package(afc, fname, ipa_contents, package_path.name)

                else:
                    await self.upload_ipcc_from_path(package_path, fname, afc)

                await self.send_package(cmd, options, handler, fname, *args)
            finally:
                await afc.rm_single(fname, force=True)

    async def send_package(
        self,
        cmd: str,
        options: Optional[dict[str, Any]],
        handler: Optional[Callable[..., Any]],
        package_path: str,
        *args: Any,
    ):
        """
        Send an install/upgrade command for a package already staged on the device, and wait for completion.

        Sends ``{"Command": cmd, "ClientOptions": options, "PackagePath": package_path}`` to the
        service, then consumes progress/status responses until the operation completes. Typically
        invoked by `install_from_local` and `install_from_bytes` after uploading the
        package via AFC.

        :param cmd: Installation-proxy command name, sent as ``Command``.
        :param options: Command options, sent as ``ClientOptions``.
        :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
            progress response. ``None`` disables progress callbacks.
        :param package_path: On-device path to the staged package, sent as ``PackagePath``.
        :param args: Extra positional arguments forwarded to ``handler``.
        :returns: None.
        :raises AppInstallError: If the service reports an error or finishes without a ``Complete`` status.
        """
        await self.service.send_plist(
            cast(
                PlistSendable,
                {
                    "Command": cmd,
                    "ClientOptions": options,
                    "PackagePath": package_path,
                },
            )
        )

        await self._watch_completion(handler, *args)

    async def upload_ipcc_from_path(self, file: Path, remote_path: str, afc_client: AfcService) -> None:
        """
        Upload a local IPCC (carrier bundle) zip to the device, unpacking it into the remote path.

        Reads the file into memory and forwards it to the unpacking uploader, which recreates the
        zip's directory tree under ``remote_path`` on the device via the given AFC client.

        :param file: Local path to the ``.ipcc`` zip file.
        :param remote_path: Destination directory on the device where the bundle is unpacked.
        :param afc_client: Connected `AfcService` used to write
            the files.
        :returns: None.
        """
        with file.open("rb") as fb:
            file_name = file.name
            file_stream = BytesIO(fb.read())
            self.logger.info(f"Uploading {file_name} contents..")
            await self._upload_ipcc(file_stream, afc_client, remote_path)

    async def upload_ipcc_from_bytes(self, file_bytes: bytes, remote_path: str, afc_client: AfcService) -> None:
        """
        Upload an in-memory IPCC (carrier bundle) zip to the device, unpacking it into the remote path.

        Wraps the bytes in a stream and forwards them to the unpacking uploader, which recreates the
        zip's directory tree under ``remote_path`` on the device via the given AFC client.

        :param file_bytes: Raw bytes of the ``.ipcc`` zip.
        :param remote_path: Destination directory on the device where the bundle is unpacked.
        :param afc_client: Connected `AfcService` used to write
            the files.
        :returns: None.
        """
        file_stream = BytesIO(file_bytes)
        self.logger.info("Uploading IPCC from given bytes..")
        await self._upload_ipcc(file_stream, afc_client, remote_path)

    async def _upload_ipcc(self, file_stream: BytesIO, afc_client: AfcService, dst: str) -> None:
        self.logger.info(f"Uploading {dst} contents..")
        await afc_client.makedirs(dst)

        # we unpack it and upload it directly instead of saving it in a temp folder
        with ZipFile(file_stream, "r") as file_zip:
            total = sum(info.file_size for info in file_zip.infolist() if not info.filename.endswith(("/", "\\")))
            with ProgressBar(total=total, desc="ipcc", unit=BYTES_UNIT) as bar:
                for file_name in file_zip.namelist():
                    if file_name.endswith(("/", "\\")):
                        await afc_client.makedirs(f"{dst}/{file_name}")
                        continue

                    with file_zip.open(file_name) as inside_file_zip:
                        file_data = inside_file_zip.read()
                        await afc_client.makedirs(dst)
                        await afc_client.set_file_contents(f"{dst}/{file_name}", file_data, progress=bar)

        self.logger.info("Upload complete.")

    async def check_capabilities_match(
        self, capabilities: Optional[dict[str, Any]] = None, options: Optional[dict[str, Any]] = None
    ) -> Optional[dict[str, Any]]:
        """
        Ask the device whether it satisfies a set of app capabilities.

        Sends the ``"CheckCapabilitiesMatch"`` command. When ``capabilities`` is provided it is
        sent under the ``Capabilities`` key; otherwise no capabilities key is sent. Returns the
        single ``LookupResult`` value from the response.

        :param capabilities: Capabilities to check, sent as ``Capabilities``. If falsy, the key is
            omitted.
        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :returns: The ``LookupResult`` value from the response describing the matched capabilities,
            or ``None`` if absent.
        """
        if options is None:
            options = {}
        cmd: dict[str, Any] = {"Command": "CheckCapabilitiesMatch", "ClientOptions": options}

        if capabilities:
            cmd["Capabilities"] = capabilities

        await self.service.send_plist(cmd)
        return cast(Optional[dict[str, Any]], (await self.service.recv_plist()).get("LookupResult"))

    async def browse(
        self, options: Optional[dict[str, Any]] = None, attributes: Optional[list[str]] = None
    ) -> list[dict[str, Any]]:
        """
        Enumerate installed apps via the ``"Browse"`` command.

        Sends the command and accumulates each response's ``CurrentList`` entries until the service
        reports a ``Complete`` status (or returns an empty response).

        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :param attributes: When provided, set as the ``ReturnAttributes`` option to limit which
            per-app attributes are returned.
        :returns: A list of per-app info dictionaries collected from all ``CurrentList`` responses.
        """
        if options is None:
            options = {}
        if attributes:
            options["ReturnAttributes"] = attributes

        cmd: dict[str, Any] = {"Command": "Browse", "ClientOptions": options}

        await self.service.send_plist(cmd)

        result: list[dict[str, Any]] = []
        while True:
            response = await self.service.recv_plist()
            if not response:
                break

            data = response.get("CurrentList")
            if data is not None:
                result += cast(list[dict[str, Any]], data)

            if response.get("Status") == "Complete":
                break

        return result

    async def lookup(self, options: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
        """
        Look up installed apps via the ``"Lookup"`` command.

        Sends the command and returns the single ``LookupResult`` value from the response. The
        options dict (e.g. ``BundleIDs``, ``ApplicationType``, ``ReturnAttributes``) determines
        which apps and attributes are returned.

        :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
        :returns: The ``LookupResult`` mapping bundle identifiers to per-app info dictionaries, or
            ``None`` if absent.
        """
        if options is None:
            options = {}
        cmd: dict[str, Any] = {"Command": "Lookup", "ClientOptions": options}
        await self.service.send_plist(cmd)
        return cast(Optional[dict[str, Any]], (await self.service.recv_plist()).get("LookupResult"))

    async def get_apps(
        self,
        application_type: str = "Any",
        calculate_sizes: bool = False,
        bundle_identifiers: Optional[list[str]] = None,
        show_placeholders: bool = False,
    ) -> dict[str, dict[str, Any]]:
        """
        Retrieve installed apps, keyed by bundle identifier.

        Builds a lookup query from the given filters and calls `lookup`. When
        ``calculate_sizes`` is set, a second lookup is issued requesting ``CFBundleIdentifier``,
        ``StaticDiskUsage`` and ``DynamicDiskUsage``, and those size attributes are merged into the
        per-app entries.

        :param application_type: Value for the ``ApplicationType`` option. Defaults to ``"Any"``;
            other values include ``"System"`` and ``"User"``.
        :param calculate_sizes: When ``True``, also fetch and merge static/dynamic disk usage for
            each app.
        :param bundle_identifiers: When provided, restrict the query to these bundle identifiers via
            the ``BundleIDs`` option.
        :param show_placeholders: When ``True``, set the ``ShowPlaceholders`` option to include
            placeholder (e.g. installing/downloading) apps.
            See <https://github.com/doronz88/pymobiledevice3/issues/1602> for details.
        :returns: A dictionary mapping each bundle identifier to its per-app info dictionary.
        """
        options: dict[str, Any] = {}
        if bundle_identifiers is not None:
            options["BundleIDs"] = bundle_identifiers

        options["ApplicationType"] = application_type
        if show_placeholders:
            options["ShowPlaceholders"] = True
        result = await self.lookup(options)
        if result is None:
            raise AppInstallError("Lookup response is missing LookupResult")
        if calculate_sizes:
            options.update(GET_APPS_ADDITIONAL_INFO)
            additional_info = await self.lookup(options)
            if additional_info is None:
                raise AppInstallError("Lookup response is missing LookupResult")
            for bundle_identifier, app in additional_info.items():
                result[bundle_identifier].update(app)
        return result
```

### send_cmd_for_bundle_identifier

```
send_cmd_for_bundle_identifier(bundle_identifier: str, cmd: str = 'Archive', options: Optional[dict[str, Any]] = None, handler: Optional[Callable[..., Any]] = None, *args: Any) -> None
```

Send a command that targets an installed app by its bundle identifier and wait for completion.

Sends a plist of the form `{"Command": cmd, "ApplicationIdentifier": bundle_identifier, "ClientOptions": options}` to the service, then consumes progress/status responses until the operation completes. Used to back `restore` and `uninstall`.

Parameters:

| Name                | Type                           | Description                                                                                                                 | Default     |
| ------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `bundle_identifier` | `str`                          | Bundle identifier of the target app, sent as ApplicationIdentifier.                                                         | *required*  |
| `cmd`               | `str`                          | Installation-proxy command name, sent as Command. Defaults to "Archive".                                                    | `'Archive'` |
| `options`           | `Optional[dict[str, Any]]`     | Command options, sent as ClientOptions. None is sent as an empty dict.                                                      | `None`      |
| `handler`           | `Optional[Callable[..., Any]]` | Progress callback invoked as handler(percent_complete, \*args) on each progress response. None disables progress callbacks. | `None`      |
| `args`              | `Any`                          | Extra positional arguments forwarded to handler.                                                                            | `()`        |

Returns:

| Type   | Description |
| ------ | ----------- |
| `None` | None.       |

Raises:

| Type              | Description                                                            |
| ----------------- | ---------------------------------------------------------------------- |
| `AppInstallError` | If the service reports an error or finishes without a Complete status. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def send_cmd_for_bundle_identifier(
    self,
    bundle_identifier: str,
    cmd: str = "Archive",
    options: Optional[dict[str, Any]] = None,
    handler: Optional[Callable[..., Any]] = None,
    *args: Any,
) -> None:
    """
    Send a command that targets an installed app by its bundle identifier and wait for completion.

    Sends a plist of the form ``{"Command": cmd, "ApplicationIdentifier": bundle_identifier,
    "ClientOptions": options}`` to the service, then consumes progress/status responses until
    the operation completes. Used to back `restore` and `uninstall`.

    :param bundle_identifier: Bundle identifier of the target app, sent as ``ApplicationIdentifier``.
    :param cmd: Installation-proxy command name, sent as ``Command``. Defaults to ``"Archive"``.
    :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
    :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
        progress response. ``None`` disables progress callbacks.
    :param args: Extra positional arguments forwarded to ``handler``.
    :returns: None.
    :raises AppInstallError: If the service reports an error or finishes without a ``Complete`` status.
    """
    request: dict[str, Any] = {"Command": cmd, "ApplicationIdentifier": bundle_identifier}

    if options is None:
        options = {}

    request.update({"ClientOptions": options})
    await self.service.send_plist(request)
    await self._watch_completion(handler, *args, desc=cmd.lower())
```

### upgrade

```
upgrade(ipa_path: str, options: Optional[dict[str, Any]] = None, handler: Optional[Callable[..., Any]] = None, *args: Any) -> None
```

Upgrade an installed app from a local package.

Delegates to `install_from_local` with the `"Upgrade"` command.

Parameters:

| Name       | Type                           | Description                                                                                                                 | Default    |
| ---------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `ipa_path` | `str`                          | Local path to the package (.ipa/.ipcc or an app directory).                                                                 | *required* |
| `options`  | `Optional[dict[str, Any]]`     | Command options, sent as ClientOptions. None is sent as an empty dict.                                                      | `None`     |
| `handler`  | `Optional[Callable[..., Any]]` | Progress callback invoked as handler(percent_complete, \*args) on each progress response. None disables progress callbacks. | `None`     |
| `args`     | `Any`                          | Extra positional arguments forwarded to handler.                                                                            | `()`       |

Returns:

| Type   | Description |
| ------ | ----------- |
| `None` | None.       |

Raises:

| Type              | Description           |
| ----------------- | --------------------- |
| `AppInstallError` | If the upgrade fails. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def upgrade(
    self,
    ipa_path: str,
    options: Optional[dict[str, Any]] = None,
    handler: Optional[Callable[..., Any]] = None,
    *args: Any,
) -> None:
    """
    Upgrade an installed app from a local package.

    Delegates to `install_from_local` with the ``"Upgrade"`` command.

    :param ipa_path: Local path to the package (``.ipa``/``.ipcc`` or an app directory).
    :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
    :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
        progress response. ``None`` disables progress callbacks.
    :param args: Extra positional arguments forwarded to ``handler``.
    :returns: None.
    :raises AppInstallError: If the upgrade fails.
    """
    await self.install_from_local(Path(ipa_path), "Upgrade", options, handler, False, *args)
```

### restore

```
restore(bundle_identifier: str, options: Optional[dict[str, Any]] = None, handler: Optional[Callable[..., Any]] = None, *args: Any) -> None
```

Restore a previously archived app, identified by its bundle identifier.

Sends the `"Restore"` command via `send_cmd_for_bundle_identifier`.

Parameters:

| Name                | Type                           | Description                                                                                                                 | Default    |
| ------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `bundle_identifier` | `str`                          | Bundle identifier of the app to restore.                                                                                    | *required* |
| `options`           | `Optional[dict[str, Any]]`     | Command options, sent as ClientOptions. None is sent as an empty dict.                                                      | `None`     |
| `handler`           | `Optional[Callable[..., Any]]` | Progress callback invoked as handler(percent_complete, \*args) on each progress response. None disables progress callbacks. | `None`     |
| `args`              | `Any`                          | Extra positional arguments forwarded to handler.                                                                            | `()`       |

Returns:

| Type   | Description |
| ------ | ----------- |
| `None` | None.       |

Raises:

| Type              | Description           |
| ----------------- | --------------------- |
| `AppInstallError` | If the restore fails. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def restore(
    self,
    bundle_identifier: str,
    options: Optional[dict[str, Any]] = None,
    handler: Optional[Callable[..., Any]] = None,
    *args: Any,
) -> None:
    """
    Restore a previously archived app, identified by its bundle identifier.

    Sends the ``"Restore"`` command via `send_cmd_for_bundle_identifier`.

    :param bundle_identifier: Bundle identifier of the app to restore.
    :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
    :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
        progress response. ``None`` disables progress callbacks.
    :param args: Extra positional arguments forwarded to ``handler``.
    :returns: None.
    :raises AppInstallError: If the restore fails.
    """
    await self.send_cmd_for_bundle_identifier(bundle_identifier, "Restore", options, handler, *args)
```

### uninstall

```
uninstall(bundle_identifier: str, options: Optional[dict[str, Any]] = None, handler: Optional[Callable[..., Any]] = None, *args: Any) -> None
```

Uninstall an app, identified by its bundle identifier.

Sends the `"Uninstall"` command via `send_cmd_for_bundle_identifier`.

Parameters:

| Name                | Type                           | Description                                                                                                                 | Default    |
| ------------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `bundle_identifier` | `str`                          | Bundle identifier of the app to uninstall.                                                                                  | *required* |
| `options`           | `Optional[dict[str, Any]]`     | Command options, sent as ClientOptions. None is sent as an empty dict.                                                      | `None`     |
| `handler`           | `Optional[Callable[..., Any]]` | Progress callback invoked as handler(percent_complete, \*args) on each progress response. None disables progress callbacks. | `None`     |
| `args`              | `Any`                          | Extra positional arguments forwarded to handler.                                                                            | `()`       |

Returns:

| Type   | Description |
| ------ | ----------- |
| `None` | None.       |

Raises:

| Type              | Description             |
| ----------------- | ----------------------- |
| `AppInstallError` | If the uninstall fails. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def uninstall(
    self,
    bundle_identifier: str,
    options: Optional[dict[str, Any]] = None,
    handler: Optional[Callable[..., Any]] = None,
    *args: Any,
) -> None:
    """
    Uninstall an app, identified by its bundle identifier.

    Sends the ``"Uninstall"`` command via `send_cmd_for_bundle_identifier`.

    :param bundle_identifier: Bundle identifier of the app to uninstall.
    :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
    :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
        progress response. ``None`` disables progress callbacks.
    :param args: Extra positional arguments forwarded to ``handler``.
    :returns: None.
    :raises AppInstallError: If the uninstall fails.
    """
    await self.send_cmd_for_bundle_identifier(bundle_identifier, "Uninstall", options, handler, *args)
```

### install_from_bytes

```
install_from_bytes(package_bytes: bytes, cmd: str = 'Install', options: Optional[dict[str, Any]] = None, handler: Optional[Callable[..., Any]] = None, *args: Any) -> None
```

Install an app or carrier bundle from a zipped package held in memory.

The package type is detected from the zip contents (see `classify_zip_file`): a `.app` payload is treated as an `.ipa`, a `.bundle` payload as an `.ipcc`. For IPCC packages, `PackageType` is forced to `"CarrierBundle"` in the options. The bytes are uploaded to a temporary path under `/PublicStaging/pymobiledevice3` via AFC, the command is dispatched with `send_package`, and the temporary file is removed afterwards.

Parameters:

| Name            | Type                           | Description                                                                                                                 | Default     |
| --------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `package_bytes` | `bytes`                        | Raw bytes of the .ipa/.ipcc zip package.                                                                                    | *required*  |
| `cmd`           | `str`                          | Installation-proxy command name, sent as Command. Defaults to "Install".                                                    | `'Install'` |
| `options`       | `Optional[dict[str, Any]]`     | Command options, sent as ClientOptions. None is sent as an empty dict.                                                      | `None`      |
| `handler`       | `Optional[Callable[..., Any]]` | Progress callback invoked as handler(percent_complete, \*args) on each progress response. None disables progress callbacks. | `None`      |
| `args`          | `Any`                          | Extra positional arguments forwarded to handler.                                                                            | `()`        |

Returns:

| Type   | Description |
| ------ | ----------- |
| `None` | None.       |

Raises:

| Type              | Description                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------- |
| `AppInstallError` | If the bytes are not a valid package, lack a Payload directory, or if the installation fails. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def install_from_bytes(
    self,
    package_bytes: bytes,
    cmd: str = "Install",
    options: Optional[dict[str, Any]] = None,
    handler: Optional[Callable[..., Any]] = None,
    *args: Any,
) -> None:
    """
    Install an app or carrier bundle from a zipped package held in memory.

    The package type is detected from the zip contents (see `classify_zip_file`): a
    ``.app`` payload is treated as an ``.ipa``, a ``.bundle`` payload as an ``.ipcc``. For
    IPCC packages, ``PackageType`` is forced to ``"CarrierBundle"`` in the options. The bytes
    are uploaded to a temporary path under ``/PublicStaging/pymobiledevice3`` via AFC, the
    command is dispatched with `send_package`, and the temporary file is removed
    afterwards.

    :param package_bytes: Raw bytes of the ``.ipa``/``.ipcc`` zip package.
    :param cmd: Installation-proxy command name, sent as ``Command``. Defaults to ``"Install"``.
    :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
    :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
        progress response. ``None`` disables progress callbacks.
    :param args: Extra positional arguments forwarded to ``handler``.
    :returns: None.
    :raises AppInstallError: If the bytes are not a valid package, lack a ``Payload`` directory,
        or if the installation fails.
    """
    ipcc_mode = classify_zip_file(package_bytes).is_ipcc()

    if options is None:
        options = {}

    if ipcc_mode:
        options["PackageType"] = "CarrierBundle"

    async with AfcService(self.lockdown) as afc:
        fpath = f"{TEMP_REMOTE_BASEDIR}/{uuid.uuid4()}.{'ipcc' if ipcc_mode else 'ipa'}"
        try:
            if not ipcc_mode:
                await afc.makedirs(TEMP_REMOTE_BASEDIR)
                await self._upload_package(afc, fpath, package_bytes, "package")
            else:
                await self.upload_ipcc_from_bytes(package_bytes, fpath, afc)

            await self.send_package(cmd, options, handler, fpath, *args)
        finally:
            await afc.rm_single(fpath, force=True)
```

### install_from_local

```
install_from_local(package_path: Path, cmd: str = 'Install', options: Optional[dict[str, Any]] = None, handler: Optional[Callable[..., Any]] = None, developer: bool = False, *args: Any) -> None
```

Install an app or carrier bundle from a local path.

Dispatches on `package_path`: a `.ipcc` suffix is treated as a carrier bundle (`PackageType` forced to `"CarrierBundle"`); a directory is treated as an unpackaged app and zipped into an `.ipa` via `create_ipa_contents_from_directory`; any other path is read as `.ipa` bytes. When `developer` is set, `PackageType` is forced to `"Developer"`. The payload is uploaded to a temporary path under `/PublicStaging/pymobiledevice3` via AFC, the command is dispatched with `send_package`, and the temporary file is removed afterwards.

Parameters:

| Name           | Type                           | Description                                                                                                                 | Default     |
| -------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `package_path` | `Path`                         | Local path to a .ipa file, a .ipcc file, or an app directory. String values are coerced to Path.                            | *required*  |
| `cmd`          | `str`                          | Installation-proxy command name, sent as Command. Defaults to "Install".                                                    | `'Install'` |
| `options`      | `Optional[dict[str, Any]]`     | Command options, sent as ClientOptions. None is sent as an empty dict.                                                      | `None`      |
| `handler`      | `Optional[Callable[..., Any]]` | Progress callback invoked as handler(percent_complete, \*args) on each progress response. None disables progress callbacks. | `None`      |
| `developer`    | `bool`                         | When True, sets PackageType to "Developer" in the options.                                                                  | `False`     |
| `args`         | `Any`                          | Extra positional arguments forwarded to handler.                                                                            | `()`        |

Returns:

| Type   | Description |
| ------ | ----------- |
| `None` | None.       |

Raises:

| Type              | Description                |
| ----------------- | -------------------------- |
| `AppInstallError` | If the installation fails. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
@str_to_path("package_path")
async def install_from_local(
    self,
    package_path: Path,
    cmd: str = "Install",
    options: Optional[dict[str, Any]] = None,
    handler: Optional[Callable[..., Any]] = None,
    developer: bool = False,
    *args: Any,
) -> None:
    """
    Install an app or carrier bundle from a local path.

    Dispatches on ``package_path``: a ``.ipcc`` suffix is treated as a carrier bundle
    (``PackageType`` forced to ``"CarrierBundle"``); a directory is treated as an unpackaged
    app and zipped into an ``.ipa`` via `create_ipa_contents_from_directory`; any other
    path is read as ``.ipa`` bytes. When ``developer`` is set, ``PackageType`` is forced to
    ``"Developer"``. The payload is uploaded to a temporary path under
    ``/PublicStaging/pymobiledevice3`` via AFC, the command is dispatched with
    `send_package`, and the temporary file is removed afterwards.

    :param package_path: Local path to a ``.ipa`` file, a ``.ipcc`` file, or an app directory.
        String values are coerced to `Path`.
    :param cmd: Installation-proxy command name, sent as ``Command``. Defaults to ``"Install"``.
    :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
    :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
        progress response. ``None`` disables progress callbacks.
    :param developer: When ``True``, sets ``PackageType`` to ``"Developer"`` in the options.
    :param args: Extra positional arguments forwarded to ``handler``.
    :returns: None.
    :raises AppInstallError: If the installation fails.
    """
    ipcc_mode = package_path.suffix == ".ipcc"

    if options is None:
        options = {}

    ipa_contents = b""
    if ipcc_mode:
        options["PackageType"] = "CarrierBundle"
    else:
        if package_path.is_dir():
            # treat as app, convert into an ipa
            ipa_contents = create_ipa_contents_from_directory(str(package_path))
        else:
            # treat as ipa
            ipa_contents = package_path.read_bytes()

    if developer:
        options["PackageType"] = "Developer"

    async with AfcService(self.lockdown) as afc:
        fname = f"{TEMP_REMOTE_BASEDIR}/{uuid.uuid4()}.{'ipcc' if ipcc_mode else 'ipa'}"
        try:
            if not ipcc_mode:
                await afc.makedirs(TEMP_REMOTE_BASEDIR)
                await self._upload_package(afc, fname, ipa_contents, package_path.name)

            else:
                await self.upload_ipcc_from_path(package_path, fname, afc)

            await self.send_package(cmd, options, handler, fname, *args)
        finally:
            await afc.rm_single(fname, force=True)
```

### send_package

```
send_package(cmd: str, options: Optional[dict[str, Any]], handler: Optional[Callable[..., Any]], package_path: str, *args: Any)
```

Send an install/upgrade command for a package already staged on the device, and wait for completion.

Sends `{"Command": cmd, "ClientOptions": options, "PackagePath": package_path}` to the service, then consumes progress/status responses until the operation completes. Typically invoked by `install_from_local` and `install_from_bytes` after uploading the package via AFC.

Parameters:

| Name           | Type                           | Description                                                                                                                 | Default    |
| -------------- | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `cmd`          | `str`                          | Installation-proxy command name, sent as Command.                                                                           | *required* |
| `options`      | `Optional[dict[str, Any]]`     | Command options, sent as ClientOptions.                                                                                     | *required* |
| `handler`      | `Optional[Callable[..., Any]]` | Progress callback invoked as handler(percent_complete, \*args) on each progress response. None disables progress callbacks. | *required* |
| `package_path` | `str`                          | On-device path to the staged package, sent as PackagePath.                                                                  | *required* |
| `args`         | `Any`                          | Extra positional arguments forwarded to handler.                                                                            | `()`       |

Returns:

| Type | Description |
| ---- | ----------- |
|      | None.       |

Raises:

| Type              | Description                                                            |
| ----------------- | ---------------------------------------------------------------------- |
| `AppInstallError` | If the service reports an error or finishes without a Complete status. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def send_package(
    self,
    cmd: str,
    options: Optional[dict[str, Any]],
    handler: Optional[Callable[..., Any]],
    package_path: str,
    *args: Any,
):
    """
    Send an install/upgrade command for a package already staged on the device, and wait for completion.

    Sends ``{"Command": cmd, "ClientOptions": options, "PackagePath": package_path}`` to the
    service, then consumes progress/status responses until the operation completes. Typically
    invoked by `install_from_local` and `install_from_bytes` after uploading the
    package via AFC.

    :param cmd: Installation-proxy command name, sent as ``Command``.
    :param options: Command options, sent as ``ClientOptions``.
    :param handler: Progress callback invoked as ``handler(percent_complete, *args)`` on each
        progress response. ``None`` disables progress callbacks.
    :param package_path: On-device path to the staged package, sent as ``PackagePath``.
    :param args: Extra positional arguments forwarded to ``handler``.
    :returns: None.
    :raises AppInstallError: If the service reports an error or finishes without a ``Complete`` status.
    """
    await self.service.send_plist(
        cast(
            PlistSendable,
            {
                "Command": cmd,
                "ClientOptions": options,
                "PackagePath": package_path,
            },
        )
    )

    await self._watch_completion(handler, *args)
```

### upload_ipcc_from_path

```
upload_ipcc_from_path(file: Path, remote_path: str, afc_client: AfcService) -> None
```

Upload a local IPCC (carrier bundle) zip to the device, unpacking it into the remote path.

Reads the file into memory and forwards it to the unpacking uploader, which recreates the zip's directory tree under `remote_path` on the device via the given AFC client.

Parameters:

| Name          | Type         | Description                                                       | Default    |
| ------------- | ------------ | ----------------------------------------------------------------- | ---------- |
| `file`        | `Path`       | Local path to the .ipcc zip file.                                 | *required* |
| `remote_path` | `str`        | Destination directory on the device where the bundle is unpacked. | *required* |
| `afc_client`  | `AfcService` | Connected AfcService used to write the files.                     | *required* |

Returns:

| Type   | Description |
| ------ | ----------- |
| `None` | None.       |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def upload_ipcc_from_path(self, file: Path, remote_path: str, afc_client: AfcService) -> None:
    """
    Upload a local IPCC (carrier bundle) zip to the device, unpacking it into the remote path.

    Reads the file into memory and forwards it to the unpacking uploader, which recreates the
    zip's directory tree under ``remote_path`` on the device via the given AFC client.

    :param file: Local path to the ``.ipcc`` zip file.
    :param remote_path: Destination directory on the device where the bundle is unpacked.
    :param afc_client: Connected `AfcService` used to write
        the files.
    :returns: None.
    """
    with file.open("rb") as fb:
        file_name = file.name
        file_stream = BytesIO(fb.read())
        self.logger.info(f"Uploading {file_name} contents..")
        await self._upload_ipcc(file_stream, afc_client, remote_path)
```

### upload_ipcc_from_bytes

```
upload_ipcc_from_bytes(file_bytes: bytes, remote_path: str, afc_client: AfcService) -> None
```

Upload an in-memory IPCC (carrier bundle) zip to the device, unpacking it into the remote path.

Wraps the bytes in a stream and forwards them to the unpacking uploader, which recreates the zip's directory tree under `remote_path` on the device via the given AFC client.

Parameters:

| Name          | Type         | Description                                                       | Default    |
| ------------- | ------------ | ----------------------------------------------------------------- | ---------- |
| `file_bytes`  | `bytes`      | Raw bytes of the .ipcc zip.                                       | *required* |
| `remote_path` | `str`        | Destination directory on the device where the bundle is unpacked. | *required* |
| `afc_client`  | `AfcService` | Connected AfcService used to write the files.                     | *required* |

Returns:

| Type   | Description |
| ------ | ----------- |
| `None` | None.       |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def upload_ipcc_from_bytes(self, file_bytes: bytes, remote_path: str, afc_client: AfcService) -> None:
    """
    Upload an in-memory IPCC (carrier bundle) zip to the device, unpacking it into the remote path.

    Wraps the bytes in a stream and forwards them to the unpacking uploader, which recreates the
    zip's directory tree under ``remote_path`` on the device via the given AFC client.

    :param file_bytes: Raw bytes of the ``.ipcc`` zip.
    :param remote_path: Destination directory on the device where the bundle is unpacked.
    :param afc_client: Connected `AfcService` used to write
        the files.
    :returns: None.
    """
    file_stream = BytesIO(file_bytes)
    self.logger.info("Uploading IPCC from given bytes..")
    await self._upload_ipcc(file_stream, afc_client, remote_path)
```

### check_capabilities_match

```
check_capabilities_match(capabilities: Optional[dict[str, Any]] = None, options: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]
```

Ask the device whether it satisfies a set of app capabilities.

Sends the `"CheckCapabilitiesMatch"` command. When `capabilities` is provided it is sent under the `Capabilities` key; otherwise no capabilities key is sent. Returns the single `LookupResult` value from the response.

Parameters:

| Name           | Type                       | Description                                                                | Default |
| -------------- | -------------------------- | -------------------------------------------------------------------------- | ------- |
| `capabilities` | `Optional[dict[str, Any]]` | Capabilities to check, sent as Capabilities. If falsy, the key is omitted. | `None`  |
| `options`      | `Optional[dict[str, Any]]` | Command options, sent as ClientOptions. None is sent as an empty dict.     | `None`  |

Returns:

| Type                       | Description                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `Optional[dict[str, Any]]` | The LookupResult value from the response describing the matched capabilities, or None if absent. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def check_capabilities_match(
    self, capabilities: Optional[dict[str, Any]] = None, options: Optional[dict[str, Any]] = None
) -> Optional[dict[str, Any]]:
    """
    Ask the device whether it satisfies a set of app capabilities.

    Sends the ``"CheckCapabilitiesMatch"`` command. When ``capabilities`` is provided it is
    sent under the ``Capabilities`` key; otherwise no capabilities key is sent. Returns the
    single ``LookupResult`` value from the response.

    :param capabilities: Capabilities to check, sent as ``Capabilities``. If falsy, the key is
        omitted.
    :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
    :returns: The ``LookupResult`` value from the response describing the matched capabilities,
        or ``None`` if absent.
    """
    if options is None:
        options = {}
    cmd: dict[str, Any] = {"Command": "CheckCapabilitiesMatch", "ClientOptions": options}

    if capabilities:
        cmd["Capabilities"] = capabilities

    await self.service.send_plist(cmd)
    return cast(Optional[dict[str, Any]], (await self.service.recv_plist()).get("LookupResult"))
```

### browse

```
browse(options: Optional[dict[str, Any]] = None, attributes: Optional[list[str]] = None) -> list[dict[str, Any]]
```

Enumerate installed apps via the `"Browse"` command.

Sends the command and accumulates each response's `CurrentList` entries until the service reports a `Complete` status (or returns an empty response).

Parameters:

| Name         | Type                       | Description                                                                                       | Default |
| ------------ | -------------------------- | ------------------------------------------------------------------------------------------------- | ------- |
| `options`    | `Optional[dict[str, Any]]` | Command options, sent as ClientOptions. None is sent as an empty dict.                            | `None`  |
| `attributes` | `Optional[list[str]]`      | When provided, set as the ReturnAttributes option to limit which per-app attributes are returned. | `None`  |

Returns:

| Type                   | Description                                                                   |
| ---------------------- | ----------------------------------------------------------------------------- |
| `list[dict[str, Any]]` | A list of per-app info dictionaries collected from all CurrentList responses. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def browse(
    self, options: Optional[dict[str, Any]] = None, attributes: Optional[list[str]] = None
) -> list[dict[str, Any]]:
    """
    Enumerate installed apps via the ``"Browse"`` command.

    Sends the command and accumulates each response's ``CurrentList`` entries until the service
    reports a ``Complete`` status (or returns an empty response).

    :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
    :param attributes: When provided, set as the ``ReturnAttributes`` option to limit which
        per-app attributes are returned.
    :returns: A list of per-app info dictionaries collected from all ``CurrentList`` responses.
    """
    if options is None:
        options = {}
    if attributes:
        options["ReturnAttributes"] = attributes

    cmd: dict[str, Any] = {"Command": "Browse", "ClientOptions": options}

    await self.service.send_plist(cmd)

    result: list[dict[str, Any]] = []
    while True:
        response = await self.service.recv_plist()
        if not response:
            break

        data = response.get("CurrentList")
        if data is not None:
            result += cast(list[dict[str, Any]], data)

        if response.get("Status") == "Complete":
            break

    return result
```

### lookup

```
lookup(options: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]
```

Look up installed apps via the `"Lookup"` command.

Sends the command and returns the single `LookupResult` value from the response. The options dict (e.g. `BundleIDs`, `ApplicationType`, `ReturnAttributes`) determines which apps and attributes are returned.

Parameters:

| Name      | Type                       | Description                                                            | Default |
| --------- | -------------------------- | ---------------------------------------------------------------------- | ------- |
| `options` | `Optional[dict[str, Any]]` | Command options, sent as ClientOptions. None is sent as an empty dict. | `None`  |

Returns:

| Type                       | Description                                                                                  |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| `Optional[dict[str, Any]]` | The LookupResult mapping bundle identifiers to per-app info dictionaries, or None if absent. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def lookup(self, options: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
    """
    Look up installed apps via the ``"Lookup"`` command.

    Sends the command and returns the single ``LookupResult`` value from the response. The
    options dict (e.g. ``BundleIDs``, ``ApplicationType``, ``ReturnAttributes``) determines
    which apps and attributes are returned.

    :param options: Command options, sent as ``ClientOptions``. ``None`` is sent as an empty dict.
    :returns: The ``LookupResult`` mapping bundle identifiers to per-app info dictionaries, or
        ``None`` if absent.
    """
    if options is None:
        options = {}
    cmd: dict[str, Any] = {"Command": "Lookup", "ClientOptions": options}
    await self.service.send_plist(cmd)
    return cast(Optional[dict[str, Any]], (await self.service.recv_plist()).get("LookupResult"))
```

### get_apps

```
get_apps(application_type: str = 'Any', calculate_sizes: bool = False, bundle_identifiers: Optional[list[str]] = None, show_placeholders: bool = False) -> dict[str, dict[str, Any]]
```

Retrieve installed apps, keyed by bundle identifier.

Builds a lookup query from the given filters and calls `lookup`. When `calculate_sizes` is set, a second lookup is issued requesting `CFBundleIdentifier`, `StaticDiskUsage` and `DynamicDiskUsage`, and those size attributes are merged into the per-app entries.

Parameters:

| Name                 | Type                  | Description                                                                                                                                                                    | Default |
| -------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- |
| `application_type`   | `str`                 | Value for the ApplicationType option. Defaults to "Any"; other values include "System" and "User".                                                                             | `'Any'` |
| `calculate_sizes`    | `bool`                | When True, also fetch and merge static/dynamic disk usage for each app.                                                                                                        | `False` |
| `bundle_identifiers` | `Optional[list[str]]` | When provided, restrict the query to these bundle identifiers via the BundleIDs option.                                                                                        | `None`  |
| `show_placeholders`  | `bool`                | When True, set the ShowPlaceholders option to include placeholder (e.g. installing/downloading) apps. See https://github.com/doronz88/pymobiledevice3/issues/1602 for details. | `False` |

Returns:

| Type                        | Description                                                                 |
| --------------------------- | --------------------------------------------------------------------------- |
| `dict[str, dict[str, Any]]` | A dictionary mapping each bundle identifier to its per-app info dictionary. |

Source code in `pymobiledevice3/services/installation_proxy.py`

```
async def get_apps(
    self,
    application_type: str = "Any",
    calculate_sizes: bool = False,
    bundle_identifiers: Optional[list[str]] = None,
    show_placeholders: bool = False,
) -> dict[str, dict[str, Any]]:
    """
    Retrieve installed apps, keyed by bundle identifier.

    Builds a lookup query from the given filters and calls `lookup`. When
    ``calculate_sizes`` is set, a second lookup is issued requesting ``CFBundleIdentifier``,
    ``StaticDiskUsage`` and ``DynamicDiskUsage``, and those size attributes are merged into the
    per-app entries.

    :param application_type: Value for the ``ApplicationType`` option. Defaults to ``"Any"``;
        other values include ``"System"`` and ``"User"``.
    :param calculate_sizes: When ``True``, also fetch and merge static/dynamic disk usage for
        each app.
    :param bundle_identifiers: When provided, restrict the query to these bundle identifiers via
        the ``BundleIDs`` option.
    :param show_placeholders: When ``True``, set the ``ShowPlaceholders`` option to include
        placeholder (e.g. installing/downloading) apps.
        See <https://github.com/doronz88/pymobiledevice3/issues/1602> for details.
    :returns: A dictionary mapping each bundle identifier to its per-app info dictionary.
    """
    options: dict[str, Any] = {}
    if bundle_identifiers is not None:
        options["BundleIDs"] = bundle_identifiers

    options["ApplicationType"] = application_type
    if show_placeholders:
        options["ShowPlaceholders"] = True
    result = await self.lookup(options)
    if result is None:
        raise AppInstallError("Lookup response is missing LookupResult")
    if calculate_sizes:
        options.update(GET_APPS_ADDITIONAL_INFO)
        additional_info = await self.lookup(options)
        if additional_info is None:
            raise AppInstallError("Lookup response is missing LookupResult")
        for bundle_identifier, app in additional_info.items():
            result[bundle_identifier].update(app)
    return result
```

## pymobiledevice3.services.streaming_zip_conduit.StreamingZipConduitService

Bases: `LockdownService`

Stream an app to the device and install it, the way Xcode does.

The device extracts the archive while it arrives, instead of receiving an `.ipa` over AFC and unpacking it afterwards as `InstallationProxyService` does, so nothing is written twice. The stream is a zip without compression and without a central directory, opened by a metadata record.

Each instance performs a single transfer. This is a lockdown service; the RSD/tunnel variant is chosen automatically for `RemoteServiceDiscoveryService` providers.

Source code in `pymobiledevice3/services/streaming_zip_conduit.py`

```
class StreamingZipConduitService(LockdownService):
    """
    Stream an app to the device and install it, the way Xcode does.

    The device extracts the archive while it arrives, instead of receiving an ``.ipa`` over AFC and
    unpacking it afterwards as `InstallationProxyService` does, so nothing is written twice. The
    stream is a zip without compression and without a central directory, opened by a metadata
    record.

    Each instance performs a single transfer. This is a lockdown service; the RSD/tunnel variant is
    chosen automatically for `RemoteServiceDiscoveryService` providers.
    """

    SERVICE_NAME = "com.apple.streaming_zip_conduit"
    RSD_SERVICE_NAME = "com.apple.streaming_zip_conduit.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        """
        :param lockdown: service provider used to start the service and reach the device.
        """
        if isinstance(lockdown, RemoteServiceDiscoveryService):
            super().__init__(lockdown, self.RSD_SERVICE_NAME)
        else:
            super().__init__(lockdown, self.SERVICE_NAME)

    async def install(
        self,
        package_path: Path,
        developer: bool = False,
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[[int], Any]] = None,
    ) -> None:
        """
        Stream a local app to the device and install it.

        :param package_path: an ``.ipa`` file or an unpackaged ``.app`` directory.
        :param developer: install as a developer package (``PackageType`` ``Developer``) rather than
            a customer one.
        :param options: extra installation options, merged over the defaults.
        :param handler: progress callback, invoked with the installation completion percentage.
        :raises AppInstallError: if the device fails to install the app.
        :raises StreamingZipConduitError: if the device refuses or fails the transfer.
        """
        install_options: dict[str, Any] = {"PackageType": "Developer" if developer else "Customer"}
        install_options.update(options or {})
        setup: dict[str, Any] = {
            "InstallOptionsDictionary": install_options,
            "InstallTransferredDirectory": True,
            "MediaSubdir": f"{STAGING_DIRECTORY}/pymobiledevice3-{uuid.uuid4()}.ipa",
            "UserInitiatedTransfer": False,
        }
        if package_path.is_dir():
            await self._transfer(setup, _app_directory_entries(package_path), handler, package_path.name)
        else:
            with zipfile.ZipFile(package_path) as archive:
                await self._transfer(setup, _ipa_entries(archive), handler, package_path.name)

    async def _transfer(
        self, setup: dict[str, Any], entries: list[_Entry], handler: Optional[Callable[[int], Any]], name: str
    ) -> None:
        await self.service.send_plist(setup)
        entries = _with_metadata(entries)
        total = sum(entry.size for entry in entries) + len(_CENTRAL_DIRECTORY_SIGNATURE)
        self.logger.info(f"Uploading {name}...")
        with ProgressBar(total=total, desc=name, unit=BYTES_UNIT) as upload_bar:
            for entry in entries:
                await self.service.sendall(entry.header())
                for chunk in entry.chunks():
                    await self.service.sendall(chunk)
                    upload_bar.update(len(chunk))
            await self.service.sendall(_CENTRAL_DIRECTORY_SIGNATURE)
            upload_bar.update(len(_CENTRAL_DIRECTORY_SIGNATURE))
        self.logger.info("Upload complete.")

        stage: Optional[str] = None
        with ProgressBar(total=100, desc="install") as install_bar:
            while True:
                response = await self.service.recv_plist()
                if "Error" in response:
                    raise StreamingZipConduitError(str(response["Error"]))
                progress = cast(dict[str, Any], response.get("InstallProgressDict") or {})
                if "Error" in progress:
                    raise AppInstallError(f"{progress['Error']}: {progress.get('ErrorDescription')}")
                status = progress.get("Status")
                if status and status != "Complete" and status != stage:
                    stage = status
                    self.logger.info(f"Stage: {status}")
                if "PercentComplete" in progress:
                    install_bar.n = progress["PercentComplete"]
                    if handler is not None:
                        handler(progress["PercentComplete"])
                if response.get("Status") == "DataComplete":
                    break
        self.logger.info("Installation succeed.")
```

### install

```
install(package_path: Path, developer: bool = False, options: Optional[dict[str, Any]] = None, handler: Optional[Callable[[int], Any]] = None) -> None
```

Stream a local app to the device and install it.

Parameters:

| Name           | Type                             | Description                                                                        | Default    |
| -------------- | -------------------------------- | ---------------------------------------------------------------------------------- | ---------- |
| `package_path` | `Path`                           | an .ipa file or an unpackaged .app directory.                                      | *required* |
| `developer`    | `bool`                           | install as a developer package (PackageType Developer) rather than a customer one. | `False`    |
| `options`      | `Optional[dict[str, Any]]`       | extra installation options, merged over the defaults.                              | `None`     |
| `handler`      | `Optional[Callable[[int], Any]]` | progress callback, invoked with the installation completion percentage.            | `None`     |

Raises:

| Type                       | Description                                  |
| -------------------------- | -------------------------------------------- |
| `AppInstallError`          | if the device fails to install the app.      |
| `StreamingZipConduitError` | if the device refuses or fails the transfer. |

Source code in `pymobiledevice3/services/streaming_zip_conduit.py`

```
async def install(
    self,
    package_path: Path,
    developer: bool = False,
    options: Optional[dict[str, Any]] = None,
    handler: Optional[Callable[[int], Any]] = None,
) -> None:
    """
    Stream a local app to the device and install it.

    :param package_path: an ``.ipa`` file or an unpackaged ``.app`` directory.
    :param developer: install as a developer package (``PackageType`` ``Developer``) rather than
        a customer one.
    :param options: extra installation options, merged over the defaults.
    :param handler: progress callback, invoked with the installation completion percentage.
    :raises AppInstallError: if the device fails to install the app.
    :raises StreamingZipConduitError: if the device refuses or fails the transfer.
    """
    install_options: dict[str, Any] = {"PackageType": "Developer" if developer else "Customer"}
    install_options.update(options or {})
    setup: dict[str, Any] = {
        "InstallOptionsDictionary": install_options,
        "InstallTransferredDirectory": True,
        "MediaSubdir": f"{STAGING_DIRECTORY}/pymobiledevice3-{uuid.uuid4()}.ipa",
        "UserInitiatedTransfer": False,
    }
    if package_path.is_dir():
        await self._transfer(setup, _app_directory_entries(package_path), handler, package_path.name)
    else:
        with zipfile.ZipFile(package_path) as archive:
            await self._transfer(setup, _ipa_entries(archive), handler, package_path.name)
```

## pymobiledevice3.services.afc.AfcService

Bases: `LockdownService`

Apple File Connection (AFC) Service for iOS device file system access.

This service provides full file system access to the /var/mobile/Media directory on iOS devices. It supports standard file operations including read, write, delete, rename, and directory operations.

The service communicates using a custom binary protocol with operation codes for different file system operations. AFC responses echo the `packet_num` from the request, enabling full concurrent operation: multiple callers may issue operations simultaneously and a background reader task routes each response to the correct waiter via a per-`packet_num` Future.

Attributes: SERVICE_NAME: Service identifier for lockdown-based connections RSD_SERVICE_NAME: Service identifier for RSD-based connections packet_num: Counter for tracking packet sequence numbers

Source code in `pymobiledevice3/services/afc.py`

```
class AfcService(LockdownService):
    """
    Apple File Connection (AFC) Service for iOS device file system access.

    This service provides full file system access to the /var/mobile/Media directory
    on iOS devices. It supports standard file operations including read, write, delete,
    rename, and directory operations.

    The service communicates using a custom binary protocol with operation codes for
    different file system operations. AFC responses echo the ``packet_num`` from the
    request, enabling full concurrent operation: multiple callers may issue operations
    simultaneously and a background reader task routes each response to the correct waiter
    via a per-``packet_num`` Future.

    Attributes:
        SERVICE_NAME: Service identifier for lockdown-based connections
        RSD_SERVICE_NAME: Service identifier for RSD-based connections
        packet_num: Counter for tracking packet sequence numbers
    """

    SERVICE_NAME = "com.apple.afc"
    RSD_SERVICE_NAME = "com.apple.afc.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider, service_name: Optional[str] = None):
        """
        Initialize the AFC service.

        :param lockdown: Lockdown service provider for establishing connection
        :param service_name: Optional service name override. Auto-detected if None
        """
        super().__init__(lockdown, service_name)
        self.packet_num = 0
        # Demux state — populated in __aenter__, torn down in __aexit__
        self._afc_pending: dict[int, asyncio.Future[Any]] = {}
        self._afc_write_lock = asyncio.Lock()
        self._afc_reader_task: Optional[asyncio.Task[None]] = None
        # Set (and never cleared) once the connection terminates; the reader task handle
        # itself is not a stable signal because _send_and_wait restarts exited readers.
        self._afc_terminated = asyncio.Event()

    async def __aenter__(self):
        await super().__aenter__()
        self._afc_reader_task = asyncio.create_task(self._afc_reader_loop(), name="afc-reader")
        return self

    async def aclose(self) -> None:
        """Shut down the service: stop the reader task, fail all in-flight requests with
        ``ConnectionTerminatedError``, and close the underlying connection."""
        if self._afc_reader_task is not None:
            self._afc_reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._afc_reader_task
            self._afc_reader_task = None
        for fut in self._afc_pending.values():
            if not fut.done():
                fut.set_exception(ConnectionTerminatedError())
        self._afc_pending.clear()
        await super().close()

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        await self.aclose()

    async def wait_terminated(self) -> None:
        """Block until the AFC connection terminates (e.g. the device disconnects).

        Ensures the background reader is running so termination is detected even when no
        AFC operation is in flight. Returns immediately if the connection already died.
        """
        if not self._afc_terminated.is_set():
            await self.connect()
            if self._afc_reader_task is None or self._afc_reader_task.done():
                self._afc_reader_task = asyncio.create_task(self._afc_reader_loop(), name="afc-reader")
        await self._afc_terminated.wait()

    async def _afc_reader_loop(self) -> None:
        """Background task: read AFC response packets and route them to waiting callers."""
        try:
            while True:
                header_bytes = await self.service.recvall(AFC_HEADER_SIZE)
                if not header_bytes:
                    break
                header = AfcHeader.parse(header_bytes)
                assert header.entire_length >= AFC_HEADER_SIZE
                length = header.entire_length - AFC_HEADER_SIZE
                data = await self.service.recvall(length) if length else b""

                status = AfcError.SUCCESS
                if header.operation == AfcOpcode.STATUS:
                    if length != 8:
                        self.logger.error("Status length != 8")
                    status = parse_afc_status(data)
                elif header.operation != AfcOpcode.DATA:
                    self.logger.debug("Unexpected AFC opcode %s", header.operation)

                fut = self._afc_pending.pop(header.packet_num, None)
                if fut is not None and not fut.done():
                    fut.set_result((status, data))
                else:
                    self.logger.warning("AFC: no waiter for packet_num=%d", header.packet_num)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # Propagate to all pending waiters so they don't hang
            for fut in self._afc_pending.values():
                if not fut.done():
                    fut.set_exception(e)
            self._afc_pending.clear()
        finally:
            self._afc_terminated.set()

    async def pull(
        self,
        relative_src: str,
        dst: str,
        match: Optional[Pattern[str]] = None,
        callback: Optional[Callable[..., Any]] = None,
        src_dir: str = "",
        ignore_errors: bool = False,
        progress_bar: bool = True,
    ) -> None:
        """
        Pull (download) a file or directory from the device to the local machine.

        The source is resolved through any symbolic link before transfer. A regular file is
        written to ``dst``; if ``dst`` is an existing local directory, the file is placed
        inside it under the source's basename. Files larger than ``MAXIMUM_READ_SIZE`` (4 MB)
        are streamed in chunks. The local file's modification time is set to match the
        device's ``st_mtime``. A directory source is copied recursively into a subdirectory
        of ``dst`` named after the source's basename.

        :param relative_src: Source path on the device, resolved relative to ``src_dir``.
        :param dst: Destination path on the local machine.
        :param match: Optional regex; only entries whose basename matches (via ``search``) are
            copied. Non-matching files are skipped.
        :param callback: Optional callable invoked as ``callback(src, dst)`` after each regular
            file is copied. If it returns an awaitable, the awaitable is awaited.
        :param src_dir: Base directory on the device against which ``relative_src`` is joined.
        :param ignore_errors: If True, per-entry errors during directory recursion are logged
            and skipped instead of propagated.
        :param progress_bar: If True, display a progress bar while streaming large files.
        """
        src = await self.resolve_path(posixpath.join(src_dir, relative_src))

        if not await self.isdir(src):
            # normal file
            if match is not None and not match.search(posixpath.basename(src)):
                return
            if os.path.isdir(dst):
                dst = os.path.join(dst, os.path.basename(relative_src))
            with open(dst, "wb") as f:
                src_size = (await self.stat(src))["st_size"]
                if src_size <= MAXIMUM_READ_SIZE:
                    contents = await self.get_file_contents(src)
                    f.write(contents)
                else:
                    handle = await self.fopen(src)
                    # Bytes-scaled bar (B/KB/MB with a live rate) rather than a chunk
                    # counter — the rate readout doubles as a transfer benchmark.
                    with ProgressBar(
                        total=src_size, desc=posixpath.basename(src), unit=BYTES_UNIT, disable=not progress_bar
                    ) as pbar:
                        for offset in range(0, src_size, MAXIMUM_READ_SIZE):
                            to_read = min(MAXIMUM_READ_SIZE, src_size - offset)
                            chunk = await self.fread(handle, to_read)
                            f.write(chunk)
                            pbar.update(len(chunk))
                    await self.fclose(handle)
            os.utime(dst, (os.stat(dst).st_atime, (await self.stat(src))["st_mtime"].timestamp()))
            if callback is not None:
                result = callback(src, dst)
                if inspect.isawaitable(result):
                    await result
        else:
            # directory
            dst_path = pathlib.Path(dst) / os.path.basename(relative_src)
            dst_path.mkdir(parents=True, exist_ok=True)

            for filename in await self.listdir(src):
                src_filename = posixpath.join(src, filename)
                src_filename = await self.resolve_path(src_filename)

                if match is not None and not match.search(posixpath.basename(src_filename)):
                    continue

                try:
                    dst_filename = device_file_path(dst_path, filename)
                    # A link is pulled under its target's name, which is just as device-supplied
                    validate_device_filename(posixpath.basename(src_filename))
                    if await self.isdir(src_filename):
                        dst_filename.mkdir(exist_ok=True)
                        await self.pull(
                            src_filename,
                            str(dst_path),
                            match=match,
                            callback=callback,
                            ignore_errors=ignore_errors,
                            progress_bar=progress_bar,
                        )
                        continue

                    await self.pull(
                        src_filename,
                        str(dst_path),
                        match=match,
                        callback=callback,
                        ignore_errors=ignore_errors,
                        progress_bar=progress_bar,
                    )

                except Exception as afc_exception:
                    if not ignore_errors:
                        raise
                    self.logger.warning(f"(Ignoring) Error: {afc_exception} occurred during the copy of {src_filename}")

    @path_to_str()
    async def exists(self, filename: str):
        """
        Check whether a path exists on the device.

        Implemented by attempting `stat`; a missing path is reported as False and any
        other AFC error propagates.

        :param filename: Path to check.
        :return: True if the path exists, False if it was not found.
        """
        try:
            await self.stat(filename)
        except AfcFileNotFoundError:
            return False
        return True

    @path_to_str()
    async def wait_exists(self, filename: str):
        """
        Block until a path exists on the device.

        Polls `exists` every 0.1 seconds until the path appears. Does not return
        until the path exists.

        :param filename: Path to wait for.
        """
        while not await self.exists(filename):
            await asyncio.sleep(0.1)

    @path_to_str()
    async def _push_internal(
        self,
        local_path: str,
        remote_path: str,
        callback: Optional[Callable[[str, str], Any]] = None,
        progress_bar: bool = True,
    ):
        """
        Internal method for pushing files to the device.

        :param local_path: Local file or directory path
        :param remote_path: Remote destination path on the device
        :param callback: Optional callback function called for each file copied (src, dst)
        :param progress_bar: If True, display a progress bar while streaming large files.
        """
        if callback is not None:
            callback(local_path, remote_path)

        if not os.path.isdir(local_path):
            # normal file
            try:
                if await self.isdir(remote_path):
                    # Remote is dir.
                    remote_path = posixpath.join(remote_path, os.path.basename(local_path))
            except AfcFileNotFoundError:
                # Remote is file.
                remote_parent = posixpath.dirname(remote_path)
                if not await self.exists(remote_parent):
                    raise
                remote_path = posixpath.join(remote_parent, os.path.basename(remote_path))
            src_size = os.path.getsize(local_path)
            if src_size <= MAXIMUM_READ_SIZE:
                with open(local_path, "rb") as f:
                    await self.set_file_contents(remote_path, f.read())
            else:
                # Stream large files in chunks instead of loading them whole into memory,
                # with the same bytes-scaled bar `pull` shows — the live rate readout
                # doubles as a transfer benchmark.
                handle = await self.fopen(remote_path, "w")
                try:
                    with (
                        open(local_path, "rb") as f,
                        ProgressBar(
                            total=src_size, desc=os.path.basename(local_path), unit=BYTES_UNIT, disable=not progress_bar
                        ) as pbar,
                    ):
                        while True:
                            chunk = f.read(MAXIMUM_READ_SIZE)
                            if not chunk:
                                break
                            await self.fwrite(handle, chunk)
                            pbar.update(len(chunk))
                finally:
                    await self.fclose(handle)
        else:
            # directory
            if not await self.exists(remote_path):
                await self.makedirs(remote_path)

            for filename in os.listdir(local_path):
                local_filename = os.path.join(local_path, filename)
                remote_filename = posixpath.join(remote_path, filename).removeprefix("/")

                if os.path.isdir(local_filename):
                    if not await self.exists(remote_filename):
                        await self.makedirs(remote_filename)
                    await self._push_internal(
                        local_filename, remote_filename, callback=callback, progress_bar=progress_bar
                    )
                    continue

                await self._push_internal(local_filename, remote_filename, callback=callback, progress_bar=progress_bar)

    @path_to_str()
    async def push(
        self,
        local_path: str,
        remote_path: str,
        callback: Optional[Callable[[str, str], Any]] = None,
        progress_bar: bool = True,
    ):
        """
        Push (upload) a file or directory from the local machine to the device.

        A regular file is written to ``remote_path`` (or, if ``remote_path`` is an existing
        remote directory, into it under the file's basename). Files larger than
        ``MAXIMUM_READ_SIZE`` (4 MB) are streamed in chunks with a byte-scaled progress bar.
        A local directory is copied recursively into ``remote_path``/<basename of local_path>,
        creating remote directories as needed.

        :param local_path: Source path on the local machine.
        :param remote_path: Destination path on the device.
        :param callback: Optional callable invoked as ``callback(local_path, remote_path)``
            before each entry is transferred.
        :param progress_bar: If True, display a progress bar while streaming large files.
        """
        if os.path.isdir(local_path):
            remote_path = posixpath.join(remote_path, os.path.basename(local_path))
        await self._push_internal(local_path, remote_path, callback, progress_bar=progress_bar)

    @path_to_str()
    async def rm_single(self, filename: str, force: bool = False) -> bool:
        """
        Remove a single file or empty directory on the device.

        Issues a single ``REMOVE_PATH`` operation; it does not recurse into a non-empty
        directory.

        :param filename: Path to the file or directory to remove.
        :param force: If True, swallow an `AfcException` and return False instead of raising.
        :return: True on success; False if the removal failed and ``force`` is True.
        :raises AfcException: if the removal fails and ``force`` is False.
        """
        try:
            await self._do_operation(AfcOpcode.REMOVE_PATH, CSTRING.build(filename), filename)
        except AfcException:
            if force:
                return False
            raise
        return True

    @path_to_str()
    async def rm(self, filename: str, match: Optional[Pattern[str]] = None, force: bool = False) -> list[str]:
        """
        Recursively remove a file or directory tree on the device.

        Without ``match``, the device removes the whole tree in a single ``REMOVE_PATH_AND_CONTENTS``
        operation; if that fails, the tree is walked instead.

        For a directory, every entry is removed depth-first and the directory itself is removed
        last.

        With ``match``, the same entries `pull` would copy are removed: at every level, entries whose
        basename does not match (via ``search``) are skipped, matching directories are descended into
        with the same pattern, and matching files are removed. Directories (including ``filename``
        itself) are never removed in this mode.

        A path removed by someone else while the tree is walked counts as deleted.

        :param filename: Path to the file or directory to remove.
        :param match: Optional regex over entry basenames, applied as `pull` applies it. None removes
            the whole tree.
        :param force: If True, suppress the final `AfcException` and instead return the
            list of paths that could not be deleted.
        :return: List of paths that could not be deleted (empty on full success).
        :raises AfcException: if ``filename`` does not exist and ``force`` is False.
        :raises AfcDeleteError: if any path could not be deleted and ``force`` is False; its ``failures`` say why.
        """
        if match is None:
            # let the device delete the whole tree in one round-trip; on any failure fall back to
            # walking it, which also reports exactly which entries could not be deleted
            with contextlib.suppress(AfcException):
                await self._do_operation(AfcOpcode.REMOVE_PATH_AND_CONTENTS, CSTRING.build(filename), filename)
                return []

        if not await self.exists(filename):
            # a missing path is an error (a dangling link, which cannot be stat'ed, is still removed here)
            if not await self.rm_single(filename, force=force):
                return [filename]
            return []

        failures = await self._rm_tree(filename) if match is None else await self._rm_matching(filename, match)
        if failures and not force:
            raise AfcDeleteError(
                "Failed to delete: "
                + ", ".join(f"{path} ({getattr(status, 'name', status)})" for path, status in failures.items()),
                dict(failures),
            )
        return list(failures)

    async def _remove(self, filename: str) -> Optional[AfcError]:
        """Remove a file or an empty directory; the device's reason when it did not, None when it is gone."""
        try:
            await self._do_operation(AfcOpcode.REMOVE_PATH, CSTRING.build(filename), filename)
        except AfcException as e:
            if e.status == AfcError.OBJECT_NOT_FOUND:
                # removed meanwhile (e.g. by the device itself): what was asked for holds
                return None
            return AfcError(e.status) if e.status is not None else AfcError.UNKNOWN_ERROR
        return None

    async def _rm_tree(self, filename: str) -> dict[str, AfcError]:
        """Remove ``filename`` and, for a directory, everything under it depth-first; return what was not removed."""
        try:
            is_dir = await self.isdir(filename)
        except AfcFileNotFoundError:
            # gone, or a dangling link the device cannot stat: removing it settles both
            is_dir = False
        failures: dict[str, AfcError] = {}
        if is_dir:
            try:
                entries = await self.listdir(filename)
            except AfcFileNotFoundError:
                entries = []
            for entry in entries:
                failures.update(await self._rm_tree(posixpath.join(filename, entry)))
        status = await self._remove(filename)
        if status is not None:
            failures[filename] = status
        return failures

    async def _rm_matching(self, filename: str, match: Pattern[str]) -> dict[str, AfcError]:
        """Remove the files under ``filename`` that `pull` would copy for ``match``; return what was not removed."""
        try:
            is_dir = await self.isdir(filename)
        except AfcFileNotFoundError:
            return {}
        if not is_dir:
            if not match.search(posixpath.basename(filename)):
                return {}
            status = await self._remove(filename)
            return {} if status is None else {filename: status}

        failures: dict[str, AfcError] = {}
        for entry in await self.listdir(filename):
            if not match.search(entry):
                continue
            failures.update(await self._rm_matching(posixpath.join(filename, entry), match))
        return failures

    async def get_device_info(self):
        """
        Query device file-system information.

        Issues a ``GET_DEVINFO`` operation and decodes the null-terminated key/value list into
        a dictionary (e.g. model, total/free bytes, block size).

        :return: Dictionary of device file-system attributes (all values are strings).
        """
        return list_to_dict(await self._do_operation(AfcOpcode.GET_DEVINFO))

    @path_to_str()
    async def listdir(self, filename: str) -> list[str]:
        """
        List the entries of a directory on the device.

        :param filename: Path to the directory.
        :return: Entry names in the directory, excluding ``.`` and ``..``.
        :raises AfcFileNotFoundError: if the path does not exist.
        :raises AfcException: if the path is not a directory or cannot be listed.
        """
        data = await self._do_operation(AfcOpcode.READ_DIR, CSTRING.build(filename), filename)
        return AfcReadDirResponse.parse(data).filenames[2:]  # skip the . and ..

    @path_to_str()
    async def makedirs(self, filename: str):
        """
        Create a directory on the device.

        Issues a ``MAKE_DIR`` operation, creating any missing parent directories.

        :param filename: Path of the directory to create.
        :return: Raw response payload from the operation (typically empty).
        :raises AfcException: if the directory could not be created.
        """
        return await self._do_operation(AfcOpcode.MAKE_DIR, CSTRING.build(filename), filename)

    @path_to_str()
    async def isdir(self, filename: str) -> bool:
        """
        Check whether a path is a directory.

        Stats the path and tests whether its ``st_ifmt`` is ``S_IFDIR``.

        :param filename: Path to check.
        :return: True if the path is a directory, False otherwise.
        :raises AfcFileNotFoundError: if the path does not exist.
        """
        stat = await self.stat(filename)
        return stat.get("st_ifmt") == "S_IFDIR"

    @path_to_str()
    async def stat(self, filename: str) -> dict[str, Any]:
        """
        Get file or directory metadata.

        Issues a ``GET_FILE_INFO`` operation and returns the decoded attribute dictionary.
        Numeric fields (``st_size``, ``st_blocks``, ``st_nlink``) are converted to ints;
        ``st_mtime`` and ``st_birthtime`` are converted from device nanosecond timestamps to
        `datetime`. A ``st_ifmt`` entry (e.g. ``S_IFREG``, ``S_IFDIR``,
        ``S_IFLNK``) describes the file type, and symbolic links also carry a ``LinkTarget``.

        :param filename: Path to the file or directory.
        :return: Dictionary of file attributes.
        :raises AfcFileNotFoundError: if the path does not exist (AFC ``READ_ERROR``).
        :raises AfcException: for any other failure status.
        """
        try:
            stat: dict[str, Any] = list_to_dict(
                await self._do_operation(AfcOpcode.GET_FILE_INFO, CSTRING.build(filename), filename)
            )
        except AfcException as e:
            if e.status != AfcError.READ_ERROR:
                raise
            raise AfcFileNotFoundError(f"No such file on the device: {filename}", e.status, filename) from e

        stat["st_size"] = int(stat["st_size"])
        stat["st_blocks"] = int(stat["st_blocks"])
        stat["st_mtime"] = int(stat["st_mtime"])
        stat["st_birthtime"] = int(stat["st_birthtime"])
        stat["st_nlink"] = int(stat["st_nlink"])
        stat["st_mtime"] = datetime.fromtimestamp(stat["st_mtime"] / (10**9))
        stat["st_birthtime"] = datetime.fromtimestamp(stat["st_birthtime"] / (10**9))
        return stat

    @path_to_str()
    async def os_stat(self, path: str):
        """
        Get file statistics as an `stat`-style result.

        Wraps `stat`, mapping the AFC ``st_ifmt`` to a numeric mode and packing the
        attributes into a `StatResult` namedtuple. ``st_ino`` is synthesized from the
        normalized path, ``st_uid``/``st_gid``/``st_dev`` are reported as 0 and ``st_blksize``
        as 4096 (AFC does not expose these). ``st_atime`` mirrors ``st_mtime``.

        :param path: Path to the file or directory.
        :return: A `StatResult` namedtuple.
        :raises AfcFileNotFoundError: if the path does not exist.
        """
        stat = await self.stat(path)
        mode = 0
        for s_mode in ["S_IFDIR", "S_IFCHR", "S_IFBLK", "S_IFREG", "S_IFIFO", "S_IFLNK", "S_IFSOCK"]:
            if stat["st_ifmt"] == s_mode:
                mode = getattr(stat_module, s_mode)
        return StatResult(
            mode,
            hash(posixpath.normpath(path)),
            0,
            stat["st_nlink"],
            0,
            0,
            stat["st_size"],
            stat["st_mtime"].timestamp(),
            stat["st_mtime"].timestamp(),
            stat["st_birthtime"].timestamp(),
            stat["st_blocks"],
            4096,
            stat["st_birthtime"].timestamp(),
        )

    @path_to_str()
    async def link(self, target: str, source: str, type_: AfcLinkType = AfcLinkType.SYMLINK):
        """
        Create a symbolic or hard link on the device.

        :param target: Path the link points to.
        :param source: Path at which the link is created.
        :param type_: `AfcLinkType` to create (``SYMLINK`` by default, or ``HARDLINK``).
        :return: Raw response payload from the operation (typically empty).
        :raises AfcException: if the link could not be created.
        """
        return await self._do_operation(
            AfcOpcode.MAKE_LINK,
            AfcMakeLinkRequest(type=type_, target=target, source=source).build(),
        )

    @path_to_str()
    async def truncate(self, filename: str, size: int) -> None:
        """
        Truncate or extend a file to ``size`` bytes (``truncate(2)``).

        :param filename: Path to the file.
        :param size: The new file size in bytes.
        :raises AfcFileNotFoundError: if the file does not exist.
        :raises AfcException: if the operation fails.
        """
        await self._do_operation(AfcOpcode.TRUNCATE, AfcTruncateRequest(size=size, filename=filename).build(), filename)

    @path_to_str()
    async def set_file_time(self, filename: str, mtime: datetime) -> None:
        """
        Set the modification time of a file or directory.

        The device stores the time with microsecond resolution, and moves ``st_birthtime`` back
        to ``mtime`` when ``mtime`` is the earlier of the two.

        :param filename: Path to the file or directory.
        :param mtime: The new modification time (naive values are local time, as `stat` returns).
        :raises AfcFileNotFoundError: if the path does not exist.
        :raises AfcException: if the operation fails.
        """
        mtime_ns = round(mtime.timestamp() * 1_000_000) * 1000
        await self._do_operation(
            AfcOpcode.SET_FILE_TIME, AfcSetFileTimeRequest(mtime=mtime_ns, filename=filename).build(), filename
        )

    @path_to_str()
    async def get_file_hash(self, filename: str) -> bytes:
        """
        Get the SHA-1 digest of a file, computed on the device.

        :param filename: Path to the file.
        :return: The 20-byte SHA-1 digest.
        :raises AfcFileNotFoundError: if the file does not exist.
        :raises AfcException: if the path is a directory (``OBJECT_IS_DIR``) or the operation fails.
        """
        try:
            return await self._do_operation(AfcOpcode.GET_FILE_HASH, CSTRING.build(filename), filename)
        except AfcException as e:
            # The device rejects hashing an empty file with INVALID_ARG
            if e.status != AfcError.INVALID_ARG or (await self.stat(filename))["st_size"] != 0:
                raise
            return hashlib.sha1(b"").digest()

    @path_to_str()
    async def get_file_hash_range(self, filename: str, start: int, length: int) -> bytes:
        """
        Get the SHA-1 digest of ``length`` bytes of a file starting at ``start``, computed on the device.

        :param filename: Path to the file.
        :param start: Offset of the first byte to hash.
        :param length: Number of bytes to hash; the range must lie within the file.
        :return: The 20-byte SHA-1 digest.
        :raises AfcFileNotFoundError: if the file does not exist.
        :raises AfcException: if the range exceeds the file (``INVALID_ARG``) or the operation fails.
        """
        return await self._do_operation(
            AfcOpcode.GET_FILE_HASH_RANGE,
            AfcFileHashRangeRequest(start=start, length=length, filename=filename).build(),
            filename,
        )

    @path_to_str()
    async def get_size_of_path_contents(self, filename: str) -> dict[str, int]:
        """
        Get the total size of the regular files under a directory, computed on the device.

        :param filename: Path to the directory (a regular file reports zero).
        :return: ``{"st_size": <bytes>, "st_blocks": <512-byte blocks>}``.
        :raises AfcFileNotFoundError: if the path does not exist.
        :raises AfcException: if the operation fails.
        """
        data = await self._do_operation(
            AfcOpcode.GET_SIZE_OF_PATH_CONTENTS,
            AfcSizeOfPathContentsRequest(flags=0, filename=filename).build(),
            filename,
        )
        return {k: int(v) for k, v in list_to_dict(data).items()}

    async def get_connection_info(self) -> dict[str, str]:
        """
        Query information about the AFC connection (e.g. the server ``Version``).

        :return: Dictionary of connection attributes (all values are strings).
        """
        return list_to_dict(await self._do_operation(AfcOpcode.GET_CON_INFO))

    @path_to_str()
    async def fopen(self, filename: str, mode: str = "r") -> int:
        """
        Open a file on the device and return its handle.

        :param filename: Path to the file.
        :param mode: Textual open mode; one of ``'r'``, ``'r+'``, ``'w'``, ``'w+'``, ``'a'``,
            ``'a+'`` (mapped to the corresponding AFC fopen mode).
        :return: Integer handle usable with `fread`, `fwrite`, `lock` and
            `fclose`.
        :raises ArgumentError: if ``mode`` is not one of the supported textual modes.
        :raises AfcException: if the file could not be opened.
        """
        if mode not in AFC_FOPEN_TEXTUAL_MODES:
            raise ArgumentError(f"Invalid file mode {mode!r}; use one of: {', '.join(AFC_FOPEN_TEXTUAL_MODES)}")

        data = await self._do_operation(
            AfcOpcode.FILE_OPEN,
            AfcFopenRequest(mode=AFC_FOPEN_TEXTUAL_MODES[mode], filename=filename).build(),
        )
        return AfcFopenResponse.parse(data).handle

    async def fclose(self, handle: int):
        """
        Close an open file handle.

        :param handle: Handle returned by `fopen`.
        :return: Raw response payload from the operation (typically empty).
        :raises AfcException: if the close operation fails.
        """
        return await self._do_operation(AfcOpcode.FILE_CLOSE, AfcFcloseRequest(handle=handle).build())

    @path_to_str()
    async def rename(self, source: str, target: str) -> None:
        """
        Rename or move a file or directory on the device.

        :param source: Current path of the file or directory.
        :param target: New path for the file or directory.
        :raises AfcFileNotFoundError: if the operation fails and ``source`` no longer exists.
        :raises AfcException: if the operation fails while ``source`` still exists.
        """
        try:
            await self._do_operation(
                AfcOpcode.RENAME_PATH,
                CSTRING.build(source) + CSTRING.build(target),
            )
        except AfcException as e:
            if await self.exists(source):
                raise
            raise AfcFileNotFoundError(
                f"Failed to rename {source} to {target}: {source} no longer exists.", e.status, source
            ) from e

    async def fread(self, handle: int, sz: int) -> bytes:
        """
        Read data from an open file handle.

        Automatically handles large reads by splitting into multiple operations.
        Each chunk send+receive is performed atomically via the demux reader so
        concurrent callers on the same AfcService instance are safe.

        :param handle: Handle returned by `fopen`.
        :param sz: Number of bytes to read. Reads larger than ``MAXIMUM_READ_SIZE`` (4 MB) are
            split into successive operations.
        :return: The bytes read.
        :raises AfcException: if any read operation returns a non-success status.
        """
        data = b""
        while sz > 0:
            to_read = MAXIMUM_READ_SIZE if sz > MAXIMUM_READ_SIZE else sz
            status, chunk = await self._send_and_wait(
                AfcOpcode.READ, AfcFreadRequest(handle=handle, size=to_read).build()
            )
            if status != AfcError.SUCCESS:
                raise AfcException("Failed to read from the file.", status)
            sz -= to_read
            data += chunk
        return data

    async def fseek(self, handle: int, offset: int, whence: int = os.SEEK_SET) -> None:
        """
        Seek within an open file handle.

        :param handle: Handle returned by `fopen`.
        :param offset: Byte offset relative to ``whence``.
        :param whence: One of ``os.SEEK_SET`` (0), ``os.SEEK_CUR`` (1), ``os.SEEK_END`` (2).
        :raises AfcException: if the seek operation fails.
        """
        await self._do_operation(
            AfcOpcode.FILE_SEEK,
            AfcFileSeekRequest(handle=handle, whence=whence, offset=offset).build(),
        )

    async def ftell(self, handle: int) -> int:
        """
        Get the current position of an open file handle.

        :param handle: Handle returned by `fopen`.
        :return: The current byte offset.
        :raises AfcException: if the tell operation fails.
        """
        return U64_LE.unpack(await self._do_operation(AfcOpcode.FILE_TELL, U64_LE.pack(handle)))[0]

    async def ftruncate(self, handle: int, size: int) -> None:
        """
        Truncate or extend an open file to ``size`` bytes (``ftruncate(2)``).

        The handle's position is left unchanged.

        :param handle: Handle returned by `fopen` with a writable mode.
        :param size: The new file size in bytes.
        :raises AfcException: if the operation fails.
        """
        await self._do_operation(AfcOpcode.FILE_SET_SIZE, AfcFileSetSizeRequest(handle=handle, size=size).build())

    async def pread(self, handle: int, size: int, offset: int) -> bytes:
        """
        Read from an open file handle at an absolute offset (``pread(2)``).

        The handle's position is left unchanged. Reads past the end of the file are short.

        :param handle: Handle returned by `fopen`.
        :param size: Number of bytes to read. Reads larger than ``MAXIMUM_READ_SIZE`` are split
            into successive operations.
        :param offset: Byte offset to read from.
        :return: The bytes read.
        :raises AfcException: if a read operation fails.
        """
        data = b""
        while size > 0:
            to_read = min(size, MAXIMUM_READ_SIZE)
            chunk = await self._do_operation(
                AfcOpcode.FILE_READ_OFFSET,
                AfcFreadOffsetRequest(handle=handle, size=to_read, offset=offset).build(),
            )
            data += chunk
            if len(chunk) < to_read:
                break
            size -= to_read
            offset += to_read
        return data

    async def pwrite(self, handle: int, data: bytes, offset: int, chunk_size: int = MAXIMUM_WRITE_SIZE) -> None:
        """
        Write to an open file handle at an absolute offset (``pwrite(2)``).

        The handle's position is left unchanged; writing past the end extends the file.

        :param handle: Handle returned by `fopen` with a writable mode.
        :param data: Bytes to write.
        :param offset: Byte offset to write at.
        :param chunk_size: Maximum bytes per ``FILE_WRITE_OFFSET`` operation.
        :raises AfcException: if a write operation fails.
        """
        for start in range(0, len(data), chunk_size):
            header = AfcFwriteOffsetHeader(handle=handle, offset=offset + start).build()
            status, _ = await self._send_and_wait(
                AfcOpcode.FILE_WRITE_OFFSET,
                header + data[start : start + chunk_size],
                this_length=AFC_HEADER_SIZE + len(header),
            )
            if status != AfcError.SUCCESS:
                raise AfcException("Failed to write to the file.", status)

    async def fwrite(self, handle: int, data: bytes, chunk_size: int = MAXIMUM_WRITE_SIZE) -> None:
        """
        Write data to an open file handle.

        Automatically handles large writes by splitting into multiple operations.
        Each chunk send+receive is performed atomically via the demux reader so
        concurrent callers on the same AfcService instance are safe.

        :param handle: Handle returned by `fopen`.
        :param data: Bytes to write.
        :param chunk_size: Maximum bytes per ``WRITE`` operation (default ``MAXIMUM_WRITE_SIZE``).
        :raises AfcException: if any write operation returns a non-success status.
        """
        file_handle = U64_LE.pack(handle)
        chunks_count = len(data) // chunk_size
        for i in range(chunks_count):
            chunk = data[i * chunk_size : (i + 1) * chunk_size]
            status, _ = await self._send_and_wait(AfcOpcode.WRITE, file_handle + chunk, this_length=48)
            if status != AfcError.SUCCESS:
                raise AfcException("Failed to write to the file.", status)

        if len(data) % chunk_size:
            chunk = data[chunks_count * chunk_size :]
            status, _ = await self._send_and_wait(AfcOpcode.WRITE, file_handle + chunk, this_length=48)
            if status != AfcError.SUCCESS:
                raise AfcException("Failed to write to the file.", status)

    @path_to_str()
    async def resolve_path(self, filename: str) -> str:
        """
        Resolve a symbolic link to its target path.

        Stats the path; if it is a symbolic link, returns its ``LinkTarget`` (joined against
        the link's parent directory when the target is relative). Non-links are returned
        unchanged. Only a single level of link is resolved.

        :param filename: Path to resolve.
        :return: The link target, or ``filename`` unchanged if it is not a symbolic link.
        :raises AfcFileNotFoundError: if the path does not exist.
        """
        info = await self.stat(filename)
        if info["st_ifmt"] == "S_IFLNK":
            target = info["LinkTarget"]
            filename = posixpath.join(posixpath.dirname(filename), target) if not target.startswith("/") else target
        return filename

    @path_to_str()
    async def get_file_contents(self, filename: str) -> bytes:
        """
        Read and return the entire contents of a file.

        Resolves any symbolic link, verifies the target is a regular file, then opens it,
        reads ``st_size`` bytes and closes the handle.

        :param filename: Path to the file.
        :return: The file contents as bytes.
        :raises AfcException: if the path is not a regular file (``S_IFREG``) or could not be opened.
        :raises AfcFileNotFoundError: if the path does not exist.
        """
        filename = await self.resolve_path(filename)
        info = await self.stat(filename)

        if info["st_ifmt"] != "S_IFREG":
            raise AfcException(f"Not a regular file: {filename}", AfcError.INVALID_ARG, filename)

        h = await self.fopen(filename)
        if not h:
            raise AfcException(f"Failed to open {filename}", AfcError.INTERNAL_ERROR, filename)
        d = await self.fread(h, int(info["st_size"]))
        await self.fclose(h)
        return d

    @path_to_str()
    async def set_file_contents(self, filename: str, data: bytes, progress: Optional[ProgressBar] = None) -> None:
        """
        Write data to a file, creating or truncating it.

        Opens the file in ``'w'`` mode (create/truncate), writes ``data`` and closes the handle.

        :param filename: Path to the file.
        :param data: Bytes to write.
        :param progress: Optional bar advanced as chunks are written.
        :raises AfcException: if the open or write operation fails.
        """
        h = await self.fopen(filename, "w")
        try:
            for offset in range(0, len(data), MAXIMUM_READ_SIZE):
                chunk = data[offset : offset + MAXIMUM_READ_SIZE]
                await self.fwrite(h, chunk)
                if progress is not None:
                    progress.update(len(chunk))
        finally:
            await self.fclose(h)

    @path_to_str()
    async def walk(self, dirname: str) -> AsyncIterator[tuple[str, list[str], list[str]]]:
        """
        Recursively walk a directory tree, similar to `walk`.

        Yields one ``(dirpath, dirnames, filenames)`` tuple per directory, top-down, starting
        at ``dirname``. ``dirnames`` lists subdirectory names and ``filenames`` lists all other
        entries. Symbolic links to directories are classified as files (not descended into).

        As with `os.walk`, the caller may modify ``dirnames`` in place to prune the descent:
        only the names still listed when the generator resumes are walked.

        :param dirname: Root directory to walk.
        :yields: ``(dirpath, dirnames, filenames)`` tuples.
        """
        dirs: list[str] = []
        files: list[str] = []
        for fd in await self.listdir(dirname):
            if fd in (".", "..", ""):
                continue
            infos = await self.stat(posixpath.join(dirname, fd))
            if infos and infos.get("st_ifmt") == "S_IFDIR":
                dirs.append(fd)
            else:
                files.append(fd)

        yield dirname, dirs, files

        if dirs:
            for d in dirs:
                async for item in self.walk(posixpath.join(dirname, d)):
                    yield item

    @path_to_str()
    async def dirlist(self, root: str, depth: int = -1) -> AsyncIterator[str]:
        """
        Recursively yield paths under a directory up to a maximum depth.

        Yields ``root`` itself first, followed by the full path of every entry found while
        walking, pruning descent once a directory's depth (in path separators) reaches
        ``depth``.

        :param root: Root directory to list.
        :param depth: Maximum traversal depth; ``-1`` for unlimited, ``0`` to yield only ``root``.
        :yields: Full paths of files and directories.
        """
        async for folder, dirs, files in self.walk(root):
            if folder == root:
                yield folder
                if depth == 0:
                    break
            for entry in dirs + files:
                yield posixpath.join(folder, entry)
            if depth != -1:
                # Prune in place so `walk` never reads directories beyond the requested depth
                dirs[:] = [d for d in dirs if posixpath.join(folder, d).count(posixpath.sep) < depth]

    async def lock(self, handle: int, operation: int):
        """
        Apply or release an advisory ``flock``-style lock on an open file.

        :param handle: Handle returned by `fopen`.
        :param operation: Lock operation, one of ``AFC_LOCK_SH`` (shared), ``AFC_LOCK_EX``
            (exclusive) or ``AFC_LOCK_UN`` (unlock).
        :return: Raw response payload from the operation (typically empty).
        :raises AfcException: if the lock operation fails.
        """
        return await self._do_operation(AfcOpcode.FILE_LOCK, AfcLockRequest(handle=handle, op=operation).build())

    async def _dispatch_packet(self, operation: AfcOpcode, data: bytes, this_length: int = 0) -> int:
        """
        Send an AFC protocol packet to the device.

        :param operation: AFC operation code
        :param data: Packet payload data
        :param this_length: Override for the packet length field (0 for auto-calculation)
        :return: The packet_num assigned to this packet (used to match the response)
        """
        pkt_num = self.packet_num
        entire_length = AFC_HEADER_SIZE + len(data)
        header = AfcHeader(
            entire_length=entire_length,
            this_length=this_length or entire_length,
            packet_num=pkt_num,
            operation=operation,
        ).build()
        self.packet_num += 1
        await self.service.sendall(header + data)
        return pkt_num

    async def _send_and_wait(self, operation: AfcOpcode, data: bytes, this_length: int = 0):
        """
        Atomically send one AFC packet and wait for its response via the demux reader.

        The write lock ensures that ``packet_num`` assignment, Future registration, and
        the actual ``sendall`` are an uninterruptible unit so the background reader always
        finds a registered Future before the response arrives.

        If the background reader task has not been started yet (e.g. when the service is
        used without ``async with``), it is started lazily on the first call.

        :param operation: AFC operation code
        :param data: Packet payload
        :param this_length: Override for the ``this_length`` header field
        :return: Tuple of (AfcError, response_bytes)
        """
        # Ensure we're connected (lazy connect for non-async-with usage)
        await self.connect()
        # Start background reader lazily for callers that don't use async with.
        # Also restart it if it exited (e.g. connection error): the new task will
        # fail immediately on the broken socket and propagate the error to the caller
        # via _afc_pending, giving a clean exception rather than an infinite hang.
        if self._afc_reader_task is None or self._afc_reader_task.done():
            self._afc_reader_task = asyncio.create_task(self._afc_reader_loop(), name="afc-reader")
        loop = asyncio.get_event_loop()
        async with self._afc_write_lock:
            fut: asyncio.Future[Any] = loop.create_future()
            # Register *before* sending so the reader never misses the response
            pkt_num = self.packet_num
            self._afc_pending[pkt_num] = fut
            try:
                await self._dispatch_packet(operation, data, this_length)
            except BaseException:
                self._afc_pending.pop(pkt_num, None)
                raise
        return await fut

    async def _do_operation(self, opcode: AfcOpcode, data: bytes = b"", filename: Optional[str] = None) -> bytes:
        """
        Performs a low-level operation using the specified opcode and additional data.

        This method dispatches a packet with the given opcode and data, waits for a
        response via the background demux reader, and processes the result to determine
        success or failure. Multiple callers may call this concurrently on the same
        instance; each operation is matched to its response by ``packet_num``.

        :param opcode: The operation code specifying the type of operation to perform.
        :param data: The additional data to send along with the operation. Defaults to an empty byte string.
        :param filename: The filename associated with the operation, if applicable. Defaults to None.

        :returns: bytes: The data received as a response to the operation.

        :raises:
            AfcException: General exception raised if the operation fails with an
                          unspecified error status.
            AfcFileNotFoundError: Exception raised when the operation fails due to
                                  an object not being found (e.g., file or directory).
        """
        status, data = await self._send_and_wait(opcode, data)

        exception = AfcException
        if status != AfcError.SUCCESS:
            if status == AfcError.OBJECT_NOT_FOUND:
                exception = AfcFileNotFoundError

            opcode_name = opcode.name
            message = f"Opcode: {opcode_name} failed with status: {status}"
            if filename is not None:
                message += f" for file: {filename}"
            # AfcException mis-annotates `status` as str; it accepts AfcError/None at runtime
            raise exception(message, status, filename)

        return data
```

### aclose

```
aclose() -> None
```

Shut down the service: stop the reader task, fail all in-flight requests with `ConnectionTerminatedError`, and close the underlying connection.

Source code in `pymobiledevice3/services/afc.py`

```
async def aclose(self) -> None:
    """Shut down the service: stop the reader task, fail all in-flight requests with
    ``ConnectionTerminatedError``, and close the underlying connection."""
    if self._afc_reader_task is not None:
        self._afc_reader_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._afc_reader_task
        self._afc_reader_task = None
    for fut in self._afc_pending.values():
        if not fut.done():
            fut.set_exception(ConnectionTerminatedError())
    self._afc_pending.clear()
    await super().close()
```

### wait_terminated

```
wait_terminated() -> None
```

Block until the AFC connection terminates (e.g. the device disconnects).

Ensures the background reader is running so termination is detected even when no AFC operation is in flight. Returns immediately if the connection already died.

Source code in `pymobiledevice3/services/afc.py`

```
async def wait_terminated(self) -> None:
    """Block until the AFC connection terminates (e.g. the device disconnects).

    Ensures the background reader is running so termination is detected even when no
    AFC operation is in flight. Returns immediately if the connection already died.
    """
    if not self._afc_terminated.is_set():
        await self.connect()
        if self._afc_reader_task is None or self._afc_reader_task.done():
            self._afc_reader_task = asyncio.create_task(self._afc_reader_loop(), name="afc-reader")
    await self._afc_terminated.wait()
```

### pull

```
pull(relative_src: str, dst: str, match: Optional[Pattern[str]] = None, callback: Optional[Callable[..., Any]] = None, src_dir: str = '', ignore_errors: bool = False, progress_bar: bool = True) -> None
```

Pull (download) a file or directory from the device to the local machine.

The source is resolved through any symbolic link before transfer. A regular file is written to `dst`; if `dst` is an existing local directory, the file is placed inside it under the source's basename. Files larger than `MAXIMUM_READ_SIZE` (4 MB) are streamed in chunks. The local file's modification time is set to match the device's `st_mtime`. A directory source is copied recursively into a subdirectory of `dst` named after the source's basename.

Parameters:

| Name            | Type                           | Description                                                                                                                              | Default    |
| --------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `relative_src`  | `str`                          | Source path on the device, resolved relative to src_dir.                                                                                 | *required* |
| `dst`           | `str`                          | Destination path on the local machine.                                                                                                   | *required* |
| `match`         | `Optional[Pattern[str]]`       | Optional regex; only entries whose basename matches (via search) are copied. Non-matching files are skipped.                             | `None`     |
| `callback`      | `Optional[Callable[..., Any]]` | Optional callable invoked as callback(src, dst) after each regular file is copied. If it returns an awaitable, the awaitable is awaited. | `None`     |
| `src_dir`       | `str`                          | Base directory on the device against which relative_src is joined.                                                                       | `''`       |
| `ignore_errors` | `bool`                         | If True, per-entry errors during directory recursion are logged and skipped instead of propagated.                                       | `False`    |
| `progress_bar`  | `bool`                         | If True, display a progress bar while streaming large files.                                                                             | `True`     |

Source code in `pymobiledevice3/services/afc.py`

```
async def pull(
    self,
    relative_src: str,
    dst: str,
    match: Optional[Pattern[str]] = None,
    callback: Optional[Callable[..., Any]] = None,
    src_dir: str = "",
    ignore_errors: bool = False,
    progress_bar: bool = True,
) -> None:
    """
    Pull (download) a file or directory from the device to the local machine.

    The source is resolved through any symbolic link before transfer. A regular file is
    written to ``dst``; if ``dst`` is an existing local directory, the file is placed
    inside it under the source's basename. Files larger than ``MAXIMUM_READ_SIZE`` (4 MB)
    are streamed in chunks. The local file's modification time is set to match the
    device's ``st_mtime``. A directory source is copied recursively into a subdirectory
    of ``dst`` named after the source's basename.

    :param relative_src: Source path on the device, resolved relative to ``src_dir``.
    :param dst: Destination path on the local machine.
    :param match: Optional regex; only entries whose basename matches (via ``search``) are
        copied. Non-matching files are skipped.
    :param callback: Optional callable invoked as ``callback(src, dst)`` after each regular
        file is copied. If it returns an awaitable, the awaitable is awaited.
    :param src_dir: Base directory on the device against which ``relative_src`` is joined.
    :param ignore_errors: If True, per-entry errors during directory recursion are logged
        and skipped instead of propagated.
    :param progress_bar: If True, display a progress bar while streaming large files.
    """
    src = await self.resolve_path(posixpath.join(src_dir, relative_src))

    if not await self.isdir(src):
        # normal file
        if match is not None and not match.search(posixpath.basename(src)):
            return
        if os.path.isdir(dst):
            dst = os.path.join(dst, os.path.basename(relative_src))
        with open(dst, "wb") as f:
            src_size = (await self.stat(src))["st_size"]
            if src_size <= MAXIMUM_READ_SIZE:
                contents = await self.get_file_contents(src)
                f.write(contents)
            else:
                handle = await self.fopen(src)
                # Bytes-scaled bar (B/KB/MB with a live rate) rather than a chunk
                # counter — the rate readout doubles as a transfer benchmark.
                with ProgressBar(
                    total=src_size, desc=posixpath.basename(src), unit=BYTES_UNIT, disable=not progress_bar
                ) as pbar:
                    for offset in range(0, src_size, MAXIMUM_READ_SIZE):
                        to_read = min(MAXIMUM_READ_SIZE, src_size - offset)
                        chunk = await self.fread(handle, to_read)
                        f.write(chunk)
                        pbar.update(len(chunk))
                await self.fclose(handle)
        os.utime(dst, (os.stat(dst).st_atime, (await self.stat(src))["st_mtime"].timestamp()))
        if callback is not None:
            result = callback(src, dst)
            if inspect.isawaitable(result):
                await result
    else:
        # directory
        dst_path = pathlib.Path(dst) / os.path.basename(relative_src)
        dst_path.mkdir(parents=True, exist_ok=True)

        for filename in await self.listdir(src):
            src_filename = posixpath.join(src, filename)
            src_filename = await self.resolve_path(src_filename)

            if match is not None and not match.search(posixpath.basename(src_filename)):
                continue

            try:
                dst_filename = device_file_path(dst_path, filename)
                # A link is pulled under its target's name, which is just as device-supplied
                validate_device_filename(posixpath.basename(src_filename))
                if await self.isdir(src_filename):
                    dst_filename.mkdir(exist_ok=True)
                    await self.pull(
                        src_filename,
                        str(dst_path),
                        match=match,
                        callback=callback,
                        ignore_errors=ignore_errors,
                        progress_bar=progress_bar,
                    )
                    continue

                await self.pull(
                    src_filename,
                    str(dst_path),
                    match=match,
                    callback=callback,
                    ignore_errors=ignore_errors,
                    progress_bar=progress_bar,
                )

            except Exception as afc_exception:
                if not ignore_errors:
                    raise
                self.logger.warning(f"(Ignoring) Error: {afc_exception} occurred during the copy of {src_filename}")
```

### exists

```
exists(filename: str)
```

Check whether a path exists on the device.

Implemented by attempting `stat`; a missing path is reported as False and any other AFC error propagates.

Parameters:

| Name       | Type  | Description    | Default    |
| ---------- | ----- | -------------- | ---------- |
| `filename` | `str` | Path to check. | *required* |

Returns:

| Type | Description                                         |
| ---- | --------------------------------------------------- |
|      | True if the path exists, False if it was not found. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def exists(self, filename: str):
    """
    Check whether a path exists on the device.

    Implemented by attempting `stat`; a missing path is reported as False and any
    other AFC error propagates.

    :param filename: Path to check.
    :return: True if the path exists, False if it was not found.
    """
    try:
        await self.stat(filename)
    except AfcFileNotFoundError:
        return False
    return True
```

### wait_exists

```
wait_exists(filename: str)
```

Block until a path exists on the device.

Polls `exists` every 0.1 seconds until the path appears. Does not return until the path exists.

Parameters:

| Name       | Type  | Description       | Default    |
| ---------- | ----- | ----------------- | ---------- |
| `filename` | `str` | Path to wait for. | *required* |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def wait_exists(self, filename: str):
    """
    Block until a path exists on the device.

    Polls `exists` every 0.1 seconds until the path appears. Does not return
    until the path exists.

    :param filename: Path to wait for.
    """
    while not await self.exists(filename):
        await asyncio.sleep(0.1)
```

### push

```
push(local_path: str, remote_path: str, callback: Optional[Callable[[str, str], Any]] = None, progress_bar: bool = True)
```

Push (upload) a file or directory from the local machine to the device.

A regular file is written to `remote_path` (or, if `remote_path` is an existing remote directory, into it under the file's basename). Files larger than `MAXIMUM_READ_SIZE` (4 MB) are streamed in chunks with a byte-scaled progress bar. A local directory is copied recursively into `remote_path`/, creating remote directories as needed.

Parameters:

| Name           | Type                                  | Description                                                                                      | Default    |
| -------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------ | ---------- |
| `local_path`   | `str`                                 | Source path on the local machine.                                                                | *required* |
| `remote_path`  | `str`                                 | Destination path on the device.                                                                  | *required* |
| `callback`     | `Optional[Callable[[str, str], Any]]` | Optional callable invoked as callback(local_path, remote_path) before each entry is transferred. | `None`     |
| `progress_bar` | `bool`                                | If True, display a progress bar while streaming large files.                                     | `True`     |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def push(
    self,
    local_path: str,
    remote_path: str,
    callback: Optional[Callable[[str, str], Any]] = None,
    progress_bar: bool = True,
):
    """
    Push (upload) a file or directory from the local machine to the device.

    A regular file is written to ``remote_path`` (or, if ``remote_path`` is an existing
    remote directory, into it under the file's basename). Files larger than
    ``MAXIMUM_READ_SIZE`` (4 MB) are streamed in chunks with a byte-scaled progress bar.
    A local directory is copied recursively into ``remote_path``/<basename of local_path>,
    creating remote directories as needed.

    :param local_path: Source path on the local machine.
    :param remote_path: Destination path on the device.
    :param callback: Optional callable invoked as ``callback(local_path, remote_path)``
        before each entry is transferred.
    :param progress_bar: If True, display a progress bar while streaming large files.
    """
    if os.path.isdir(local_path):
        remote_path = posixpath.join(remote_path, os.path.basename(local_path))
    await self._push_internal(local_path, remote_path, callback, progress_bar=progress_bar)
```

### rm_single

```
rm_single(filename: str, force: bool = False) -> bool
```

Remove a single file or empty directory on the device.

Issues a single `REMOVE_PATH` operation; it does not recurse into a non-empty directory.

Parameters:

| Name       | Type   | Description                                                           | Default    |
| ---------- | ------ | --------------------------------------------------------------------- | ---------- |
| `filename` | `str`  | Path to the file or directory to remove.                              | *required* |
| `force`    | `bool` | If True, swallow an AfcException and return False instead of raising. | `False`    |

Returns:

| Type   | Description                                                     |
| ------ | --------------------------------------------------------------- |
| `bool` | True on success; False if the removal failed and force is True. |

Raises:

| Type           | Description                              |
| -------------- | ---------------------------------------- |
| `AfcException` | if the removal fails and force is False. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def rm_single(self, filename: str, force: bool = False) -> bool:
    """
    Remove a single file or empty directory on the device.

    Issues a single ``REMOVE_PATH`` operation; it does not recurse into a non-empty
    directory.

    :param filename: Path to the file or directory to remove.
    :param force: If True, swallow an `AfcException` and return False instead of raising.
    :return: True on success; False if the removal failed and ``force`` is True.
    :raises AfcException: if the removal fails and ``force`` is False.
    """
    try:
        await self._do_operation(AfcOpcode.REMOVE_PATH, CSTRING.build(filename), filename)
    except AfcException:
        if force:
            return False
        raise
    return True
```

### rm

```
rm(filename: str, match: Optional[Pattern[str]] = None, force: bool = False) -> list[str]
```

Recursively remove a file or directory tree on the device.

Without `match`, the device removes the whole tree in a single `REMOVE_PATH_AND_CONTENTS` operation; if that fails, the tree is walked instead.

For a directory, every entry is removed depth-first and the directory itself is removed last.

With `match`, the same entries `pull` would copy are removed: at every level, entries whose basename does not match (via `search`) are skipped, matching directories are descended into with the same pattern, and matching files are removed. Directories (including `filename` itself) are never removed in this mode.

A path removed by someone else while the tree is walked counts as deleted.

Parameters:

| Name       | Type                     | Description                                                                                              | Default    |
| ---------- | ------------------------ | -------------------------------------------------------------------------------------------------------- | ---------- |
| `filename` | `str`                    | Path to the file or directory to remove.                                                                 | *required* |
| `match`    | `Optional[Pattern[str]]` | Optional regex over entry basenames, applied as pull applies it. None removes the whole tree.            | `None`     |
| `force`    | `bool`                   | If True, suppress the final AfcException and instead return the list of paths that could not be deleted. | `False`    |

Returns:

| Type        | Description                                                      |
| ----------- | ---------------------------------------------------------------- |
| `list[str]` | List of paths that could not be deleted (empty on full success). |

Raises:

| Type             | Description                                                                |
| ---------------- | -------------------------------------------------------------------------- |
| `AfcException`   | if filename does not exist and force is False.                             |
| `AfcDeleteError` | if any path could not be deleted and force is False; its failures say why. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def rm(self, filename: str, match: Optional[Pattern[str]] = None, force: bool = False) -> list[str]:
    """
    Recursively remove a file or directory tree on the device.

    Without ``match``, the device removes the whole tree in a single ``REMOVE_PATH_AND_CONTENTS``
    operation; if that fails, the tree is walked instead.

    For a directory, every entry is removed depth-first and the directory itself is removed
    last.

    With ``match``, the same entries `pull` would copy are removed: at every level, entries whose
    basename does not match (via ``search``) are skipped, matching directories are descended into
    with the same pattern, and matching files are removed. Directories (including ``filename``
    itself) are never removed in this mode.

    A path removed by someone else while the tree is walked counts as deleted.

    :param filename: Path to the file or directory to remove.
    :param match: Optional regex over entry basenames, applied as `pull` applies it. None removes
        the whole tree.
    :param force: If True, suppress the final `AfcException` and instead return the
        list of paths that could not be deleted.
    :return: List of paths that could not be deleted (empty on full success).
    :raises AfcException: if ``filename`` does not exist and ``force`` is False.
    :raises AfcDeleteError: if any path could not be deleted and ``force`` is False; its ``failures`` say why.
    """
    if match is None:
        # let the device delete the whole tree in one round-trip; on any failure fall back to
        # walking it, which also reports exactly which entries could not be deleted
        with contextlib.suppress(AfcException):
            await self._do_operation(AfcOpcode.REMOVE_PATH_AND_CONTENTS, CSTRING.build(filename), filename)
            return []

    if not await self.exists(filename):
        # a missing path is an error (a dangling link, which cannot be stat'ed, is still removed here)
        if not await self.rm_single(filename, force=force):
            return [filename]
        return []

    failures = await self._rm_tree(filename) if match is None else await self._rm_matching(filename, match)
    if failures and not force:
        raise AfcDeleteError(
            "Failed to delete: "
            + ", ".join(f"{path} ({getattr(status, 'name', status)})" for path, status in failures.items()),
            dict(failures),
        )
    return list(failures)
```

### get_device_info

```
get_device_info()
```

Query device file-system information.

Issues a `GET_DEVINFO` operation and decodes the null-terminated key/value list into a dictionary (e.g. model, total/free bytes, block size).

Returns:

| Type | Description                                                           |
| ---- | --------------------------------------------------------------------- |
|      | Dictionary of device file-system attributes (all values are strings). |

Source code in `pymobiledevice3/services/afc.py`

```
async def get_device_info(self):
    """
    Query device file-system information.

    Issues a ``GET_DEVINFO`` operation and decodes the null-terminated key/value list into
    a dictionary (e.g. model, total/free bytes, block size).

    :return: Dictionary of device file-system attributes (all values are strings).
    """
    return list_to_dict(await self._do_operation(AfcOpcode.GET_DEVINFO))
```

### listdir

```
listdir(filename: str) -> list[str]
```

List the entries of a directory on the device.

Parameters:

| Name       | Type  | Description            | Default    |
| ---------- | ----- | ---------------------- | ---------- |
| `filename` | `str` | Path to the directory. | *required* |

Returns:

| Type        | Description                                       |
| ----------- | ------------------------------------------------- |
| `list[str]` | Entry names in the directory, excluding . and ... |

Raises:

| Type                   | Description                                         |
| ---------------------- | --------------------------------------------------- |
| `AfcFileNotFoundError` | if the path does not exist.                         |
| `AfcException`         | if the path is not a directory or cannot be listed. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def listdir(self, filename: str) -> list[str]:
    """
    List the entries of a directory on the device.

    :param filename: Path to the directory.
    :return: Entry names in the directory, excluding ``.`` and ``..``.
    :raises AfcFileNotFoundError: if the path does not exist.
    :raises AfcException: if the path is not a directory or cannot be listed.
    """
    data = await self._do_operation(AfcOpcode.READ_DIR, CSTRING.build(filename), filename)
    return AfcReadDirResponse.parse(data).filenames[2:]  # skip the . and ..
```

### makedirs

```
makedirs(filename: str)
```

Create a directory on the device.

Issues a `MAKE_DIR` operation, creating any missing parent directories.

Parameters:

| Name       | Type  | Description                      | Default    |
| ---------- | ----- | -------------------------------- | ---------- |
| `filename` | `str` | Path of the directory to create. | *required* |

Returns:

| Type | Description                                                |
| ---- | ---------------------------------------------------------- |
|      | Raw response payload from the operation (typically empty). |

Raises:

| Type           | Description                            |
| -------------- | -------------------------------------- |
| `AfcException` | if the directory could not be created. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def makedirs(self, filename: str):
    """
    Create a directory on the device.

    Issues a ``MAKE_DIR`` operation, creating any missing parent directories.

    :param filename: Path of the directory to create.
    :return: Raw response payload from the operation (typically empty).
    :raises AfcException: if the directory could not be created.
    """
    return await self._do_operation(AfcOpcode.MAKE_DIR, CSTRING.build(filename), filename)
```

### isdir

```
isdir(filename: str) -> bool
```

Check whether a path is a directory.

Stats the path and tests whether its `st_ifmt` is `S_IFDIR`.

Parameters:

| Name       | Type  | Description    | Default    |
| ---------- | ----- | -------------- | ---------- |
| `filename` | `str` | Path to check. | *required* |

Returns:

| Type   | Description                                       |
| ------ | ------------------------------------------------- |
| `bool` | True if the path is a directory, False otherwise. |

Raises:

| Type                   | Description                 |
| ---------------------- | --------------------------- |
| `AfcFileNotFoundError` | if the path does not exist. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def isdir(self, filename: str) -> bool:
    """
    Check whether a path is a directory.

    Stats the path and tests whether its ``st_ifmt`` is ``S_IFDIR``.

    :param filename: Path to check.
    :return: True if the path is a directory, False otherwise.
    :raises AfcFileNotFoundError: if the path does not exist.
    """
    stat = await self.stat(filename)
    return stat.get("st_ifmt") == "S_IFDIR"
```

### stat

```
stat(filename: str) -> dict[str, Any]
```

Get file or directory metadata.

Issues a `GET_FILE_INFO` operation and returns the decoded attribute dictionary. Numeric fields (`st_size`, `st_blocks`, `st_nlink`) are converted to ints; `st_mtime` and `st_birthtime` are converted from device nanosecond timestamps to `datetime`. A `st_ifmt` entry (e.g. `S_IFREG`, `S_IFDIR`, `S_IFLNK`) describes the file type, and symbolic links also carry a `LinkTarget`.

Parameters:

| Name       | Type  | Description                    | Default    |
| ---------- | ----- | ------------------------------ | ---------- |
| `filename` | `str` | Path to the file or directory. | *required* |

Returns:

| Type             | Description                    |
| ---------------- | ------------------------------ |
| `dict[str, Any]` | Dictionary of file attributes. |

Raises:

| Type                   | Description                                  |
| ---------------------- | -------------------------------------------- |
| `AfcFileNotFoundError` | if the path does not exist (AFC READ_ERROR). |
| `AfcException`         | for any other failure status.                |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def stat(self, filename: str) -> dict[str, Any]:
    """
    Get file or directory metadata.

    Issues a ``GET_FILE_INFO`` operation and returns the decoded attribute dictionary.
    Numeric fields (``st_size``, ``st_blocks``, ``st_nlink``) are converted to ints;
    ``st_mtime`` and ``st_birthtime`` are converted from device nanosecond timestamps to
    `datetime`. A ``st_ifmt`` entry (e.g. ``S_IFREG``, ``S_IFDIR``,
    ``S_IFLNK``) describes the file type, and symbolic links also carry a ``LinkTarget``.

    :param filename: Path to the file or directory.
    :return: Dictionary of file attributes.
    :raises AfcFileNotFoundError: if the path does not exist (AFC ``READ_ERROR``).
    :raises AfcException: for any other failure status.
    """
    try:
        stat: dict[str, Any] = list_to_dict(
            await self._do_operation(AfcOpcode.GET_FILE_INFO, CSTRING.build(filename), filename)
        )
    except AfcException as e:
        if e.status != AfcError.READ_ERROR:
            raise
        raise AfcFileNotFoundError(f"No such file on the device: {filename}", e.status, filename) from e

    stat["st_size"] = int(stat["st_size"])
    stat["st_blocks"] = int(stat["st_blocks"])
    stat["st_mtime"] = int(stat["st_mtime"])
    stat["st_birthtime"] = int(stat["st_birthtime"])
    stat["st_nlink"] = int(stat["st_nlink"])
    stat["st_mtime"] = datetime.fromtimestamp(stat["st_mtime"] / (10**9))
    stat["st_birthtime"] = datetime.fromtimestamp(stat["st_birthtime"] / (10**9))
    return stat
```

### os_stat

```
os_stat(path: str)
```

Get file statistics as an `stat`-style result.

Wraps `stat`, mapping the AFC `st_ifmt` to a numeric mode and packing the attributes into a `StatResult` namedtuple. `st_ino` is synthesized from the normalized path, `st_uid`/`st_gid`/`st_dev` are reported as 0 and `st_blksize` as 4096 (AFC does not expose these). `st_atime` mirrors `st_mtime`.

Parameters:

| Name   | Type  | Description                    | Default    |
| ------ | ----- | ------------------------------ | ---------- |
| `path` | `str` | Path to the file or directory. | *required* |

Returns:

| Type | Description              |
| ---- | ------------------------ |
|      | A StatResult namedtuple. |

Raises:

| Type                   | Description                 |
| ---------------------- | --------------------------- |
| `AfcFileNotFoundError` | if the path does not exist. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def os_stat(self, path: str):
    """
    Get file statistics as an `stat`-style result.

    Wraps `stat`, mapping the AFC ``st_ifmt`` to a numeric mode and packing the
    attributes into a `StatResult` namedtuple. ``st_ino`` is synthesized from the
    normalized path, ``st_uid``/``st_gid``/``st_dev`` are reported as 0 and ``st_blksize``
    as 4096 (AFC does not expose these). ``st_atime`` mirrors ``st_mtime``.

    :param path: Path to the file or directory.
    :return: A `StatResult` namedtuple.
    :raises AfcFileNotFoundError: if the path does not exist.
    """
    stat = await self.stat(path)
    mode = 0
    for s_mode in ["S_IFDIR", "S_IFCHR", "S_IFBLK", "S_IFREG", "S_IFIFO", "S_IFLNK", "S_IFSOCK"]:
        if stat["st_ifmt"] == s_mode:
            mode = getattr(stat_module, s_mode)
    return StatResult(
        mode,
        hash(posixpath.normpath(path)),
        0,
        stat["st_nlink"],
        0,
        0,
        stat["st_size"],
        stat["st_mtime"].timestamp(),
        stat["st_mtime"].timestamp(),
        stat["st_birthtime"].timestamp(),
        stat["st_blocks"],
        4096,
        stat["st_birthtime"].timestamp(),
    )
```

### link

```
link(target: str, source: str, type_: AfcLinkType = AfcLinkType.SYMLINK)
```

Create a symbolic or hard link on the device.

Parameters:

| Name     | Type          | Description                                              | Default    |
| -------- | ------------- | -------------------------------------------------------- | ---------- |
| `target` | `str`         | Path the link points to.                                 | *required* |
| `source` | `str`         | Path at which the link is created.                       | *required* |
| `type_`  | `AfcLinkType` | AfcLinkType to create (SYMLINK by default, or HARDLINK). | `SYMLINK`  |

Returns:

| Type | Description                                                |
| ---- | ---------------------------------------------------------- |
|      | Raw response payload from the operation (typically empty). |

Raises:

| Type           | Description                       |
| -------------- | --------------------------------- |
| `AfcException` | if the link could not be created. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def link(self, target: str, source: str, type_: AfcLinkType = AfcLinkType.SYMLINK):
    """
    Create a symbolic or hard link on the device.

    :param target: Path the link points to.
    :param source: Path at which the link is created.
    :param type_: `AfcLinkType` to create (``SYMLINK`` by default, or ``HARDLINK``).
    :return: Raw response payload from the operation (typically empty).
    :raises AfcException: if the link could not be created.
    """
    return await self._do_operation(
        AfcOpcode.MAKE_LINK,
        AfcMakeLinkRequest(type=type_, target=target, source=source).build(),
    )
```

### truncate

```
truncate(filename: str, size: int) -> None
```

Truncate or extend a file to `size` bytes (`truncate(2)`).

Parameters:

| Name       | Type  | Description                 | Default    |
| ---------- | ----- | --------------------------- | ---------- |
| `filename` | `str` | Path to the file.           | *required* |
| `size`     | `int` | The new file size in bytes. | *required* |

Raises:

| Type                   | Description                 |
| ---------------------- | --------------------------- |
| `AfcFileNotFoundError` | if the file does not exist. |
| `AfcException`         | if the operation fails.     |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def truncate(self, filename: str, size: int) -> None:
    """
    Truncate or extend a file to ``size`` bytes (``truncate(2)``).

    :param filename: Path to the file.
    :param size: The new file size in bytes.
    :raises AfcFileNotFoundError: if the file does not exist.
    :raises AfcException: if the operation fails.
    """
    await self._do_operation(AfcOpcode.TRUNCATE, AfcTruncateRequest(size=size, filename=filename).build(), filename)
```

### set_file_time

```
set_file_time(filename: str, mtime: datetime) -> None
```

Set the modification time of a file or directory.

The device stores the time with microsecond resolution, and moves `st_birthtime` back to `mtime` when `mtime` is the earlier of the two.

Parameters:

| Name       | Type       | Description                                                               | Default    |
| ---------- | ---------- | ------------------------------------------------------------------------- | ---------- |
| `filename` | `str`      | Path to the file or directory.                                            | *required* |
| `mtime`    | `datetime` | The new modification time (naive values are local time, as stat returns). | *required* |

Raises:

| Type                   | Description                 |
| ---------------------- | --------------------------- |
| `AfcFileNotFoundError` | if the path does not exist. |
| `AfcException`         | if the operation fails.     |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def set_file_time(self, filename: str, mtime: datetime) -> None:
    """
    Set the modification time of a file or directory.

    The device stores the time with microsecond resolution, and moves ``st_birthtime`` back
    to ``mtime`` when ``mtime`` is the earlier of the two.

    :param filename: Path to the file or directory.
    :param mtime: The new modification time (naive values are local time, as `stat` returns).
    :raises AfcFileNotFoundError: if the path does not exist.
    :raises AfcException: if the operation fails.
    """
    mtime_ns = round(mtime.timestamp() * 1_000_000) * 1000
    await self._do_operation(
        AfcOpcode.SET_FILE_TIME, AfcSetFileTimeRequest(mtime=mtime_ns, filename=filename).build(), filename
    )
```

### get_file_hash

```
get_file_hash(filename: str) -> bytes
```

Get the SHA-1 digest of a file, computed on the device.

Parameters:

| Name       | Type  | Description       | Default    |
| ---------- | ----- | ----------------- | ---------- |
| `filename` | `str` | Path to the file. | *required* |

Returns:

| Type    | Description               |
| ------- | ------------------------- |
| `bytes` | The 20-byte SHA-1 digest. |

Raises:

| Type                   | Description                                                        |
| ---------------------- | ------------------------------------------------------------------ |
| `AfcFileNotFoundError` | if the file does not exist.                                        |
| `AfcException`         | if the path is a directory (OBJECT_IS_DIR) or the operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def get_file_hash(self, filename: str) -> bytes:
    """
    Get the SHA-1 digest of a file, computed on the device.

    :param filename: Path to the file.
    :return: The 20-byte SHA-1 digest.
    :raises AfcFileNotFoundError: if the file does not exist.
    :raises AfcException: if the path is a directory (``OBJECT_IS_DIR``) or the operation fails.
    """
    try:
        return await self._do_operation(AfcOpcode.GET_FILE_HASH, CSTRING.build(filename), filename)
    except AfcException as e:
        # The device rejects hashing an empty file with INVALID_ARG
        if e.status != AfcError.INVALID_ARG or (await self.stat(filename))["st_size"] != 0:
            raise
        return hashlib.sha1(b"").digest()
```

### get_file_hash_range

```
get_file_hash_range(filename: str, start: int, length: int) -> bytes
```

Get the SHA-1 digest of `length` bytes of a file starting at `start`, computed on the device.

Parameters:

| Name       | Type  | Description                                                  | Default    |
| ---------- | ----- | ------------------------------------------------------------ | ---------- |
| `filename` | `str` | Path to the file.                                            | *required* |
| `start`    | `int` | Offset of the first byte to hash.                            | *required* |
| `length`   | `int` | Number of bytes to hash; the range must lie within the file. | *required* |

Returns:

| Type    | Description               |
| ------- | ------------------------- |
| `bytes` | The 20-byte SHA-1 digest. |

Raises:

| Type                   | Description                                                         |
| ---------------------- | ------------------------------------------------------------------- |
| `AfcFileNotFoundError` | if the file does not exist.                                         |
| `AfcException`         | if the range exceeds the file (INVALID_ARG) or the operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def get_file_hash_range(self, filename: str, start: int, length: int) -> bytes:
    """
    Get the SHA-1 digest of ``length`` bytes of a file starting at ``start``, computed on the device.

    :param filename: Path to the file.
    :param start: Offset of the first byte to hash.
    :param length: Number of bytes to hash; the range must lie within the file.
    :return: The 20-byte SHA-1 digest.
    :raises AfcFileNotFoundError: if the file does not exist.
    :raises AfcException: if the range exceeds the file (``INVALID_ARG``) or the operation fails.
    """
    return await self._do_operation(
        AfcOpcode.GET_FILE_HASH_RANGE,
        AfcFileHashRangeRequest(start=start, length=length, filename=filename).build(),
        filename,
    )
```

### get_size_of_path_contents

```
get_size_of_path_contents(filename: str) -> dict[str, int]
```

Get the total size of the regular files under a directory, computed on the device.

Parameters:

| Name       | Type  | Description                                          | Default    |
| ---------- | ----- | ---------------------------------------------------- | ---------- |
| `filename` | `str` | Path to the directory (a regular file reports zero). | *required* |

Returns:

| Type             | Description                                            |
| ---------------- | ------------------------------------------------------ |
| `dict[str, int]` | {"st_size": <bytes>, "st_blocks": \<512-byte blocks>}. |

Raises:

| Type                   | Description                 |
| ---------------------- | --------------------------- |
| `AfcFileNotFoundError` | if the path does not exist. |
| `AfcException`         | if the operation fails.     |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def get_size_of_path_contents(self, filename: str) -> dict[str, int]:
    """
    Get the total size of the regular files under a directory, computed on the device.

    :param filename: Path to the directory (a regular file reports zero).
    :return: ``{"st_size": <bytes>, "st_blocks": <512-byte blocks>}``.
    :raises AfcFileNotFoundError: if the path does not exist.
    :raises AfcException: if the operation fails.
    """
    data = await self._do_operation(
        AfcOpcode.GET_SIZE_OF_PATH_CONTENTS,
        AfcSizeOfPathContentsRequest(flags=0, filename=filename).build(),
        filename,
    )
    return {k: int(v) for k, v in list_to_dict(data).items()}
```

### get_connection_info

```
get_connection_info() -> dict[str, str]
```

Query information about the AFC connection (e.g. the server `Version`).

Returns:

| Type             | Description                                                   |
| ---------------- | ------------------------------------------------------------- |
| `dict[str, str]` | Dictionary of connection attributes (all values are strings). |

Source code in `pymobiledevice3/services/afc.py`

```
async def get_connection_info(self) -> dict[str, str]:
    """
    Query information about the AFC connection (e.g. the server ``Version``).

    :return: Dictionary of connection attributes (all values are strings).
    """
    return list_to_dict(await self._do_operation(AfcOpcode.GET_CON_INFO))
```

### fopen

```
fopen(filename: str, mode: str = 'r') -> int
```

Open a file on the device and return its handle.

Parameters:

| Name       | Type  | Description                                                                                             | Default    |
| ---------- | ----- | ------------------------------------------------------------------------------------------------------- | ---------- |
| `filename` | `str` | Path to the file.                                                                                       | *required* |
| `mode`     | `str` | Textual open mode; one of 'r', 'r+', 'w', 'w+', 'a', 'a+' (mapped to the corresponding AFC fopen mode). | `'r'`      |

Returns:

| Type  | Description                                                |
| ----- | ---------------------------------------------------------- |
| `int` | Integer handle usable with fread, fwrite, lock and fclose. |

Raises:

| Type            | Description                                        |
| --------------- | -------------------------------------------------- |
| `ArgumentError` | if mode is not one of the supported textual modes. |
| `AfcException`  | if the file could not be opened.                   |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def fopen(self, filename: str, mode: str = "r") -> int:
    """
    Open a file on the device and return its handle.

    :param filename: Path to the file.
    :param mode: Textual open mode; one of ``'r'``, ``'r+'``, ``'w'``, ``'w+'``, ``'a'``,
        ``'a+'`` (mapped to the corresponding AFC fopen mode).
    :return: Integer handle usable with `fread`, `fwrite`, `lock` and
        `fclose`.
    :raises ArgumentError: if ``mode`` is not one of the supported textual modes.
    :raises AfcException: if the file could not be opened.
    """
    if mode not in AFC_FOPEN_TEXTUAL_MODES:
        raise ArgumentError(f"Invalid file mode {mode!r}; use one of: {', '.join(AFC_FOPEN_TEXTUAL_MODES)}")

    data = await self._do_operation(
        AfcOpcode.FILE_OPEN,
        AfcFopenRequest(mode=AFC_FOPEN_TEXTUAL_MODES[mode], filename=filename).build(),
    )
    return AfcFopenResponse.parse(data).handle
```

### fclose

```
fclose(handle: int)
```

Close an open file handle.

Parameters:

| Name     | Type  | Description               | Default    |
| -------- | ----- | ------------------------- | ---------- |
| `handle` | `int` | Handle returned by fopen. | *required* |

Returns:

| Type | Description                                                |
| ---- | ---------------------------------------------------------- |
|      | Raw response payload from the operation (typically empty). |

Raises:

| Type           | Description                   |
| -------------- | ----------------------------- |
| `AfcException` | if the close operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
async def fclose(self, handle: int):
    """
    Close an open file handle.

    :param handle: Handle returned by `fopen`.
    :return: Raw response payload from the operation (typically empty).
    :raises AfcException: if the close operation fails.
    """
    return await self._do_operation(AfcOpcode.FILE_CLOSE, AfcFcloseRequest(handle=handle).build())
```

### rename

```
rename(source: str, target: str) -> None
```

Rename or move a file or directory on the device.

Parameters:

| Name     | Type  | Description                            | Default    |
| -------- | ----- | -------------------------------------- | ---------- |
| `source` | `str` | Current path of the file or directory. | *required* |
| `target` | `str` | New path for the file or directory.    | *required* |

Raises:

| Type                   | Description                                         |
| ---------------------- | --------------------------------------------------- |
| `AfcFileNotFoundError` | if the operation fails and source no longer exists. |
| `AfcException`         | if the operation fails while source still exists.   |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def rename(self, source: str, target: str) -> None:
    """
    Rename or move a file or directory on the device.

    :param source: Current path of the file or directory.
    :param target: New path for the file or directory.
    :raises AfcFileNotFoundError: if the operation fails and ``source`` no longer exists.
    :raises AfcException: if the operation fails while ``source`` still exists.
    """
    try:
        await self._do_operation(
            AfcOpcode.RENAME_PATH,
            CSTRING.build(source) + CSTRING.build(target),
        )
    except AfcException as e:
        if await self.exists(source):
            raise
        raise AfcFileNotFoundError(
            f"Failed to rename {source} to {target}: {source} no longer exists.", e.status, source
        ) from e
```

### fread

```
fread(handle: int, sz: int) -> bytes
```

Read data from an open file handle.

Automatically handles large reads by splitting into multiple operations. Each chunk send+receive is performed atomically via the demux reader so concurrent callers on the same AfcService instance are safe.

Parameters:

| Name     | Type  | Description                                                                                               | Default    |
| -------- | ----- | --------------------------------------------------------------------------------------------------------- | ---------- |
| `handle` | `int` | Handle returned by fopen.                                                                                 | *required* |
| `sz`     | `int` | Number of bytes to read. Reads larger than MAXIMUM_READ_SIZE (4 MB) are split into successive operations. | *required* |

Returns:

| Type    | Description     |
| ------- | --------------- |
| `bytes` | The bytes read. |

Raises:

| Type           | Description                                         |
| -------------- | --------------------------------------------------- |
| `AfcException` | if any read operation returns a non-success status. |

Source code in `pymobiledevice3/services/afc.py`

```
async def fread(self, handle: int, sz: int) -> bytes:
    """
    Read data from an open file handle.

    Automatically handles large reads by splitting into multiple operations.
    Each chunk send+receive is performed atomically via the demux reader so
    concurrent callers on the same AfcService instance are safe.

    :param handle: Handle returned by `fopen`.
    :param sz: Number of bytes to read. Reads larger than ``MAXIMUM_READ_SIZE`` (4 MB) are
        split into successive operations.
    :return: The bytes read.
    :raises AfcException: if any read operation returns a non-success status.
    """
    data = b""
    while sz > 0:
        to_read = MAXIMUM_READ_SIZE if sz > MAXIMUM_READ_SIZE else sz
        status, chunk = await self._send_and_wait(
            AfcOpcode.READ, AfcFreadRequest(handle=handle, size=to_read).build()
        )
        if status != AfcError.SUCCESS:
            raise AfcException("Failed to read from the file.", status)
        sz -= to_read
        data += chunk
    return data
```

### fseek

```
fseek(handle: int, offset: int, whence: int = os.SEEK_SET) -> None
```

Seek within an open file handle.

Parameters:

| Name     | Type  | Description                                               | Default    |
| -------- | ----- | --------------------------------------------------------- | ---------- |
| `handle` | `int` | Handle returned by fopen.                                 | *required* |
| `offset` | `int` | Byte offset relative to whence.                           | *required* |
| `whence` | `int` | One of os.SEEK_SET (0), os.SEEK_CUR (1), os.SEEK_END (2). | `SEEK_SET` |

Raises:

| Type           | Description                  |
| -------------- | ---------------------------- |
| `AfcException` | if the seek operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
async def fseek(self, handle: int, offset: int, whence: int = os.SEEK_SET) -> None:
    """
    Seek within an open file handle.

    :param handle: Handle returned by `fopen`.
    :param offset: Byte offset relative to ``whence``.
    :param whence: One of ``os.SEEK_SET`` (0), ``os.SEEK_CUR`` (1), ``os.SEEK_END`` (2).
    :raises AfcException: if the seek operation fails.
    """
    await self._do_operation(
        AfcOpcode.FILE_SEEK,
        AfcFileSeekRequest(handle=handle, whence=whence, offset=offset).build(),
    )
```

### ftell

```
ftell(handle: int) -> int
```

Get the current position of an open file handle.

Parameters:

| Name     | Type  | Description               | Default    |
| -------- | ----- | ------------------------- | ---------- |
| `handle` | `int` | Handle returned by fopen. | *required* |

Returns:

| Type  | Description              |
| ----- | ------------------------ |
| `int` | The current byte offset. |

Raises:

| Type           | Description                  |
| -------------- | ---------------------------- |
| `AfcException` | if the tell operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
async def ftell(self, handle: int) -> int:
    """
    Get the current position of an open file handle.

    :param handle: Handle returned by `fopen`.
    :return: The current byte offset.
    :raises AfcException: if the tell operation fails.
    """
    return U64_LE.unpack(await self._do_operation(AfcOpcode.FILE_TELL, U64_LE.pack(handle)))[0]
```

### ftruncate

```
ftruncate(handle: int, size: int) -> None
```

Truncate or extend an open file to `size` bytes (`ftruncate(2)`).

The handle's position is left unchanged.

Parameters:

| Name     | Type  | Description                                    | Default    |
| -------- | ----- | ---------------------------------------------- | ---------- |
| `handle` | `int` | Handle returned by fopen with a writable mode. | *required* |
| `size`   | `int` | The new file size in bytes.                    | *required* |

Raises:

| Type           | Description             |
| -------------- | ----------------------- |
| `AfcException` | if the operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
async def ftruncate(self, handle: int, size: int) -> None:
    """
    Truncate or extend an open file to ``size`` bytes (``ftruncate(2)``).

    The handle's position is left unchanged.

    :param handle: Handle returned by `fopen` with a writable mode.
    :param size: The new file size in bytes.
    :raises AfcException: if the operation fails.
    """
    await self._do_operation(AfcOpcode.FILE_SET_SIZE, AfcFileSetSizeRequest(handle=handle, size=size).build())
```

### pread

```
pread(handle: int, size: int, offset: int) -> bytes
```

Read from an open file handle at an absolute offset (`pread(2)`).

The handle's position is left unchanged. Reads past the end of the file are short.

Parameters:

| Name     | Type  | Description                                                                                        | Default    |
| -------- | ----- | -------------------------------------------------------------------------------------------------- | ---------- |
| `handle` | `int` | Handle returned by fopen.                                                                          | *required* |
| `size`   | `int` | Number of bytes to read. Reads larger than MAXIMUM_READ_SIZE are split into successive operations. | *required* |
| `offset` | `int` | Byte offset to read from.                                                                          | *required* |

Returns:

| Type    | Description     |
| ------- | --------------- |
| `bytes` | The bytes read. |

Raises:

| Type           | Description                |
| -------------- | -------------------------- |
| `AfcException` | if a read operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
async def pread(self, handle: int, size: int, offset: int) -> bytes:
    """
    Read from an open file handle at an absolute offset (``pread(2)``).

    The handle's position is left unchanged. Reads past the end of the file are short.

    :param handle: Handle returned by `fopen`.
    :param size: Number of bytes to read. Reads larger than ``MAXIMUM_READ_SIZE`` are split
        into successive operations.
    :param offset: Byte offset to read from.
    :return: The bytes read.
    :raises AfcException: if a read operation fails.
    """
    data = b""
    while size > 0:
        to_read = min(size, MAXIMUM_READ_SIZE)
        chunk = await self._do_operation(
            AfcOpcode.FILE_READ_OFFSET,
            AfcFreadOffsetRequest(handle=handle, size=to_read, offset=offset).build(),
        )
        data += chunk
        if len(chunk) < to_read:
            break
        size -= to_read
        offset += to_read
    return data
```

### pwrite

```
pwrite(handle: int, data: bytes, offset: int, chunk_size: int = MAXIMUM_WRITE_SIZE) -> None
```

Write to an open file handle at an absolute offset (`pwrite(2)`).

The handle's position is left unchanged; writing past the end extends the file.

Parameters:

| Name         | Type    | Description                                    | Default              |
| ------------ | ------- | ---------------------------------------------- | -------------------- |
| `handle`     | `int`   | Handle returned by fopen with a writable mode. | *required*           |
| `data`       | `bytes` | Bytes to write.                                | *required*           |
| `offset`     | `int`   | Byte offset to write at.                       | *required*           |
| `chunk_size` | `int`   | Maximum bytes per FILE_WRITE_OFFSET operation. | `MAXIMUM_WRITE_SIZE` |

Raises:

| Type           | Description                 |
| -------------- | --------------------------- |
| `AfcException` | if a write operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
async def pwrite(self, handle: int, data: bytes, offset: int, chunk_size: int = MAXIMUM_WRITE_SIZE) -> None:
    """
    Write to an open file handle at an absolute offset (``pwrite(2)``).

    The handle's position is left unchanged; writing past the end extends the file.

    :param handle: Handle returned by `fopen` with a writable mode.
    :param data: Bytes to write.
    :param offset: Byte offset to write at.
    :param chunk_size: Maximum bytes per ``FILE_WRITE_OFFSET`` operation.
    :raises AfcException: if a write operation fails.
    """
    for start in range(0, len(data), chunk_size):
        header = AfcFwriteOffsetHeader(handle=handle, offset=offset + start).build()
        status, _ = await self._send_and_wait(
            AfcOpcode.FILE_WRITE_OFFSET,
            header + data[start : start + chunk_size],
            this_length=AFC_HEADER_SIZE + len(header),
        )
        if status != AfcError.SUCCESS:
            raise AfcException("Failed to write to the file.", status)
```

### fwrite

```
fwrite(handle: int, data: bytes, chunk_size: int = MAXIMUM_WRITE_SIZE) -> None
```

Write data to an open file handle.

Automatically handles large writes by splitting into multiple operations. Each chunk send+receive is performed atomically via the demux reader so concurrent callers on the same AfcService instance are safe.

Parameters:

| Name         | Type    | Description                                                     | Default              |
| ------------ | ------- | --------------------------------------------------------------- | -------------------- |
| `handle`     | `int`   | Handle returned by fopen.                                       | *required*           |
| `data`       | `bytes` | Bytes to write.                                                 | *required*           |
| `chunk_size` | `int`   | Maximum bytes per WRITE operation (default MAXIMUM_WRITE_SIZE). | `MAXIMUM_WRITE_SIZE` |

Raises:

| Type           | Description                                          |
| -------------- | ---------------------------------------------------- |
| `AfcException` | if any write operation returns a non-success status. |

Source code in `pymobiledevice3/services/afc.py`

```
async def fwrite(self, handle: int, data: bytes, chunk_size: int = MAXIMUM_WRITE_SIZE) -> None:
    """
    Write data to an open file handle.

    Automatically handles large writes by splitting into multiple operations.
    Each chunk send+receive is performed atomically via the demux reader so
    concurrent callers on the same AfcService instance are safe.

    :param handle: Handle returned by `fopen`.
    :param data: Bytes to write.
    :param chunk_size: Maximum bytes per ``WRITE`` operation (default ``MAXIMUM_WRITE_SIZE``).
    :raises AfcException: if any write operation returns a non-success status.
    """
    file_handle = U64_LE.pack(handle)
    chunks_count = len(data) // chunk_size
    for i in range(chunks_count):
        chunk = data[i * chunk_size : (i + 1) * chunk_size]
        status, _ = await self._send_and_wait(AfcOpcode.WRITE, file_handle + chunk, this_length=48)
        if status != AfcError.SUCCESS:
            raise AfcException("Failed to write to the file.", status)

    if len(data) % chunk_size:
        chunk = data[chunks_count * chunk_size :]
        status, _ = await self._send_and_wait(AfcOpcode.WRITE, file_handle + chunk, this_length=48)
        if status != AfcError.SUCCESS:
            raise AfcException("Failed to write to the file.", status)
```

### resolve_path

```
resolve_path(filename: str) -> str
```

Resolve a symbolic link to its target path.

Stats the path; if it is a symbolic link, returns its `LinkTarget` (joined against the link's parent directory when the target is relative). Non-links are returned unchanged. Only a single level of link is resolved.

Parameters:

| Name       | Type  | Description      | Default    |
| ---------- | ----- | ---------------- | ---------- |
| `filename` | `str` | Path to resolve. | *required* |

Returns:

| Type  | Description                                                          |
| ----- | -------------------------------------------------------------------- |
| `str` | The link target, or filename unchanged if it is not a symbolic link. |

Raises:

| Type                   | Description                 |
| ---------------------- | --------------------------- |
| `AfcFileNotFoundError` | if the path does not exist. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def resolve_path(self, filename: str) -> str:
    """
    Resolve a symbolic link to its target path.

    Stats the path; if it is a symbolic link, returns its ``LinkTarget`` (joined against
    the link's parent directory when the target is relative). Non-links are returned
    unchanged. Only a single level of link is resolved.

    :param filename: Path to resolve.
    :return: The link target, or ``filename`` unchanged if it is not a symbolic link.
    :raises AfcFileNotFoundError: if the path does not exist.
    """
    info = await self.stat(filename)
    if info["st_ifmt"] == "S_IFLNK":
        target = info["LinkTarget"]
        filename = posixpath.join(posixpath.dirname(filename), target) if not target.startswith("/") else target
    return filename
```

### get_file_contents

```
get_file_contents(filename: str) -> bytes
```

Read and return the entire contents of a file.

Resolves any symbolic link, verifies the target is a regular file, then opens it, reads `st_size` bytes and closes the handle.

Parameters:

| Name       | Type  | Description       | Default    |
| ---------- | ----- | ----------------- | ---------- |
| `filename` | `str` | Path to the file. | *required* |

Returns:

| Type    | Description                 |
| ------- | --------------------------- |
| `bytes` | The file contents as bytes. |

Raises:

| Type                   | Description                                                         |
| ---------------------- | ------------------------------------------------------------------- |
| `AfcException`         | if the path is not a regular file (S_IFREG) or could not be opened. |
| `AfcFileNotFoundError` | if the path does not exist.                                         |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def get_file_contents(self, filename: str) -> bytes:
    """
    Read and return the entire contents of a file.

    Resolves any symbolic link, verifies the target is a regular file, then opens it,
    reads ``st_size`` bytes and closes the handle.

    :param filename: Path to the file.
    :return: The file contents as bytes.
    :raises AfcException: if the path is not a regular file (``S_IFREG``) or could not be opened.
    :raises AfcFileNotFoundError: if the path does not exist.
    """
    filename = await self.resolve_path(filename)
    info = await self.stat(filename)

    if info["st_ifmt"] != "S_IFREG":
        raise AfcException(f"Not a regular file: {filename}", AfcError.INVALID_ARG, filename)

    h = await self.fopen(filename)
    if not h:
        raise AfcException(f"Failed to open {filename}", AfcError.INTERNAL_ERROR, filename)
    d = await self.fread(h, int(info["st_size"]))
    await self.fclose(h)
    return d
```

### set_file_contents

```
set_file_contents(filename: str, data: bytes, progress: Optional[ProgressBar] = None) -> None
```

Write data to a file, creating or truncating it.

Opens the file in `'w'` mode (create/truncate), writes `data` and closes the handle.

Parameters:

| Name       | Type                    | Description                                  | Default    |
| ---------- | ----------------------- | -------------------------------------------- | ---------- |
| `filename` | `str`                   | Path to the file.                            | *required* |
| `data`     | `bytes`                 | Bytes to write.                              | *required* |
| `progress` | `Optional[ProgressBar]` | Optional bar advanced as chunks are written. | `None`     |

Raises:

| Type           | Description                           |
| -------------- | ------------------------------------- |
| `AfcException` | if the open or write operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def set_file_contents(self, filename: str, data: bytes, progress: Optional[ProgressBar] = None) -> None:
    """
    Write data to a file, creating or truncating it.

    Opens the file in ``'w'`` mode (create/truncate), writes ``data`` and closes the handle.

    :param filename: Path to the file.
    :param data: Bytes to write.
    :param progress: Optional bar advanced as chunks are written.
    :raises AfcException: if the open or write operation fails.
    """
    h = await self.fopen(filename, "w")
    try:
        for offset in range(0, len(data), MAXIMUM_READ_SIZE):
            chunk = data[offset : offset + MAXIMUM_READ_SIZE]
            await self.fwrite(h, chunk)
            if progress is not None:
                progress.update(len(chunk))
    finally:
        await self.fclose(h)
```

### walk

```
walk(dirname: str) -> AsyncIterator[tuple[str, list[str], list[str]]]
```

Recursively walk a directory tree, similar to `walk`.

Yields one `(dirpath, dirnames, filenames)` tuple per directory, top-down, starting at `dirname`. `dirnames` lists subdirectory names and `filenames` lists all other entries. Symbolic links to directories are classified as files (not descended into).

As with `os.walk`, the caller may modify `dirnames` in place to prune the descent: only the names still listed when the generator resumes are walked.

:yields: `(dirpath, dirnames, filenames)` tuples.

Parameters:

| Name      | Type  | Description             | Default    |
| --------- | ----- | ----------------------- | ---------- |
| `dirname` | `str` | Root directory to walk. | *required* |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def walk(self, dirname: str) -> AsyncIterator[tuple[str, list[str], list[str]]]:
    """
    Recursively walk a directory tree, similar to `walk`.

    Yields one ``(dirpath, dirnames, filenames)`` tuple per directory, top-down, starting
    at ``dirname``. ``dirnames`` lists subdirectory names and ``filenames`` lists all other
    entries. Symbolic links to directories are classified as files (not descended into).

    As with `os.walk`, the caller may modify ``dirnames`` in place to prune the descent:
    only the names still listed when the generator resumes are walked.

    :param dirname: Root directory to walk.
    :yields: ``(dirpath, dirnames, filenames)`` tuples.
    """
    dirs: list[str] = []
    files: list[str] = []
    for fd in await self.listdir(dirname):
        if fd in (".", "..", ""):
            continue
        infos = await self.stat(posixpath.join(dirname, fd))
        if infos and infos.get("st_ifmt") == "S_IFDIR":
            dirs.append(fd)
        else:
            files.append(fd)

    yield dirname, dirs, files

    if dirs:
        for d in dirs:
            async for item in self.walk(posixpath.join(dirname, d)):
                yield item
```

### dirlist

```
dirlist(root: str, depth: int = -1) -> AsyncIterator[str]
```

Recursively yield paths under a directory up to a maximum depth.

Yields `root` itself first, followed by the full path of every entry found while walking, pruning descent once a directory's depth (in path separators) reaches `depth`.

:yields: Full paths of files and directories.

Parameters:

| Name    | Type  | Description                                                      | Default    |
| ------- | ----- | ---------------------------------------------------------------- | ---------- |
| `root`  | `str` | Root directory to list.                                          | *required* |
| `depth` | `int` | Maximum traversal depth; -1 for unlimited, 0 to yield only root. | `-1`       |

Source code in `pymobiledevice3/services/afc.py`

```
@path_to_str()
async def dirlist(self, root: str, depth: int = -1) -> AsyncIterator[str]:
    """
    Recursively yield paths under a directory up to a maximum depth.

    Yields ``root`` itself first, followed by the full path of every entry found while
    walking, pruning descent once a directory's depth (in path separators) reaches
    ``depth``.

    :param root: Root directory to list.
    :param depth: Maximum traversal depth; ``-1`` for unlimited, ``0`` to yield only ``root``.
    :yields: Full paths of files and directories.
    """
    async for folder, dirs, files in self.walk(root):
        if folder == root:
            yield folder
            if depth == 0:
                break
        for entry in dirs + files:
            yield posixpath.join(folder, entry)
        if depth != -1:
            # Prune in place so `walk` never reads directories beyond the requested depth
            dirs[:] = [d for d in dirs if posixpath.join(folder, d).count(posixpath.sep) < depth]
```

### lock

```
lock(handle: int, operation: int)
```

Apply or release an advisory `flock`-style lock on an open file.

Parameters:

| Name        | Type  | Description                                                                                   | Default    |
| ----------- | ----- | --------------------------------------------------------------------------------------------- | ---------- |
| `handle`    | `int` | Handle returned by fopen.                                                                     | *required* |
| `operation` | `int` | Lock operation, one of AFC_LOCK_SH (shared), AFC_LOCK_EX (exclusive) or AFC_LOCK_UN (unlock). | *required* |

Returns:

| Type | Description                                                |
| ---- | ---------------------------------------------------------- |
|      | Raw response payload from the operation (typically empty). |

Raises:

| Type           | Description                  |
| -------------- | ---------------------------- |
| `AfcException` | if the lock operation fails. |

Source code in `pymobiledevice3/services/afc.py`

```
async def lock(self, handle: int, operation: int):
    """
    Apply or release an advisory ``flock``-style lock on an open file.

    :param handle: Handle returned by `fopen`.
    :param operation: Lock operation, one of ``AFC_LOCK_SH`` (shared), ``AFC_LOCK_EX``
        (exclusive) or ``AFC_LOCK_UN`` (unlock).
    :return: Raw response payload from the operation (typically empty).
    :raises AfcException: if the lock operation fails.
    """
    return await self._do_operation(AfcOpcode.FILE_LOCK, AfcLockRequest(handle=handle, op=operation).build())
```

## pymobiledevice3.services.diagnostics.DiagnosticsService

Bases: `LockdownService`

Client for the device's `diagnostics_relay` lockdown service.

Exposes the diagnostics relay over a plist request/response channel, allowing callers to:

- Query MobileGestalt and IORegistry keys.
- Read diagnostic information reports (e.g. battery, Wi-Fi, generic diagnostics).
- Restart, shut down or put the device to sleep.

Source code in `pymobiledevice3/services/diagnostics.py`

```
class DiagnosticsService(LockdownService):
    """
    Client for the device's ``diagnostics_relay`` lockdown service.

    Exposes the diagnostics relay over a plist request/response channel, allowing callers to:

    * Query MobileGestalt and IORegistry keys.
    * Read diagnostic information reports (e.g. battery, Wi-Fi, generic diagnostics).
    * Restart, shut down or put the device to sleep.
    """

    RSD_SERVICE_NAME = "com.apple.mobile.diagnostics_relay.shim.remote"
    SERVICE_NAME = "com.apple.mobile.diagnostics_relay"
    OLD_SERVICE_NAME = "com.apple.iosdiagnostics.relay"

    async def _send_recv(self, request: dict[str, Any]) -> dict[str, Any]:
        return await self.service.send_recv_plist(request)

    async def mobilegestalt(self, keys: Optional[list[str]] = None) -> dict[str, Any]:
        """
        Query MobileGestalt values from the device.

        Sends a ``MobileGestalt`` request and returns the resolved key/value mapping (with the internal ``Status``
        entry stripped out).

        :param keys: MobileGestalt keys to query. If ``None`` or empty, the full built-in `MobileGestaltKeys`
            list is queried.
        :returns: Mapping of each requested MobileGestalt key to its value.
        :raises DeprecationError: If MobileGestalt is reported as deprecated (iOS >= 17.4).
        :raises PyMobileDevice3Exception: If the request or the MobileGestalt query did not complete successfully.
        """
        if keys is None or len(keys) == 0:
            keys = MobileGestaltKeys
        response = await self._send_recv({"Request": "MobileGestalt", "MobileGestaltKeys": keys})

        if response["Diagnostics"]["MobileGestalt"]["Status"] == "MobileGestaltDeprecated":
            err_msg = (
                f"Failed to query MobileGestalt: it is deprecated on iOS 17.4 and later. The device replied: {response}"
            )
            raise DeprecationError(err_msg)

        if (response["Status"] != "Success") or (response["Diagnostics"]["MobileGestalt"]["Status"] != "Success"):
            raise PyMobileDevice3Exception(f"The device failed to query MobileGestalt: {response}")

        response["Diagnostics"]["MobileGestalt"].pop("Status")

        return response["Diagnostics"]["MobileGestalt"]

    async def action(self, action: str) -> Optional[dict[str, Any]]:
        """
        Send a single diagnostics relay request and return its ``Diagnostics`` payload.

        This is the low-level primitive used by the action/info helpers below. The given string is sent verbatim as
        the request's ``Request`` field.

        :param action: Request name to send (e.g. ``Restart``, ``Shutdown``, ``Sleep``, ``All``).
        :returns: The response's ``Diagnostics`` payload, or ``None`` when the response carries no such payload.
        :raises PyMobileDevice3Exception: If the response status is not ``Success``.
        """
        response = await self._send_recv({"Request": action})
        if response["Status"] != "Success":
            raise PyMobileDevice3Exception(f"The device failed the {action} diagnostics request: {response}")
        return response.get("Diagnostics")

    async def restart(self):
        """
        Restart the device by sending the ``Restart`` request.

        The device goes down once this service's connection is closed, not when the request is
        acknowledged: close the service (or leave its ``async with`` block) before waiting for the
        device to come back.

        :raises PyMobileDevice3Exception: If the request did not complete successfully.
        """
        await self.action("Restart")

    async def shutdown(self):
        """
        Shut the device down by sending the ``Shutdown`` request.

        :raises PyMobileDevice3Exception: If the request did not complete successfully.
        """
        await self.action("Shutdown")

    async def sleep(self):
        """
        Put the device to sleep by sending the ``Sleep`` request.

        :raises PyMobileDevice3Exception: If the request did not complete successfully.
        """
        await self.action("Sleep")

    async def info(self, diag_type: str = "All") -> Optional[dict[str, Any]]:
        """
        Fetch a diagnostics information report from the device.

        :param diag_type: Diagnostics report type to request; sent as the ``Request`` field. Defaults to ``All``.
        :returns: The ``Diagnostics`` payload of the response.
        :raises PyMobileDevice3Exception: If the request did not complete successfully.
        """
        return await self.action(diag_type)

    async def ioregistry(self, plane: Optional[str] = None, name: Optional[str] = None, ioclass: Optional[str] = None):
        """
        Query the device's IORegistry.

        Sends an ``IORegistry`` request, optionally narrowed by plane, entry name and/or entry class.

        :param plane: IORegistry plane to traverse, sent as ``CurrentPlane`` (e.g. ``IODeviceTree``,
            ``IOService``). Omitted when falsy.
        :param name: Name of the registry entry to look up, sent as ``EntryName``. Omitted when falsy.
        :param ioclass: Class of the registry entry to look up, sent as ``EntryClass``. Omitted when falsy.
        :returns: The ``IORegistry`` portion of the response's ``Diagnostics`` payload, or ``None`` when the response
            carries no such payload.
        :raises PyMobileDevice3Exception: If the response status is not ``Success``.
        """
        d: dict[str, Any] = {}

        if plane:
            d["CurrentPlane"] = plane

        if name:
            d["EntryName"] = name

        if ioclass:
            d["EntryClass"] = ioclass

        d["Request"] = "IORegistry"

        response = await self._send_recv(d)
        if response.get("Status") != "Success":
            raise PyMobileDevice3Exception(f"The device failed the IORegistry query: {response}")

        dd = response.get("Diagnostics")
        if dd:
            return dd.get("IORegistry")
        return None

    async def get_battery(self) -> Optional[dict[str, Any]]:
        """
        Fetch battery/power-source information from the IORegistry.

        Convenience wrapper that queries the IORegistry entry of class ``IOPMPowerSource``.

        :returns: The IORegistry data for the power-source entry, or ``None`` if it is absent.
        :raises PyMobileDevice3Exception: If the underlying IORegistry request did not complete successfully.
        """
        return await self.ioregistry(ioclass="IOPMPowerSource")

    async def get_wifi(self) -> Optional[dict[str, Any]]:
        """
        Fetch the Wi-Fi interface information from the IORegistry.

        First attempts the entry named ``AppleBCMWLANSkywalkInterface``; if that yields no result, falls back to the
        entry of class ``IO80211Interface``.

        :returns: The IORegistry data for the Wi-Fi interface, or ``None`` if neither lookup matches.
        :raises PyMobileDevice3Exception: If an underlying IORegistry request did not complete successfully.
        """
        result = await self.ioregistry(name="AppleBCMWLANSkywalkInterface")
        if result:
            return result
        return await self.ioregistry(ioclass="IO80211Interface")
```

### mobilegestalt

```
mobilegestalt(keys: Optional[list[str]] = None) -> dict[str, Any]
```

Query MobileGestalt values from the device.

Sends a `MobileGestalt` request and returns the resolved key/value mapping (with the internal `Status` entry stripped out).

Parameters:

| Name   | Type                  | Description                                                                                         | Default |
| ------ | --------------------- | --------------------------------------------------------------------------------------------------- | ------- |
| `keys` | `Optional[list[str]]` | MobileGestalt keys to query. If None or empty, the full built-in MobileGestaltKeys list is queried. | `None`  |

Returns:

| Type             | Description                                               |
| ---------------- | --------------------------------------------------------- |
| `dict[str, Any]` | Mapping of each requested MobileGestalt key to its value. |

Raises:

| Type                       | Description                                                              |
| -------------------------- | ------------------------------------------------------------------------ |
| `DeprecationError`         | If MobileGestalt is reported as deprecated (iOS >= 17.4).                |
| `PyMobileDevice3Exception` | If the request or the MobileGestalt query did not complete successfully. |

Source code in `pymobiledevice3/services/diagnostics.py`

```
async def mobilegestalt(self, keys: Optional[list[str]] = None) -> dict[str, Any]:
    """
    Query MobileGestalt values from the device.

    Sends a ``MobileGestalt`` request and returns the resolved key/value mapping (with the internal ``Status``
    entry stripped out).

    :param keys: MobileGestalt keys to query. If ``None`` or empty, the full built-in `MobileGestaltKeys`
        list is queried.
    :returns: Mapping of each requested MobileGestalt key to its value.
    :raises DeprecationError: If MobileGestalt is reported as deprecated (iOS >= 17.4).
    :raises PyMobileDevice3Exception: If the request or the MobileGestalt query did not complete successfully.
    """
    if keys is None or len(keys) == 0:
        keys = MobileGestaltKeys
    response = await self._send_recv({"Request": "MobileGestalt", "MobileGestaltKeys": keys})

    if response["Diagnostics"]["MobileGestalt"]["Status"] == "MobileGestaltDeprecated":
        err_msg = (
            f"Failed to query MobileGestalt: it is deprecated on iOS 17.4 and later. The device replied: {response}"
        )
        raise DeprecationError(err_msg)

    if (response["Status"] != "Success") or (response["Diagnostics"]["MobileGestalt"]["Status"] != "Success"):
        raise PyMobileDevice3Exception(f"The device failed to query MobileGestalt: {response}")

    response["Diagnostics"]["MobileGestalt"].pop("Status")

    return response["Diagnostics"]["MobileGestalt"]
```

### action

```
action(action: str) -> Optional[dict[str, Any]]
```

Send a single diagnostics relay request and return its `Diagnostics` payload.

This is the low-level primitive used by the action/info helpers below. The given string is sent verbatim as the request's `Request` field.

Parameters:

| Name     | Type  | Description                                                | Default    |
| -------- | ----- | ---------------------------------------------------------- | ---------- |
| `action` | `str` | Request name to send (e.g. Restart, Shutdown, Sleep, All). | *required* |

Returns:

| Type                       | Description                                                                            |
| -------------------------- | -------------------------------------------------------------------------------------- |
| `Optional[dict[str, Any]]` | The response's Diagnostics payload, or None when the response carries no such payload. |

Raises:

| Type                       | Description                            |
| -------------------------- | -------------------------------------- |
| `PyMobileDevice3Exception` | If the response status is not Success. |

Source code in `pymobiledevice3/services/diagnostics.py`

```
async def action(self, action: str) -> Optional[dict[str, Any]]:
    """
    Send a single diagnostics relay request and return its ``Diagnostics`` payload.

    This is the low-level primitive used by the action/info helpers below. The given string is sent verbatim as
    the request's ``Request`` field.

    :param action: Request name to send (e.g. ``Restart``, ``Shutdown``, ``Sleep``, ``All``).
    :returns: The response's ``Diagnostics`` payload, or ``None`` when the response carries no such payload.
    :raises PyMobileDevice3Exception: If the response status is not ``Success``.
    """
    response = await self._send_recv({"Request": action})
    if response["Status"] != "Success":
        raise PyMobileDevice3Exception(f"The device failed the {action} diagnostics request: {response}")
    return response.get("Diagnostics")
```

### restart

```
restart()
```

Restart the device by sending the `Restart` request.

The device goes down once this service's connection is closed, not when the request is acknowledged: close the service (or leave its `async with` block) before waiting for the device to come back.

Raises:

| Type                       | Description                                   |
| -------------------------- | --------------------------------------------- |
| `PyMobileDevice3Exception` | If the request did not complete successfully. |

Source code in `pymobiledevice3/services/diagnostics.py`

```
async def restart(self):
    """
    Restart the device by sending the ``Restart`` request.

    The device goes down once this service's connection is closed, not when the request is
    acknowledged: close the service (or leave its ``async with`` block) before waiting for the
    device to come back.

    :raises PyMobileDevice3Exception: If the request did not complete successfully.
    """
    await self.action("Restart")
```

### shutdown

```
shutdown()
```

Shut the device down by sending the `Shutdown` request.

Raises:

| Type                       | Description                                   |
| -------------------------- | --------------------------------------------- |
| `PyMobileDevice3Exception` | If the request did not complete successfully. |

Source code in `pymobiledevice3/services/diagnostics.py`

```
async def shutdown(self):
    """
    Shut the device down by sending the ``Shutdown`` request.

    :raises PyMobileDevice3Exception: If the request did not complete successfully.
    """
    await self.action("Shutdown")
```

### sleep

```
sleep()
```

Put the device to sleep by sending the `Sleep` request.

Raises:

| Type                       | Description                                   |
| -------------------------- | --------------------------------------------- |
| `PyMobileDevice3Exception` | If the request did not complete successfully. |

Source code in `pymobiledevice3/services/diagnostics.py`

```
async def sleep(self):
    """
    Put the device to sleep by sending the ``Sleep`` request.

    :raises PyMobileDevice3Exception: If the request did not complete successfully.
    """
    await self.action("Sleep")
```

### info

```
info(diag_type: str = 'All') -> Optional[dict[str, Any]]
```

Fetch a diagnostics information report from the device.

Parameters:

| Name        | Type  | Description                                                                     | Default |
| ----------- | ----- | ------------------------------------------------------------------------------- | ------- |
| `diag_type` | `str` | Diagnostics report type to request; sent as the Request field. Defaults to All. | `'All'` |

Returns:

| Type                       | Description                              |
| -------------------------- | ---------------------------------------- |
| `Optional[dict[str, Any]]` | The Diagnostics payload of the response. |

Raises:

| Type                       | Description                                   |
| -------------------------- | --------------------------------------------- |
| `PyMobileDevice3Exception` | If the request did not complete successfully. |

Source code in `pymobiledevice3/services/diagnostics.py`

```
async def info(self, diag_type: str = "All") -> Optional[dict[str, Any]]:
    """
    Fetch a diagnostics information report from the device.

    :param diag_type: Diagnostics report type to request; sent as the ``Request`` field. Defaults to ``All``.
    :returns: The ``Diagnostics`` payload of the response.
    :raises PyMobileDevice3Exception: If the request did not complete successfully.
    """
    return await self.action(diag_type)
```

### ioregistry

```
ioregistry(plane: Optional[str] = None, name: Optional[str] = None, ioclass: Optional[str] = None)
```

Query the device's IORegistry.

Sends an `IORegistry` request, optionally narrowed by plane, entry name and/or entry class.

Parameters:

| Name      | Type            | Description                                                                                            | Default |
| --------- | --------------- | ------------------------------------------------------------------------------------------------------ | ------- |
| `plane`   | `Optional[str]` | IORegistry plane to traverse, sent as CurrentPlane (e.g. IODeviceTree, IOService). Omitted when falsy. | `None`  |
| `name`    | `Optional[str]` | Name of the registry entry to look up, sent as EntryName. Omitted when falsy.                          | `None`  |
| `ioclass` | `Optional[str]` | Class of the registry entry to look up, sent as EntryClass. Omitted when falsy.                        | `None`  |

Returns:

| Type | Description                                                                                                      |
| ---- | ---------------------------------------------------------------------------------------------------------------- |
|      | The IORegistry portion of the response's Diagnostics payload, or None when the response carries no such payload. |

Raises:

| Type                       | Description                            |
| -------------------------- | -------------------------------------- |
| `PyMobileDevice3Exception` | If the response status is not Success. |

Source code in `pymobiledevice3/services/diagnostics.py`

```
async def ioregistry(self, plane: Optional[str] = None, name: Optional[str] = None, ioclass: Optional[str] = None):
    """
    Query the device's IORegistry.

    Sends an ``IORegistry`` request, optionally narrowed by plane, entry name and/or entry class.

    :param plane: IORegistry plane to traverse, sent as ``CurrentPlane`` (e.g. ``IODeviceTree``,
        ``IOService``). Omitted when falsy.
    :param name: Name of the registry entry to look up, sent as ``EntryName``. Omitted when falsy.
    :param ioclass: Class of the registry entry to look up, sent as ``EntryClass``. Omitted when falsy.
    :returns: The ``IORegistry`` portion of the response's ``Diagnostics`` payload, or ``None`` when the response
        carries no such payload.
    :raises PyMobileDevice3Exception: If the response status is not ``Success``.
    """
    d: dict[str, Any] = {}

    if plane:
        d["CurrentPlane"] = plane

    if name:
        d["EntryName"] = name

    if ioclass:
        d["EntryClass"] = ioclass

    d["Request"] = "IORegistry"

    response = await self._send_recv(d)
    if response.get("Status") != "Success":
        raise PyMobileDevice3Exception(f"The device failed the IORegistry query: {response}")

    dd = response.get("Diagnostics")
    if dd:
        return dd.get("IORegistry")
    return None
```

### get_battery

```
get_battery() -> Optional[dict[str, Any]]
```

Fetch battery/power-source information from the IORegistry.

Convenience wrapper that queries the IORegistry entry of class `IOPMPowerSource`.

Returns:

| Type                       | Description                                                              |
| -------------------------- | ------------------------------------------------------------------------ |
| `Optional[dict[str, Any]]` | The IORegistry data for the power-source entry, or None if it is absent. |

Raises:

| Type                       | Description                                                         |
| -------------------------- | ------------------------------------------------------------------- |
| `PyMobileDevice3Exception` | If the underlying IORegistry request did not complete successfully. |

Source code in `pymobiledevice3/services/diagnostics.py`

```
async def get_battery(self) -> Optional[dict[str, Any]]:
    """
    Fetch battery/power-source information from the IORegistry.

    Convenience wrapper that queries the IORegistry entry of class ``IOPMPowerSource``.

    :returns: The IORegistry data for the power-source entry, or ``None`` if it is absent.
    :raises PyMobileDevice3Exception: If the underlying IORegistry request did not complete successfully.
    """
    return await self.ioregistry(ioclass="IOPMPowerSource")
```

### get_wifi

```
get_wifi() -> Optional[dict[str, Any]]
```

Fetch the Wi-Fi interface information from the IORegistry.

First attempts the entry named `AppleBCMWLANSkywalkInterface`; if that yields no result, falls back to the entry of class `IO80211Interface`.

Returns:

| Type                       | Description                                                                     |
| -------------------------- | ------------------------------------------------------------------------------- |
| `Optional[dict[str, Any]]` | The IORegistry data for the Wi-Fi interface, or None if neither lookup matches. |

Raises:

| Type                       | Description                                                        |
| -------------------------- | ------------------------------------------------------------------ |
| `PyMobileDevice3Exception` | If an underlying IORegistry request did not complete successfully. |

Source code in `pymobiledevice3/services/diagnostics.py`

```
async def get_wifi(self) -> Optional[dict[str, Any]]:
    """
    Fetch the Wi-Fi interface information from the IORegistry.

    First attempts the entry named ``AppleBCMWLANSkywalkInterface``; if that yields no result, falls back to the
    entry of class ``IO80211Interface``.

    :returns: The IORegistry data for the Wi-Fi interface, or ``None`` if neither lookup matches.
    :raises PyMobileDevice3Exception: If an underlying IORegistry request did not complete successfully.
    """
    result = await self.ioregistry(name="AppleBCMWLANSkywalkInterface")
    if result:
        return result
    return await self.ioregistry(ioclass="IO80211Interface")
```

## pymobiledevice3.services.springboard.SpringBoardServicesService

Bases: `LockdownService`

Client for the `com.apple.springboardservices` lockdown service.

Exposes SpringBoard operations such as reading and writing the home screen icon layout, fetching application icon and wallpaper images, and querying the interface orientation.

Source code in `pymobiledevice3/services/springboard.py`

```
class SpringBoardServicesService(LockdownService):
    """
    Client for the ``com.apple.springboardservices`` lockdown service.

    Exposes SpringBoard operations such as reading and writing the home screen icon layout,
    fetching application icon and wallpaper images, and querying the interface orientation.
    """

    RSD_SERVICE_NAME = "com.apple.springboardservices.shim.remote"
    SERVICE_NAME = "com.apple.springboardservices"

    async def get_icon_state(self, format_version: str = "2") -> list[Any]:
        """
        Retrieve the current home screen icon layout.

        :param format_version: Icon state format version sent to SpringBoard as ``formatVersion``.
            When falsy, the key is omitted from the request.
        :returns: Nested list describing the home screen pages, folders and icons.
        """
        cmd = {"command": "getIconState"}
        if format_version:
            cmd["formatVersion"] = format_version
        return cast(list[Any], await self.service.send_recv_plist(cmd))

    async def set_icon_state(self, newstate: Optional[list[Any]] = None) -> None:
        """
        Apply a new home screen icon layout.

        :param newstate: Icon layout in the same structure returned by `get_icon_state`.
            When ``None``, an empty layout is sent.
        """
        state: Union[list[Any], dict[str, Any]] = {} if newstate is None else newstate
        await self.service.send_recv_prefixed(build_plist({"command": "setIconState", "iconState": state}))

    async def get_icon_pngdata(self, bundle_id: str) -> bytes:
        """
        Retrieve the home screen icon image of an installed application.

        :param bundle_id: Bundle identifier of the application whose icon is requested.
        :returns: PNG-encoded icon image bytes, or ``None`` if no ``pngData`` is returned.
        """
        return cast(
            bytes,
            (await self.service.send_recv_plist({"command": "getIconPNGData", "bundleId": bundle_id})).get("pngData"),
        )

    async def get_interface_orientation(self) -> InterfaceOrientation:
        """
        Query the current SpringBoard interface orientation.

        :returns: The current orientation as an `InterfaceOrientation` enum value.
        """
        res = await self.service.send_recv_plist({"command": "getInterfaceOrientation"})
        return InterfaceOrientation(res.get("interfaceOrientation"))

    async def get_wallpaper_pngdata(self) -> bytes:
        """
        Retrieve the current home screen wallpaper image.

        The device answers from the wallpaper's stored image. Poster-based wallpapers (the kind iOS creates
        since the customizable Lock Screen) have none, and the device then drops the connection instead of
        replying. `get_wallpaper_preview_image` renders the current home screen wallpaper either way.

        :returns: PNG-encoded wallpaper image bytes.
        :raises WallpaperImageUnavailableError: if the current wallpaper has no stored image.
        """
        try:
            response = await self.service.send_recv_plist({"command": "getHomeScreenWallpaperPNGData"})
        except ConnectionTerminatedError:
            # The connection is unusable now; drop it so the next request starts a fresh one.
            await self.close()
            raise WallpaperImageUnavailableError(
                "The home screen wallpaper has no stored image (a poster-based wallpaper); "
                "use get_wallpaper_preview_image('homescreen') instead"
            ) from None
        return cast(bytes, response["pngData"])

    async def get_homescreen_icon_metrics(self) -> dict[str, float]:
        """
        Retrieve the home screen icon layout metrics.

        :returns: Mapping of metric names to their numeric values, as reported by SpringBoard.
        """
        return cast(dict[str, float], await self.service.send_recv_plist({"command": "getHomeScreenIconMetrics"}))

    async def get_wallpaper_info(self, wallpaper_name: str) -> dict[str, Any]:
        """
        Retrieve metadata about a named wallpaper.

        :param wallpaper_name: Name of the wallpaper to query.
        :returns: Mapping describing the wallpaper, as reported by SpringBoard.
        """
        return await self.service.send_recv_plist({"command": "getWallpaperInfo", "wallpaperName": wallpaper_name})

    async def reload_icon_state(self) -> None:
        """
        Re-apply the current icon layout by reading it back and writing it unchanged.

        Fetches the current icon state via `get_icon_state` and immediately sends it back
        through `set_icon_state`, forcing SpringBoard to reload its layout.
        """
        await self.set_icon_state(await self.get_icon_state())

    async def get_wallpaper_preview_image(self, wallpaper_name: str) -> bytes:
        """
        Retrieve the preview image for a named wallpaper.

        :param wallpaper_name: Name of the wallpaper whose preview image is requested.
        :returns: PNG-encoded preview image bytes.
        """
        return cast(
            bytes,
            (
                await self.service.send_recv_plist({
                    "command": "getWallpaperPreviewImage",
                    "wallpaperName": wallpaper_name,
                })
            )["pngData"],
        )
```

### get_icon_state

```
get_icon_state(format_version: str = '2') -> list[Any]
```

Retrieve the current home screen icon layout.

Parameters:

| Name             | Type  | Description                                                                                                      | Default |
| ---------------- | ----- | ---------------------------------------------------------------------------------------------------------------- | ------- |
| `format_version` | `str` | Icon state format version sent to SpringBoard as formatVersion. When falsy, the key is omitted from the request. | `'2'`   |

Returns:

| Type        | Description                                                      |
| ----------- | ---------------------------------------------------------------- |
| `list[Any]` | Nested list describing the home screen pages, folders and icons. |

Source code in `pymobiledevice3/services/springboard.py`

```
async def get_icon_state(self, format_version: str = "2") -> list[Any]:
    """
    Retrieve the current home screen icon layout.

    :param format_version: Icon state format version sent to SpringBoard as ``formatVersion``.
        When falsy, the key is omitted from the request.
    :returns: Nested list describing the home screen pages, folders and icons.
    """
    cmd = {"command": "getIconState"}
    if format_version:
        cmd["formatVersion"] = format_version
    return cast(list[Any], await self.service.send_recv_plist(cmd))
```

### set_icon_state

```
set_icon_state(newstate: Optional[list[Any]] = None) -> None
```

Apply a new home screen icon layout.

Parameters:

| Name       | Type                  | Description                                                                                       | Default |
| ---------- | --------------------- | ------------------------------------------------------------------------------------------------- | ------- |
| `newstate` | `Optional[list[Any]]` | Icon layout in the same structure returned by get_icon_state. When None, an empty layout is sent. | `None`  |

Source code in `pymobiledevice3/services/springboard.py`

```
async def set_icon_state(self, newstate: Optional[list[Any]] = None) -> None:
    """
    Apply a new home screen icon layout.

    :param newstate: Icon layout in the same structure returned by `get_icon_state`.
        When ``None``, an empty layout is sent.
    """
    state: Union[list[Any], dict[str, Any]] = {} if newstate is None else newstate
    await self.service.send_recv_prefixed(build_plist({"command": "setIconState", "iconState": state}))
```

### get_icon_pngdata

```
get_icon_pngdata(bundle_id: str) -> bytes
```

Retrieve the home screen icon image of an installed application.

Parameters:

| Name        | Type  | Description                                                   | Default    |
| ----------- | ----- | ------------------------------------------------------------- | ---------- |
| `bundle_id` | `str` | Bundle identifier of the application whose icon is requested. | *required* |

Returns:

| Type    | Description                                                      |
| ------- | ---------------------------------------------------------------- |
| `bytes` | PNG-encoded icon image bytes, or None if no pngData is returned. |

Source code in `pymobiledevice3/services/springboard.py`

```
async def get_icon_pngdata(self, bundle_id: str) -> bytes:
    """
    Retrieve the home screen icon image of an installed application.

    :param bundle_id: Bundle identifier of the application whose icon is requested.
    :returns: PNG-encoded icon image bytes, or ``None`` if no ``pngData`` is returned.
    """
    return cast(
        bytes,
        (await self.service.send_recv_plist({"command": "getIconPNGData", "bundleId": bundle_id})).get("pngData"),
    )
```

### get_interface_orientation

```
get_interface_orientation() -> InterfaceOrientation
```

Query the current SpringBoard interface orientation.

Returns:

| Type                   | Description                                                    |
| ---------------------- | -------------------------------------------------------------- |
| `InterfaceOrientation` | The current orientation as an InterfaceOrientation enum value. |

Source code in `pymobiledevice3/services/springboard.py`

```
async def get_interface_orientation(self) -> InterfaceOrientation:
    """
    Query the current SpringBoard interface orientation.

    :returns: The current orientation as an `InterfaceOrientation` enum value.
    """
    res = await self.service.send_recv_plist({"command": "getInterfaceOrientation"})
    return InterfaceOrientation(res.get("interfaceOrientation"))
```

### get_wallpaper_pngdata

```
get_wallpaper_pngdata() -> bytes
```

Retrieve the current home screen wallpaper image.

The device answers from the wallpaper's stored image. Poster-based wallpapers (the kind iOS creates since the customizable Lock Screen) have none, and the device then drops the connection instead of replying. `get_wallpaper_preview_image` renders the current home screen wallpaper either way.

Returns:

| Type    | Description                        |
| ------- | ---------------------------------- |
| `bytes` | PNG-encoded wallpaper image bytes. |

Raises:

| Type                             | Description                                   |
| -------------------------------- | --------------------------------------------- |
| `WallpaperImageUnavailableError` | if the current wallpaper has no stored image. |

Source code in `pymobiledevice3/services/springboard.py`

```
async def get_wallpaper_pngdata(self) -> bytes:
    """
    Retrieve the current home screen wallpaper image.

    The device answers from the wallpaper's stored image. Poster-based wallpapers (the kind iOS creates
    since the customizable Lock Screen) have none, and the device then drops the connection instead of
    replying. `get_wallpaper_preview_image` renders the current home screen wallpaper either way.

    :returns: PNG-encoded wallpaper image bytes.
    :raises WallpaperImageUnavailableError: if the current wallpaper has no stored image.
    """
    try:
        response = await self.service.send_recv_plist({"command": "getHomeScreenWallpaperPNGData"})
    except ConnectionTerminatedError:
        # The connection is unusable now; drop it so the next request starts a fresh one.
        await self.close()
        raise WallpaperImageUnavailableError(
            "The home screen wallpaper has no stored image (a poster-based wallpaper); "
            "use get_wallpaper_preview_image('homescreen') instead"
        ) from None
    return cast(bytes, response["pngData"])
```

### get_homescreen_icon_metrics

```
get_homescreen_icon_metrics() -> dict[str, float]
```

Retrieve the home screen icon layout metrics.

Returns:

| Type               | Description                                                                  |
| ------------------ | ---------------------------------------------------------------------------- |
| `dict[str, float]` | Mapping of metric names to their numeric values, as reported by SpringBoard. |

Source code in `pymobiledevice3/services/springboard.py`

```
async def get_homescreen_icon_metrics(self) -> dict[str, float]:
    """
    Retrieve the home screen icon layout metrics.

    :returns: Mapping of metric names to their numeric values, as reported by SpringBoard.
    """
    return cast(dict[str, float], await self.service.send_recv_plist({"command": "getHomeScreenIconMetrics"}))
```

### get_wallpaper_info

```
get_wallpaper_info(wallpaper_name: str) -> dict[str, Any]
```

Retrieve metadata about a named wallpaper.

Parameters:

| Name             | Type  | Description                     | Default    |
| ---------------- | ----- | ------------------------------- | ---------- |
| `wallpaper_name` | `str` | Name of the wallpaper to query. | *required* |

Returns:

| Type             | Description                                                   |
| ---------------- | ------------------------------------------------------------- |
| `dict[str, Any]` | Mapping describing the wallpaper, as reported by SpringBoard. |

Source code in `pymobiledevice3/services/springboard.py`

```
async def get_wallpaper_info(self, wallpaper_name: str) -> dict[str, Any]:
    """
    Retrieve metadata about a named wallpaper.

    :param wallpaper_name: Name of the wallpaper to query.
    :returns: Mapping describing the wallpaper, as reported by SpringBoard.
    """
    return await self.service.send_recv_plist({"command": "getWallpaperInfo", "wallpaperName": wallpaper_name})
```

### reload_icon_state

```
reload_icon_state() -> None
```

Re-apply the current icon layout by reading it back and writing it unchanged.

Fetches the current icon state via `get_icon_state` and immediately sends it back through `set_icon_state`, forcing SpringBoard to reload its layout.

Source code in `pymobiledevice3/services/springboard.py`

```
async def reload_icon_state(self) -> None:
    """
    Re-apply the current icon layout by reading it back and writing it unchanged.

    Fetches the current icon state via `get_icon_state` and immediately sends it back
    through `set_icon_state`, forcing SpringBoard to reload its layout.
    """
    await self.set_icon_state(await self.get_icon_state())
```

### get_wallpaper_preview_image

```
get_wallpaper_preview_image(wallpaper_name: str) -> bytes
```

Retrieve the preview image for a named wallpaper.

Parameters:

| Name             | Type  | Description                                             | Default    |
| ---------------- | ----- | ------------------------------------------------------- | ---------- |
| `wallpaper_name` | `str` | Name of the wallpaper whose preview image is requested. | *required* |

Returns:

| Type    | Description                      |
| ------- | -------------------------------- |
| `bytes` | PNG-encoded preview image bytes. |

Source code in `pymobiledevice3/services/springboard.py`

```
async def get_wallpaper_preview_image(self, wallpaper_name: str) -> bytes:
    """
    Retrieve the preview image for a named wallpaper.

    :param wallpaper_name: Name of the wallpaper whose preview image is requested.
    :returns: PNG-encoded preview image bytes.
    """
    return cast(
        bytes,
        (
            await self.service.send_recv_plist({
                "command": "getWallpaperPreviewImage",
                "wallpaperName": wallpaper_name,
            })
        )["pngData"],
    )
```

## pymobiledevice3.services.crash_reports.CrashReportsManager

Manage crash reports stored on a device.

Wraps the `com.apple.crashreportcopymobile` AFC service (for listing, reading, pulling and erasing reports) and the `com.apple.crashreportmover` service (for flushing pending reports). Must be used as an async context manager (`async with`); the synchronous context manager protocol is intentionally disabled.

Source code in `pymobiledevice3/services/crash_reports.py`

```
class CrashReportsManager:
    """
    Manage crash reports stored on a device.

    Wraps the ``com.apple.crashreportcopymobile`` AFC service (for listing, reading, pulling and
    erasing reports) and the ``com.apple.crashreportmover`` service (for flushing pending reports).
    Must be used as an async context manager (``async with``); the synchronous context manager
    protocol is intentionally disabled.
    """

    COPY_MOBILE_NAME = "com.apple.crashreportcopymobile"
    RSD_COPY_MOBILE_NAME = "com.apple.crashreportcopymobile.shim.remote"

    CRASH_MOVER_NAME = "com.apple.crashreportmover"
    RSD_CRASH_MOVER_NAME = "com.apple.crashreportmover.shim.remote"

    APPSTORED_PATH = "/com.apple.appstored"
    IN_PROGRESS_SYSDIAGNOSE_EXTENSIONS: ClassVar = [".tmp", ".tar.gz"]

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

        if isinstance(lockdown, LockdownClient):
            self.copy_mobile_service_name = self.COPY_MOBILE_NAME
            self.crash_mover_service_name = self.CRASH_MOVER_NAME
        else:
            self.copy_mobile_service_name = self.RSD_COPY_MOBILE_NAME
            self.crash_mover_service_name = self.RSD_CRASH_MOVER_NAME

        self.afc = AfcService(lockdown, service_name=self.copy_mobile_service_name)

    def __enter__(self):
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aenter__(self):
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ):
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying AFC connection."""
        await self.afc.aclose()

    async def clear(self, path: str = "/", match: Optional[str] = None) -> None:
        """
        Delete crash reports under a path.

        Without ``match``, lists the immediate children of ``path`` and removes each recursively.
        With ``match``, removes exactly the files `pull` would copy for the same regex (see
        `AfcService.rm`), without copying them; directories are kept.

        Some items cannot be deleted, and these are tolerated:
        - a ``com.apple.appstored`` entry, which the device may recreate right after it is deleted;
        - the files of a sysdiagnose that is still running or was interrupted, which the device does not
          let anyone delete (logged as a warning).
        An item the device removes while it is being cleared counts as deleted.

        :param path: Path under the crash reports directory to clear. Defaults to '/'.
        :param match: Optional regex over entry basenames, applied as `pull` applies it.
        :raises AfcDeleteError: If any other item could not be deleted; ``failures`` says why for each.
        """
        failures: dict[str, int] = {}
        if match is not None:
            failures.update(await self._rm(path, match=re.compile(match)))
        else:
            for filename in await self.ls(path, depth=1):
                failures.update(await self._rm(filename))

        # special case of file that sometimes created automatically right after delete,
        # and then we can't delete the folder because it's not empty
        failures.pop(self.APPSTORED_PATH, None)
        # a directory that keeps an undeletable entry cannot go either; report only the entries themselves
        failures = {
            failed: status
            for failed, status in failures.items()
            if not any(other.startswith(failed.rstrip("/") + "/") for other in failures)
        }
        sysdiagnose_dir = f"/{SYSDIAGNOSE_DIR}/"
        protected = sorted({
            failed[len(sysdiagnose_dir) :].split("/", 1)[0]
            for failed, status in failures.items()
            if failed.startswith(sysdiagnose_dir) and status == AfcError.PERM_DENIED
        })
        others = {
            failed: status
            for failed, status in failures.items()
            if not (failed.startswith(sysdiagnose_dir) and status == AfcError.PERM_DENIED)
        }
        if protected:
            self.logger.warning(
                f"The device does not allow deleting the files of a sysdiagnose that is still running or was "
                f"interrupted; kept under /{SYSDIAGNOSE_DIR}: {', '.join(protected)}"
            )
        if others:
            raise AfcDeleteError(
                f"Could not clear the crash reports under {path!r}: "
                + ", ".join(f"{failed} ({getattr(status, 'name', status)})" for failed, status in others.items()),
                others,
            )

    async def _rm(self, filename: str, match: Optional[re.Pattern[str]] = None) -> dict[str, int]:
        """What ``filename`` (or the files under it matching ``match``) kept that could not be deleted, and why."""
        try:
            await self.afc.rm(filename, match=match)
        except AfcDeleteError as e:
            return e.failures
        except AfcException as e:
            if e.status != AfcError.OBJECT_NOT_FOUND:
                raise
            # listed, then removed by the device before we got to it
        return {}

    async def ls(self, path: str = "/", depth: int = 1) -> list[str]:
        """
        List file and folder in the crash report's directory.
        :param path: Path to list, relative to the crash report's directory.
        :param depth: Listing depth, -1 to list infinite.
        :return: List of files listed.
        """
        result: list[str] = []
        async for item in self.afc.dirlist(path, depth):
            result.append(item)
        return result[1:]  # skip the root path '/'

    async def parse(self, path: str = "/") -> CrashReportBase:
        """
        Parse a crash report file and return the parsed crash report object.

        :param path: Path to a crash report file.
        :return: Parsed crash report object.
        """
        contents = await self.afc.get_file_contents(path)
        return get_crash_report_from_buf(contents.decode(), filename=path)

    async def parse_latest(
        self,
        path: str = "/",
        match: Optional[list[str]] = None,
        match_insensitive: Optional[list[str]] = None,
        count: int = 1,
    ) -> list[CrashReportBase]:
        """
        Parse latest top-level crash report(s) under a path, optionally filtered by basename regex patterns.

        Scans the top level of the given path, filters regular files by basename,
        and returns matches sorted by last modification time (newest first).

        :param path: Path whose top-level entries should be considered. Defaults to '/'
        :param match: Case-sensitive regex patterns over report basename.
        :param match_insensitive: Case-insensitive regex patterns over report basename.
        :param count: Maximum number of latest matching reports to parse.
        :return: Parsed crash report objects ordered from newest to oldest.
                 Result length is between 1 and count.
        :raises ValueError: If count < 1 or if no reports match the filters.

        All provided patterns must match.
        """

        def get_match_arguments_description():
            return ", ".join(
                f"{name}={value!r}"
                for name, value in (("match", match_patterns), ("match_insensitive", match_insensitive_patterns))
                if value
            )

        if count < 1:
            raise ValueError("count must be >= 1")

        match_patterns = match or []
        match_insensitive_patterns = match_insensitive or []

        patterns = [re.compile(pattern) for pattern in match_patterns]
        patterns.extend(re.compile(pattern, re.IGNORECASE) for pattern in match_insensitive_patterns)

        matching_entries_by_mtime = sorted(
            [
                (stat["st_mtime"].timestamp(), entry)
                async for entry in self.afc.dirlist(path, depth=1)
                if entry != path
                and (stat := await self.afc.stat(entry)).get("st_ifmt") == "S_IFREG"
                and (not patterns or all(pattern.search(posixpath.basename(entry)) for pattern in patterns))
            ],
            reverse=True,
        )

        if len(matching_entries_by_mtime) == 0:
            match_arguments_description = get_match_arguments_description()
            raise ValueError(
                f"No reports found ({match_arguments_description})"
                if match_arguments_description
                else "No reports found"
            )

        return [await self.parse(report_path) for _, report_path in matching_entries_by_mtime[:count]]

    async def pull(
        self, out: str, entry: str = "/", erase: bool = False, match: Optional[str] = None, progress_bar: bool = True
    ) -> None:
        """
        Pull crash reports from the device.
        :param out: Directory to pull crash reports to.
        :param entry: File or Folder to pull.
        :param erase: Whether to erase the original file from the CrashReports directory.
        :param match: Regex to match against file and directory names to pull.
        :param progress_bar: Whether to show a progress bar when pulling large files.
        """

        async def _callback(src: str, dst: str) -> None:
            self.logger.info(f"{src} --> {dst}")
            if erase:
                await self.afc.rm_single(src, force=True)

        match_pattern = None if match is None else re.compile(match)
        await self.afc.pull(
            entry, out, match_pattern, callback=_callback, progress_bar=progress_bar, ignore_errors=True
        )

    async def flush(self) -> None:
        """
        Flush pending crash products into the CrashReports directory.

        Connects to the ``com.apple.crashreportmover`` service, which moves any pending reports into
        the CrashReports directory and acknowledges with a ``ping`` once done.
        """
        ack = b"ping\x00"
        async with await self.lockdown.start_lockdown_service(self.crash_mover_service_name) as service:
            response = await service.recvall(len(ack))
        if response != ack:
            raise ProtocolError(f"The crash report mover sent an unexpected acknowledgement: {response!r}")

    async def watch(
        self, name: Optional[str] = None, raw: bool = False
    ) -> AsyncGenerator[Union[str, CrashReportBase], None]:
        """
        Continuously monitor the syslog and yield each newly created crash report.

        Watches the device syslog for ``osanalyticshelper`` "Saved type" messages, reads the
        referenced ``.ips`` or ``.panic`` file (retrying until it becomes readable) and yields it.

        :param name: If provided, only reports whose parsed process name equals this value are
            yielded; otherwise every new report is yielded.
        :param raw: When ``True``, yield the raw report text; when ``False``, yield the parsed
            crash report object.
        :returns: Async generator yielding either raw report strings or parsed crash report objects.
        """
        async for syslog_entry in OsTraceService(lockdown=self.lockdown).syslog():
            if (
                (posixpath.basename(syslog_entry.filename) != "osanalyticshelper")
                or (posixpath.basename(syslog_entry.image_name) != "OSAnalytics")
                or not syslog_entry.message.startswith("Saved type ")
            ):
                # skip non-ips creation syslog lines
                continue

            filename = posixpath.basename(syslog_entry.message.split()[-1])
            self.logger.debug(f"crash report: {filename}")

            if posixpath.splitext(filename)[-1] not in (".ips", ".panic"):
                continue

            while True:
                try:
                    contents = await self.afc.get_file_contents(filename)
                    crash_report_raw = contents.decode()
                    crash_report = get_crash_report_from_buf(crash_report_raw, filename=filename)
                    break
                except (AfcFileNotFoundError, JSONDecodeError):
                    # Sometimes we have to wait for the file to be readable
                    pass

            if name is None or crash_report.name == name:
                if raw:
                    yield crash_report_raw
                else:
                    yield crash_report

    async def get_new_sysdiagnose(
        self,
        out: str,
        erase: bool = True,
        *,
        timeout: Optional[float] = None,
        callback: Optional[Callable[[float], None]] = None,
    ) -> None:
        """
        Monitor the creation of a newly created sysdiagnose archive and pull it
        :param out: filename
        :param erase: remove after pulling
        :keyword timeout: Maximum time in seconds to wait for the completion of sysdiagnose archive
            If None (default), waits indefinitely
        :keyword callback: optional callback function (form: func(float)) that accepts the elapsed time so far
        """
        start_time = time.monotonic()
        end_time = None
        if timeout is not None:
            end_time = start_time + timeout
        sysdiagnose_filename = await self._get_new_sysdiagnose_filename(end_time)

        if callback is not None:
            callback(time.monotonic() - start_time)

        self.logger.info("sysdiagnose tarball creation has been started")
        await self._wait_for_sysdiagnose_to_finish(end_time)

        if callback is not None:
            callback(time.monotonic() - start_time)

        await self.pull(out, entry=sysdiagnose_filename, erase=erase)

        if callback is not None:
            callback(time.monotonic() - start_time)

    async def _wait_for_sysdiagnose_to_finish(self, end_time: Optional[float] = None) -> None:
        timeout = None if end_time is None else max(end_time - time.monotonic(), 0)
        async with NotificationProxyService(self.lockdown, timeout=timeout) as service:
            stop_notification = "com.apple.sysdiagnose.sysdiagnoseStopped"
            await service.notify_register_dispatch(stop_notification)
            try:
                async for event in service.receive_notification():
                    if event["Name"] != stop_notification:
                        continue
                    self.logger.debug(f"Received {event}")
                    await asyncio.sleep(IOS17_SYSDIAGNOSE_DELAY)
                    break
            except NotificationTimeoutError as e:
                raise SysdiagnoseTimeoutError("Timed out waiting for the sysdiagnose to complete.") from e

    async def _get_new_sysdiagnose_filename(self, end_time: Optional[float] = None) -> str:
        sysdiagnose_filename = None
        excluded_temp_files: list[str] = []

        while sysdiagnose_filename is None:
            try:
                for filename in await self.afc.listdir(SYSDIAGNOSE_DIR):
                    # search for an IN_PROGRESS archive
                    if filename not in excluded_temp_files and "IN_PROGRESS_" in filename:
                        for ext in self.IN_PROGRESS_SYSDIAGNOSE_EXTENSIONS:
                            if filename.endswith(ext):
                                delta = (
                                    await self.lockdown.get_date()
                                    - (await self.afc.stat(posixpath.join(SYSDIAGNOSE_DIR, filename)))["st_mtime"]
                                )
                                # Ignores IN_PROGRESS sysdiagnose files older than the defined time to live
                                if delta.total_seconds() < SYSDIAGNOSE_IN_PROGRESS_MAX_TTL_SECS:
                                    self.logger.debug(f"Detected in progress sysdiagnose {filename}")
                                    sysdiagnose_filename = filename.rsplit(ext)[0]
                                    sysdiagnose_filename = sysdiagnose_filename.replace("IN_PROGRESS_", "")
                                    sysdiagnose_filename = f"{sysdiagnose_filename}.tar.gz"
                                    return posixpath.join(SYSDIAGNOSE_DIR, sysdiagnose_filename)
                                else:
                                    self.logger.warning(f"Old sysdiagnose temp file ignored {filename}")
                                    excluded_temp_files.append(filename)
            except AfcException:
                pass

            if self._check_timeout(end_time):
                raise SysdiagnoseTimeoutError(
                    "Timed out waiting for the device to start writing the sysdiagnose archive."
                )
            await asyncio.sleep(0.1)

        # unreachable in practice (the loop only exits via return/raise); satisfies the declared return type
        return sysdiagnose_filename

    def _check_timeout(self, end_time: Optional[float] = None) -> bool:
        return end_time is not None and time.monotonic() > end_time
```

### aclose

```
aclose() -> None
```

Close the underlying AFC connection.

Source code in `pymobiledevice3/services/crash_reports.py`

```
async def aclose(self) -> None:
    """Close the underlying AFC connection."""
    await self.afc.aclose()
```

### clear

```
clear(path: str = '/', match: Optional[str] = None) -> None
```

Delete crash reports under a path.

Without `match`, lists the immediate children of `path` and removes each recursively. With `match`, removes exactly the files `pull` would copy for the same regex (see `AfcService.rm`), without copying them; directories are kept.

Some items cannot be deleted, and these are tolerated:

- a `com.apple.appstored` entry, which the device may recreate right after it is deleted;
- the files of a sysdiagnose that is still running or was interrupted, which the device does not let anyone delete (logged as a warning). An item the device removes while it is being cleared counts as deleted.

Parameters:

| Name    | Type            | Description                                                       | Default |
| ------- | --------------- | ----------------------------------------------------------------- | ------- |
| `path`  | `str`           | Path under the crash reports directory to clear. Defaults to '/'. | `'/'`   |
| `match` | `Optional[str]` | Optional regex over entry basenames, applied as pull applies it.  | `None`  |

Raises:

| Type             | Description                                                         |
| ---------------- | ------------------------------------------------------------------- |
| `AfcDeleteError` | If any other item could not be deleted; failures says why for each. |

Source code in `pymobiledevice3/services/crash_reports.py`

```
async def clear(self, path: str = "/", match: Optional[str] = None) -> None:
    """
    Delete crash reports under a path.

    Without ``match``, lists the immediate children of ``path`` and removes each recursively.
    With ``match``, removes exactly the files `pull` would copy for the same regex (see
    `AfcService.rm`), without copying them; directories are kept.

    Some items cannot be deleted, and these are tolerated:
    - a ``com.apple.appstored`` entry, which the device may recreate right after it is deleted;
    - the files of a sysdiagnose that is still running or was interrupted, which the device does not
      let anyone delete (logged as a warning).
    An item the device removes while it is being cleared counts as deleted.

    :param path: Path under the crash reports directory to clear. Defaults to '/'.
    :param match: Optional regex over entry basenames, applied as `pull` applies it.
    :raises AfcDeleteError: If any other item could not be deleted; ``failures`` says why for each.
    """
    failures: dict[str, int] = {}
    if match is not None:
        failures.update(await self._rm(path, match=re.compile(match)))
    else:
        for filename in await self.ls(path, depth=1):
            failures.update(await self._rm(filename))

    # special case of file that sometimes created automatically right after delete,
    # and then we can't delete the folder because it's not empty
    failures.pop(self.APPSTORED_PATH, None)
    # a directory that keeps an undeletable entry cannot go either; report only the entries themselves
    failures = {
        failed: status
        for failed, status in failures.items()
        if not any(other.startswith(failed.rstrip("/") + "/") for other in failures)
    }
    sysdiagnose_dir = f"/{SYSDIAGNOSE_DIR}/"
    protected = sorted({
        failed[len(sysdiagnose_dir) :].split("/", 1)[0]
        for failed, status in failures.items()
        if failed.startswith(sysdiagnose_dir) and status == AfcError.PERM_DENIED
    })
    others = {
        failed: status
        for failed, status in failures.items()
        if not (failed.startswith(sysdiagnose_dir) and status == AfcError.PERM_DENIED)
    }
    if protected:
        self.logger.warning(
            f"The device does not allow deleting the files of a sysdiagnose that is still running or was "
            f"interrupted; kept under /{SYSDIAGNOSE_DIR}: {', '.join(protected)}"
        )
    if others:
        raise AfcDeleteError(
            f"Could not clear the crash reports under {path!r}: "
            + ", ".join(f"{failed} ({getattr(status, 'name', status)})" for failed, status in others.items()),
            others,
        )
```

### ls

```
ls(path: str = '/', depth: int = 1) -> list[str]
```

List file and folder in the crash report's directory.

Parameters:

| Name    | Type  | Description                                             | Default |
| ------- | ----- | ------------------------------------------------------- | ------- |
| `path`  | `str` | Path to list, relative to the crash report's directory. | `'/'`   |
| `depth` | `int` | Listing depth, -1 to list infinite.                     | `1`     |

Returns:

| Type        | Description           |
| ----------- | --------------------- |
| `list[str]` | List of files listed. |

Source code in `pymobiledevice3/services/crash_reports.py`

```
async def ls(self, path: str = "/", depth: int = 1) -> list[str]:
    """
    List file and folder in the crash report's directory.
    :param path: Path to list, relative to the crash report's directory.
    :param depth: Listing depth, -1 to list infinite.
    :return: List of files listed.
    """
    result: list[str] = []
    async for item in self.afc.dirlist(path, depth):
        result.append(item)
    return result[1:]  # skip the root path '/'
```

### parse

```
parse(path: str = '/') -> CrashReportBase
```

Parse a crash report file and return the parsed crash report object.

Parameters:

| Name   | Type  | Description                  | Default |
| ------ | ----- | ---------------------------- | ------- |
| `path` | `str` | Path to a crash report file. | `'/'`   |

Returns:

| Type              | Description                 |
| ----------------- | --------------------------- |
| `CrashReportBase` | Parsed crash report object. |

Source code in `pymobiledevice3/services/crash_reports.py`

```
async def parse(self, path: str = "/") -> CrashReportBase:
    """
    Parse a crash report file and return the parsed crash report object.

    :param path: Path to a crash report file.
    :return: Parsed crash report object.
    """
    contents = await self.afc.get_file_contents(path)
    return get_crash_report_from_buf(contents.decode(), filename=path)
```

### parse_latest

```
parse_latest(path: str = '/', match: Optional[list[str]] = None, match_insensitive: Optional[list[str]] = None, count: int = 1) -> list[CrashReportBase]
```

Parse latest top-level crash report(s) under a path, optionally filtered by basename regex patterns.

Scans the top level of the given path, filters regular files by basename, and returns matches sorted by last modification time (newest first).

Parameters:

| Name                | Type                  | Description                                                        | Default |
| ------------------- | --------------------- | ------------------------------------------------------------------ | ------- |
| `path`              | `str`                 | Path whose top-level entries should be considered. Defaults to '/' | `'/'`   |
| `match`             | `Optional[list[str]]` | Case-sensitive regex patterns over report basename.                | `None`  |
| `match_insensitive` | `Optional[list[str]]` | Case-insensitive regex patterns over report basename.              | `None`  |
| `count`             | `int`                 | Maximum number of latest matching reports to parse.                | `1`     |

Returns:

| Type                    | Description                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------ |
| `list[CrashReportBase]` | Parsed crash report objects ordered from newest to oldest. Result length is between 1 and count. |

Raises:

| Type         | Description                                                                        |
| ------------ | ---------------------------------------------------------------------------------- |
| `ValueError` | If count < 1 or if no reports match the filters. All provided patterns must match. |

Source code in `pymobiledevice3/services/crash_reports.py`

```
async def parse_latest(
    self,
    path: str = "/",
    match: Optional[list[str]] = None,
    match_insensitive: Optional[list[str]] = None,
    count: int = 1,
) -> list[CrashReportBase]:
    """
    Parse latest top-level crash report(s) under a path, optionally filtered by basename regex patterns.

    Scans the top level of the given path, filters regular files by basename,
    and returns matches sorted by last modification time (newest first).

    :param path: Path whose top-level entries should be considered. Defaults to '/'
    :param match: Case-sensitive regex patterns over report basename.
    :param match_insensitive: Case-insensitive regex patterns over report basename.
    :param count: Maximum number of latest matching reports to parse.
    :return: Parsed crash report objects ordered from newest to oldest.
             Result length is between 1 and count.
    :raises ValueError: If count < 1 or if no reports match the filters.

    All provided patterns must match.
    """

    def get_match_arguments_description():
        return ", ".join(
            f"{name}={value!r}"
            for name, value in (("match", match_patterns), ("match_insensitive", match_insensitive_patterns))
            if value
        )

    if count < 1:
        raise ValueError("count must be >= 1")

    match_patterns = match or []
    match_insensitive_patterns = match_insensitive or []

    patterns = [re.compile(pattern) for pattern in match_patterns]
    patterns.extend(re.compile(pattern, re.IGNORECASE) for pattern in match_insensitive_patterns)

    matching_entries_by_mtime = sorted(
        [
            (stat["st_mtime"].timestamp(), entry)
            async for entry in self.afc.dirlist(path, depth=1)
            if entry != path
            and (stat := await self.afc.stat(entry)).get("st_ifmt") == "S_IFREG"
            and (not patterns or all(pattern.search(posixpath.basename(entry)) for pattern in patterns))
        ],
        reverse=True,
    )

    if len(matching_entries_by_mtime) == 0:
        match_arguments_description = get_match_arguments_description()
        raise ValueError(
            f"No reports found ({match_arguments_description})"
            if match_arguments_description
            else "No reports found"
        )

    return [await self.parse(report_path) for _, report_path in matching_entries_by_mtime[:count]]
```

### pull

```
pull(out: str, entry: str = '/', erase: bool = False, match: Optional[str] = None, progress_bar: bool = True) -> None
```

Pull crash reports from the device.

Parameters:

| Name           | Type            | Description                                                         | Default    |
| -------------- | --------------- | ------------------------------------------------------------------- | ---------- |
| `out`          | `str`           | Directory to pull crash reports to.                                 | *required* |
| `entry`        | `str`           | File or Folder to pull.                                             | `'/'`      |
| `erase`        | `bool`          | Whether to erase the original file from the CrashReports directory. | `False`    |
| `match`        | `Optional[str]` | Regex to match against file and directory names to pull.            | `None`     |
| `progress_bar` | `bool`          | Whether to show a progress bar when pulling large files.            | `True`     |

Source code in `pymobiledevice3/services/crash_reports.py`

```
async def pull(
    self, out: str, entry: str = "/", erase: bool = False, match: Optional[str] = None, progress_bar: bool = True
) -> None:
    """
    Pull crash reports from the device.
    :param out: Directory to pull crash reports to.
    :param entry: File or Folder to pull.
    :param erase: Whether to erase the original file from the CrashReports directory.
    :param match: Regex to match against file and directory names to pull.
    :param progress_bar: Whether to show a progress bar when pulling large files.
    """

    async def _callback(src: str, dst: str) -> None:
        self.logger.info(f"{src} --> {dst}")
        if erase:
            await self.afc.rm_single(src, force=True)

    match_pattern = None if match is None else re.compile(match)
    await self.afc.pull(
        entry, out, match_pattern, callback=_callback, progress_bar=progress_bar, ignore_errors=True
    )
```

### flush

```
flush() -> None
```

Flush pending crash products into the CrashReports directory.

Connects to the `com.apple.crashreportmover` service, which moves any pending reports into the CrashReports directory and acknowledges with a `ping` once done.

Source code in `pymobiledevice3/services/crash_reports.py`

```
async def flush(self) -> None:
    """
    Flush pending crash products into the CrashReports directory.

    Connects to the ``com.apple.crashreportmover`` service, which moves any pending reports into
    the CrashReports directory and acknowledges with a ``ping`` once done.
    """
    ack = b"ping\x00"
    async with await self.lockdown.start_lockdown_service(self.crash_mover_service_name) as service:
        response = await service.recvall(len(ack))
    if response != ack:
        raise ProtocolError(f"The crash report mover sent an unexpected acknowledgement: {response!r}")
```

### watch

```
watch(name: Optional[str] = None, raw: bool = False) -> AsyncGenerator[Union[str, CrashReportBase], None]
```

Continuously monitor the syslog and yield each newly created crash report.

Watches the device syslog for `osanalyticshelper` "Saved type" messages, reads the referenced `.ips` or `.panic` file (retrying until it becomes readable) and yields it.

Parameters:

| Name   | Type            | Description                                                                                                               | Default |
| ------ | --------------- | ------------------------------------------------------------------------------------------------------------------------- | ------- |
| `name` | `Optional[str]` | If provided, only reports whose parsed process name equals this value are yielded; otherwise every new report is yielded. | `None`  |
| `raw`  | `bool`          | When True, yield the raw report text; when False, yield the parsed crash report object.                                   | `False` |

Returns:

| Type                                                | Description                                                                        |
| --------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `AsyncGenerator[Union[str, CrashReportBase], None]` | Async generator yielding either raw report strings or parsed crash report objects. |

Source code in `pymobiledevice3/services/crash_reports.py`

```
async def watch(
    self, name: Optional[str] = None, raw: bool = False
) -> AsyncGenerator[Union[str, CrashReportBase], None]:
    """
    Continuously monitor the syslog and yield each newly created crash report.

    Watches the device syslog for ``osanalyticshelper`` "Saved type" messages, reads the
    referenced ``.ips`` or ``.panic`` file (retrying until it becomes readable) and yields it.

    :param name: If provided, only reports whose parsed process name equals this value are
        yielded; otherwise every new report is yielded.
    :param raw: When ``True``, yield the raw report text; when ``False``, yield the parsed
        crash report object.
    :returns: Async generator yielding either raw report strings or parsed crash report objects.
    """
    async for syslog_entry in OsTraceService(lockdown=self.lockdown).syslog():
        if (
            (posixpath.basename(syslog_entry.filename) != "osanalyticshelper")
            or (posixpath.basename(syslog_entry.image_name) != "OSAnalytics")
            or not syslog_entry.message.startswith("Saved type ")
        ):
            # skip non-ips creation syslog lines
            continue

        filename = posixpath.basename(syslog_entry.message.split()[-1])
        self.logger.debug(f"crash report: {filename}")

        if posixpath.splitext(filename)[-1] not in (".ips", ".panic"):
            continue

        while True:
            try:
                contents = await self.afc.get_file_contents(filename)
                crash_report_raw = contents.decode()
                crash_report = get_crash_report_from_buf(crash_report_raw, filename=filename)
                break
            except (AfcFileNotFoundError, JSONDecodeError):
                # Sometimes we have to wait for the file to be readable
                pass

        if name is None or crash_report.name == name:
            if raw:
                yield crash_report_raw
            else:
                yield crash_report
```

### get_new_sysdiagnose

```
get_new_sysdiagnose(out: str, erase: bool = True, *, timeout: Optional[float] = None, callback: Optional[Callable[[float], None]] = None) -> None
```

Monitor the creation of a newly created sysdiagnose archive and pull it

Parameters:

| Name       | Type                                | Description                                                                                                     | Default    |
| ---------- | ----------------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------- |
| `out`      | `str`                               | filename                                                                                                        | *required* |
| `erase`    | `bool`                              | remove after pulling                                                                                            | `True`     |
| `timeout`  | `Optional[float]`                   | Maximum time in seconds to wait for the completion of sysdiagnose archive If None (default), waits indefinitely | `None`     |
| `callback` | `Optional[Callable[[float], None]]` | optional callback function (form: func(float)) that accepts the elapsed time so far                             | `None`     |

Source code in `pymobiledevice3/services/crash_reports.py`

```
async def get_new_sysdiagnose(
    self,
    out: str,
    erase: bool = True,
    *,
    timeout: Optional[float] = None,
    callback: Optional[Callable[[float], None]] = None,
) -> None:
    """
    Monitor the creation of a newly created sysdiagnose archive and pull it
    :param out: filename
    :param erase: remove after pulling
    :keyword timeout: Maximum time in seconds to wait for the completion of sysdiagnose archive
        If None (default), waits indefinitely
    :keyword callback: optional callback function (form: func(float)) that accepts the elapsed time so far
    """
    start_time = time.monotonic()
    end_time = None
    if timeout is not None:
        end_time = start_time + timeout
    sysdiagnose_filename = await self._get_new_sysdiagnose_filename(end_time)

    if callback is not None:
        callback(time.monotonic() - start_time)

    self.logger.info("sysdiagnose tarball creation has been started")
    await self._wait_for_sysdiagnose_to_finish(end_time)

    if callback is not None:
        callback(time.monotonic() - start_time)

    await self.pull(out, entry=sysdiagnose_filename, erase=erase)

    if callback is not None:
        callback(time.monotonic() - start_time)
```

## pymobiledevice3.services.mobile_image_mounter.MobileImageMounterService

Bases: `LockdownService`

Client for the `com.apple.mobile.mobile_image_mounter` lockdown service.

Provides the low-level operations for mounting and unmounting disk images (such as the Developer Disk Image) on a device: looking up mounted images, uploading image bytes, mounting and unmounting, and the personalization queries used for personalized images. Subclasses specialize the behavior for a specific image type via `IMAGE_TYPE`.

Implemented device-side in `/usr/libexec/mobile_storage_proxy`.

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
class MobileImageMounterService(LockdownService):
    """
    Client for the ``com.apple.mobile.mobile_image_mounter`` lockdown service.

    Provides the low-level operations for mounting and unmounting disk images (such as the
    Developer Disk Image) on a device: looking up mounted images, uploading image bytes, mounting
    and unmounting, and the personalization queries used for personalized images. Subclasses
    specialize the behavior for a specific image type via `IMAGE_TYPE`.

    Implemented device-side in ``/usr/libexec/mobile_storage_proxy``.
    """

    # implemented in /usr/libexec/mobile_storage_proxy
    SERVICE_NAME = "com.apple.mobile.mobile_image_mounter"
    RSD_SERVICE_NAME = "com.apple.mobile.mobile_image_mounter.shim.remote"
    IMAGE_TYPE: ClassVar[Optional[str]] = None

    def __init__(self, lockdown: LockdownServiceProvider):
        super().__init__(lockdown)
        self._copy_devices_unsupported = False

    async def _send_recv(self, request: dict[str, Any]) -> dict[str, Any]:
        return await self.service.send_recv_plist(request)

    async def raise_if_cannot_mount(self) -> None:
        """
        Verify that an image of this mounter's `IMAGE_TYPE` can be mounted.

        :raises AlreadyMountedError: If an image of this type is already mounted.
        :raises DeveloperModeIsNotEnabledError: On iOS 16 and later when Developer Mode is disabled.
        """
        assert self.IMAGE_TYPE is not None
        if await self.is_image_mounted(self.IMAGE_TYPE):
            raise AlreadyMountedError()
        if self.lockdown.has_developer_mode and not await self.lockdown.get_developer_mode_status():
            raise DeveloperModeIsNotEnabledError()

    async def copy_devices(self) -> list[dict[str, Any]]:
        """
        List the images currently mounted on the device.

        :returns: List of dictionaries, one per mounted image entry.
        :raises MessageNotSupportedError: If the device does not support the ``CopyDevices`` command.
        """
        response = await self._send_recv({"Command": "CopyDevices"})
        try:
            return response["EntryList"]
        except KeyError as e:
            raise MessageNotSupportedError("CopyDevices", response) from e

    async def list_images(self) -> list[dict[str, Any]]:
        """
        List the images currently mounted on the device, also on devices without ``CopyDevices``.

        Before iOS 14 the only image is the ``Developer`` one, so it is looked up instead and reported
        with the fields ``CopyDevices`` gives it (``DiskImageType``, ``IsMounted``, ``ImageSignature``).

        :returns: List of dictionaries, one per mounted image entry.
        """
        if not self._copy_devices_unsupported:
            try:
                return await self.copy_devices()
            except MessageNotSupportedError:
                # see is_image_mounted(): the legacy proxy hangs up after an unknown command
                self._copy_devices_unsupported = True
                await self.close()
        try:
            signature = await self.lookup_image("Developer")
        except NotMountedError:
            return []
        return [{"DiskImageType": "Developer", "IsMounted": True, "ImageSignature": signature}]

    async def lookup_image(self, image_type: str) -> bytes:
        """
        Look up the signature of a mounted image by its type.

        :param image_type: Image type to look up (e.g. ``Developer`` or ``Personalized``).
        :returns: The image signature. If the device returns a list of signatures, the first is
            returned.
        :raises NotMountedError: If no image of this type is present.
        """
        response = await self._send_recv({"Command": "LookupImage", "ImageType": image_type})

        if not response or not response.get("ImagePresent", True):
            raise NotMountedError()

        signature = response.get("ImageSignature", [])
        if isinstance(signature, list):
            if not signature:
                raise NotMountedError()
            return cast(bytes, signature[0])
        return signature

    async def is_image_mounted(self, image_type: str) -> bool:
        """
        Check whether an image of the given type is mounted.

        :param image_type: Image type to check (e.g. ``Developer`` or ``Personalized``).
        :returns: ``True`` if an image of this type is mounted, ``False`` otherwise.
        """
        try:
            await self.lookup_image(image_type)
        except NotMountedError:
            pass
        else:
            return True
        # LookupImage may return an empty ImageSignature for a Personalized image that IS mounted
        # (observed on iOS 27.0), in which case MountImage would fail with "already mounted".
        # CopyDevices does list such an image, so consult it as well.
        if self._copy_devices_unsupported:
            return False
        try:
            devices = await self.copy_devices()
        except MessageNotSupportedError:
            # Legacy mobile_storage_proxy (observed on iOS 12.5.7) hangs up the connection after
            # answering an unknown command, so drop it for the next command to reconnect, and
            # don't provoke the hangup again.
            self._copy_devices_unsupported = True
            await self.close()
            return False
        return any(device.get("DiskImageType") == image_type for device in devices)

    async def unmount_image(self, mount_path: str) -> None:
        """
        Unmount the image mounted at a given path (available since iOS 14.0).

        :param mount_path: Mount point of the image to unmount (e.g. ``/Developer``).
        :raises UnsupportedCommandError: If the device does not support the ``UnmountImage`` command.
        :raises NotMountedError: If no image is mounted at ``mount_path``.
        :raises InternalError: If the device reports an internal error.
        :raises PyMobileDevice3Exception: For any other error reported by the device.
        """
        request = {"Command": "UnmountImage", "MountPath": mount_path}
        response = await self._send_recv(request)

        error = response.get("Error")
        if error:
            if error == "UnknownCommand":
                raise UnsupportedCommandError()
            elif "There is no matching entry" in response.get("DetailedError", ""):
                raise NotMountedError(f"No image is mounted at {mount_path}.")
            elif error == "InternalError":
                raise InternalError(response)
            else:
                raise PyMobileDevice3Exception(f"The device failed to unmount the image at {mount_path}: {response}")

    async def mount_image(self, image_type: str, signature: bytes, extras: Optional[dict[str, Any]] = None) -> None:
        """
        Mount an image that has already been uploaded to the device.

        :param image_type: Image type to mount (e.g. ``Developer`` or ``Personalized``).
        :param signature: Image signature (or, for personalized images, the IM4M manifest).
        :param extras: Optional additional fields merged into the ``MountImage`` request, such as
            ``ImageTrustCache`` and ``ImageInfoPlist`` for personalized images.
        :raises AlreadyMountedError: If an image of this type is already mounted.
        :raises DeveloperModeIsNotEnabledError: If the device reports Developer Mode is disabled.
        :raises PyMobileDevice3Exception: If the mount does not complete successfully.
        """

        if await self.is_image_mounted(image_type):
            raise AlreadyMountedError()

        request: dict[str, Any] = {"Command": "MountImage", "ImageType": image_type, "ImageSignature": signature}

        if extras is not None:
            request.update(extras)
        response = await self._send_recv(request)

        if "Developer mode is not enabled" in response.get("DetailedError", ""):
            raise DeveloperModeIsNotEnabledError()

        status = response.get("Status")

        if status != "Complete":
            # backstop for when the pre-mount check above missed the mounted image
            if "is already mounted" in response.get("DetailedError", ""):
                raise AlreadyMountedError(
                    f"A {image_type} image is already mounted: {response.get('DetailedError', response)}"
                )
            raise PyMobileDevice3Exception(f"The device failed to mount the {image_type} image: {response}")

    async def upload_image(self, image_type: str, image: bytes, signature: bytes) -> None:
        """
        Upload image bytes to the device in preparation for mounting.

        Issues a ``ReceiveBytes`` command, streams the image bytes once the device acknowledges, and
        waits for completion.

        :param image_type: Image type being uploaded (e.g. ``Developer`` or ``Personalized``).
        :param image: Raw image bytes to upload.
        :param signature: Image signature (or, for personalized images, the IM4M manifest).
        :raises PyMobileDevice3Exception: If the device does not acknowledge or does not complete
            the transfer.
        """
        result = await self.service.send_recv_plist({
            "Command": "ReceiveBytes",
            "ImageType": image_type,
            "ImageSize": len(image),
            "ImageSignature": signature,
        })

        status = result.get("Status")

        if status != "ReceiveBytesAck":
            raise PyMobileDevice3Exception(f"The device refused to receive the {image_type} image: {result}")

        await self.service.sendall(image)
        result = await self.service.recv_plist()

        status = result.get("Status")

        if status != "Complete":
            raise PyMobileDevice3Exception(f"The device failed to receive the {image_type} image: {result}")

    async def query_developer_mode_status(self) -> bool:
        """
        Query whether Developer Mode is enabled on the device.

        :returns: ``True`` if Developer Mode is enabled, ``False`` otherwise.
        :raises MessageNotSupportedError: If the device does not support this command.
        """
        response = await self._send_recv({"Command": "QueryDeveloperModeStatus"})

        try:
            return response["DeveloperModeStatus"]
        except KeyError as e:
            raise MessageNotSupportedError("QueryDeveloperModeStatus", response) from e

    async def query_nonce(self, personalized_image_type: Optional[str] = None) -> bytes:
        """
        Query the personalization nonce used for image personalization.

        :param personalized_image_type: Optional image type to scope the nonce to, sent as
            ``PersonalizedImageType``.
        :returns: The personalization nonce bytes.
        :raises MessageNotSupportedError: If the device does not support this command.
        """
        request = {"Command": "QueryNonce"}
        if personalized_image_type is not None:
            request["PersonalizedImageType"] = personalized_image_type
        response = await self._send_recv(request)
        try:
            return response["PersonalizationNonce"]
        except KeyError as e:
            raise MessageNotSupportedError("QueryNonce", response) from e

    async def query_personalization_identifiers(self, image_type: Optional[str] = None) -> dict[str, Any]:
        """
        Query the device identifiers required to personalize an image (board ID, chip ID, etc.).

        :param image_type: Optional image type to scope the query to, sent as
            ``PersonalizedImageType``.
        :returns: Mapping of personalization identifiers reported by the device.
        :raises MessageNotSupportedError: If the device does not support this command.
        """
        request = {"Command": "QueryPersonalizationIdentifiers"}

        if image_type is not None:
            request["PersonalizedImageType"] = image_type

        response = await self._send_recv(request)

        try:
            return response["PersonalizationIdentifiers"]
        except KeyError as e:
            raise MessageNotSupportedError from e

    async def query_personalization_manifest(self, image_type: str, signature: bytes) -> bytes:
        """
        Fetch a personalization manifest already stored on the device for an image.

        :param image_type: Image type whose manifest is requested.
        :param signature: Signature/digest of the image being queried.
        :returns: The personalization manifest, returned by the device under ``ImageSignature`` but
            actually an IM4M.
        :raises MissingManifestError: If the device has no manifest for the image.
        """
        response = await self._send_recv({
            "Command": "QueryPersonalizationManifest",
            "PersonalizedImageType": image_type,
            "ImageType": image_type,
            "ImageSignature": signature,
        })
        try:
            # The response "ImageSignature" is actually an IM4M
            return response["ImageSignature"]
        except KeyError as e:
            raise MissingManifestError() from e

    async def roll_personalization_nonce(self) -> None:
        """
        Request the device to roll (regenerate) its personalization nonce.

        The device may close the connection while handling this command; a resulting
        `ConnectionTerminatedError` is swallowed and treated as success.
        """
        try:
            await self._send_recv({"Command": "RollPersonalizationNonce"})
        except ConnectionTerminatedError:
            return

    async def roll_cryptex_nonce(self) -> None:
        """
        Request the device to roll (regenerate) its cryptex nonce.

        The device may close the connection while handling this command; a resulting
        `ConnectionTerminatedError` is swallowed and treated as success.
        """
        try:
            await self._send_recv({"Command": "RollCryptexNonce"})
        except ConnectionTerminatedError:
            return
```

### raise_if_cannot_mount

```
raise_if_cannot_mount() -> None
```

Verify that an image of this mounter's `IMAGE_TYPE` can be mounted.

Raises:

| Type                             | Description                                          |
| -------------------------------- | ---------------------------------------------------- |
| `AlreadyMountedError`            | If an image of this type is already mounted.         |
| `DeveloperModeIsNotEnabledError` | On iOS 16 and later when Developer Mode is disabled. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def raise_if_cannot_mount(self) -> None:
    """
    Verify that an image of this mounter's `IMAGE_TYPE` can be mounted.

    :raises AlreadyMountedError: If an image of this type is already mounted.
    :raises DeveloperModeIsNotEnabledError: On iOS 16 and later when Developer Mode is disabled.
    """
    assert self.IMAGE_TYPE is not None
    if await self.is_image_mounted(self.IMAGE_TYPE):
        raise AlreadyMountedError()
    if self.lockdown.has_developer_mode and not await self.lockdown.get_developer_mode_status():
        raise DeveloperModeIsNotEnabledError()
```

### copy_devices

```
copy_devices() -> list[dict[str, Any]]
```

List the images currently mounted on the device.

Returns:

| Type                   | Description                                        |
| ---------------------- | -------------------------------------------------- |
| `list[dict[str, Any]]` | List of dictionaries, one per mounted image entry. |

Raises:

| Type                       | Description                                             |
| -------------------------- | ------------------------------------------------------- |
| `MessageNotSupportedError` | If the device does not support the CopyDevices command. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def copy_devices(self) -> list[dict[str, Any]]:
    """
    List the images currently mounted on the device.

    :returns: List of dictionaries, one per mounted image entry.
    :raises MessageNotSupportedError: If the device does not support the ``CopyDevices`` command.
    """
    response = await self._send_recv({"Command": "CopyDevices"})
    try:
        return response["EntryList"]
    except KeyError as e:
        raise MessageNotSupportedError("CopyDevices", response) from e
```

### list_images

```
list_images() -> list[dict[str, Any]]
```

List the images currently mounted on the device, also on devices without `CopyDevices`.

Before iOS 14 the only image is the `Developer` one, so it is looked up instead and reported with the fields `CopyDevices` gives it (`DiskImageType`, `IsMounted`, `ImageSignature`).

Returns:

| Type                   | Description                                        |
| ---------------------- | -------------------------------------------------- |
| `list[dict[str, Any]]` | List of dictionaries, one per mounted image entry. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def list_images(self) -> list[dict[str, Any]]:
    """
    List the images currently mounted on the device, also on devices without ``CopyDevices``.

    Before iOS 14 the only image is the ``Developer`` one, so it is looked up instead and reported
    with the fields ``CopyDevices`` gives it (``DiskImageType``, ``IsMounted``, ``ImageSignature``).

    :returns: List of dictionaries, one per mounted image entry.
    """
    if not self._copy_devices_unsupported:
        try:
            return await self.copy_devices()
        except MessageNotSupportedError:
            # see is_image_mounted(): the legacy proxy hangs up after an unknown command
            self._copy_devices_unsupported = True
            await self.close()
    try:
        signature = await self.lookup_image("Developer")
    except NotMountedError:
        return []
    return [{"DiskImageType": "Developer", "IsMounted": True, "ImageSignature": signature}]
```

### lookup_image

```
lookup_image(image_type: str) -> bytes
```

Look up the signature of a mounted image by its type.

Parameters:

| Name         | Type  | Description                                             | Default    |
| ------------ | ----- | ------------------------------------------------------- | ---------- |
| `image_type` | `str` | Image type to look up (e.g. Developer or Personalized). | *required* |

Returns:

| Type    | Description                                                                             |
| ------- | --------------------------------------------------------------------------------------- |
| `bytes` | The image signature. If the device returns a list of signatures, the first is returned. |

Raises:

| Type              | Description                          |
| ----------------- | ------------------------------------ |
| `NotMountedError` | If no image of this type is present. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def lookup_image(self, image_type: str) -> bytes:
    """
    Look up the signature of a mounted image by its type.

    :param image_type: Image type to look up (e.g. ``Developer`` or ``Personalized``).
    :returns: The image signature. If the device returns a list of signatures, the first is
        returned.
    :raises NotMountedError: If no image of this type is present.
    """
    response = await self._send_recv({"Command": "LookupImage", "ImageType": image_type})

    if not response or not response.get("ImagePresent", True):
        raise NotMountedError()

    signature = response.get("ImageSignature", [])
    if isinstance(signature, list):
        if not signature:
            raise NotMountedError()
        return cast(bytes, signature[0])
    return signature
```

### is_image_mounted

```
is_image_mounted(image_type: str) -> bool
```

Check whether an image of the given type is mounted.

Parameters:

| Name         | Type  | Description                                           | Default    |
| ------------ | ----- | ----------------------------------------------------- | ---------- |
| `image_type` | `str` | Image type to check (e.g. Developer or Personalized). | *required* |

Returns:

| Type   | Description                                                |
| ------ | ---------------------------------------------------------- |
| `bool` | True if an image of this type is mounted, False otherwise. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def is_image_mounted(self, image_type: str) -> bool:
    """
    Check whether an image of the given type is mounted.

    :param image_type: Image type to check (e.g. ``Developer`` or ``Personalized``).
    :returns: ``True`` if an image of this type is mounted, ``False`` otherwise.
    """
    try:
        await self.lookup_image(image_type)
    except NotMountedError:
        pass
    else:
        return True
    # LookupImage may return an empty ImageSignature for a Personalized image that IS mounted
    # (observed on iOS 27.0), in which case MountImage would fail with "already mounted".
    # CopyDevices does list such an image, so consult it as well.
    if self._copy_devices_unsupported:
        return False
    try:
        devices = await self.copy_devices()
    except MessageNotSupportedError:
        # Legacy mobile_storage_proxy (observed on iOS 12.5.7) hangs up the connection after
        # answering an unknown command, so drop it for the next command to reconnect, and
        # don't provoke the hangup again.
        self._copy_devices_unsupported = True
        await self.close()
        return False
    return any(device.get("DiskImageType") == image_type for device in devices)
```

### unmount_image

```
unmount_image(mount_path: str) -> None
```

Unmount the image mounted at a given path (available since iOS 14.0).

Parameters:

| Name         | Type  | Description                                            | Default    |
| ------------ | ----- | ------------------------------------------------------ | ---------- |
| `mount_path` | `str` | Mount point of the image to unmount (e.g. /Developer). | *required* |

Raises:

| Type                       | Description                                              |
| -------------------------- | -------------------------------------------------------- |
| `UnsupportedCommandError`  | If the device does not support the UnmountImage command. |
| `NotMountedError`          | If no image is mounted at mount_path.                    |
| `InternalError`            | If the device reports an internal error.                 |
| `PyMobileDevice3Exception` | For any other error reported by the device.              |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def unmount_image(self, mount_path: str) -> None:
    """
    Unmount the image mounted at a given path (available since iOS 14.0).

    :param mount_path: Mount point of the image to unmount (e.g. ``/Developer``).
    :raises UnsupportedCommandError: If the device does not support the ``UnmountImage`` command.
    :raises NotMountedError: If no image is mounted at ``mount_path``.
    :raises InternalError: If the device reports an internal error.
    :raises PyMobileDevice3Exception: For any other error reported by the device.
    """
    request = {"Command": "UnmountImage", "MountPath": mount_path}
    response = await self._send_recv(request)

    error = response.get("Error")
    if error:
        if error == "UnknownCommand":
            raise UnsupportedCommandError()
        elif "There is no matching entry" in response.get("DetailedError", ""):
            raise NotMountedError(f"No image is mounted at {mount_path}.")
        elif error == "InternalError":
            raise InternalError(response)
        else:
            raise PyMobileDevice3Exception(f"The device failed to unmount the image at {mount_path}: {response}")
```

### mount_image

```
mount_image(image_type: str, signature: bytes, extras: Optional[dict[str, Any]] = None) -> None
```

Mount an image that has already been uploaded to the device.

Parameters:

| Name         | Type                       | Description                                                                                                                        | Default    |
| ------------ | -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `image_type` | `str`                      | Image type to mount (e.g. Developer or Personalized).                                                                              | *required* |
| `signature`  | `bytes`                    | Image signature (or, for personalized images, the IM4M manifest).                                                                  | *required* |
| `extras`     | `Optional[dict[str, Any]]` | Optional additional fields merged into the MountImage request, such as ImageTrustCache and ImageInfoPlist for personalized images. | `None`     |

Raises:

| Type                             | Description                                       |
| -------------------------------- | ------------------------------------------------- |
| `AlreadyMountedError`            | If an image of this type is already mounted.      |
| `DeveloperModeIsNotEnabledError` | If the device reports Developer Mode is disabled. |
| `PyMobileDevice3Exception`       | If the mount does not complete successfully.      |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def mount_image(self, image_type: str, signature: bytes, extras: Optional[dict[str, Any]] = None) -> None:
    """
    Mount an image that has already been uploaded to the device.

    :param image_type: Image type to mount (e.g. ``Developer`` or ``Personalized``).
    :param signature: Image signature (or, for personalized images, the IM4M manifest).
    :param extras: Optional additional fields merged into the ``MountImage`` request, such as
        ``ImageTrustCache`` and ``ImageInfoPlist`` for personalized images.
    :raises AlreadyMountedError: If an image of this type is already mounted.
    :raises DeveloperModeIsNotEnabledError: If the device reports Developer Mode is disabled.
    :raises PyMobileDevice3Exception: If the mount does not complete successfully.
    """

    if await self.is_image_mounted(image_type):
        raise AlreadyMountedError()

    request: dict[str, Any] = {"Command": "MountImage", "ImageType": image_type, "ImageSignature": signature}

    if extras is not None:
        request.update(extras)
    response = await self._send_recv(request)

    if "Developer mode is not enabled" in response.get("DetailedError", ""):
        raise DeveloperModeIsNotEnabledError()

    status = response.get("Status")

    if status != "Complete":
        # backstop for when the pre-mount check above missed the mounted image
        if "is already mounted" in response.get("DetailedError", ""):
            raise AlreadyMountedError(
                f"A {image_type} image is already mounted: {response.get('DetailedError', response)}"
            )
        raise PyMobileDevice3Exception(f"The device failed to mount the {image_type} image: {response}")
```

### upload_image

```
upload_image(image_type: str, image: bytes, signature: bytes) -> None
```

Upload image bytes to the device in preparation for mounting.

Issues a `ReceiveBytes` command, streams the image bytes once the device acknowledges, and waits for completion.

Parameters:

| Name         | Type    | Description                                                       | Default    |
| ------------ | ------- | ----------------------------------------------------------------- | ---------- |
| `image_type` | `str`   | Image type being uploaded (e.g. Developer or Personalized).       | *required* |
| `image`      | `bytes` | Raw image bytes to upload.                                        | *required* |
| `signature`  | `bytes` | Image signature (or, for personalized images, the IM4M manifest). | *required* |

Raises:

| Type                       | Description                                                           |
| -------------------------- | --------------------------------------------------------------------- |
| `PyMobileDevice3Exception` | If the device does not acknowledge or does not complete the transfer. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def upload_image(self, image_type: str, image: bytes, signature: bytes) -> None:
    """
    Upload image bytes to the device in preparation for mounting.

    Issues a ``ReceiveBytes`` command, streams the image bytes once the device acknowledges, and
    waits for completion.

    :param image_type: Image type being uploaded (e.g. ``Developer`` or ``Personalized``).
    :param image: Raw image bytes to upload.
    :param signature: Image signature (or, for personalized images, the IM4M manifest).
    :raises PyMobileDevice3Exception: If the device does not acknowledge or does not complete
        the transfer.
    """
    result = await self.service.send_recv_plist({
        "Command": "ReceiveBytes",
        "ImageType": image_type,
        "ImageSize": len(image),
        "ImageSignature": signature,
    })

    status = result.get("Status")

    if status != "ReceiveBytesAck":
        raise PyMobileDevice3Exception(f"The device refused to receive the {image_type} image: {result}")

    await self.service.sendall(image)
    result = await self.service.recv_plist()

    status = result.get("Status")

    if status != "Complete":
        raise PyMobileDevice3Exception(f"The device failed to receive the {image_type} image: {result}")
```

### query_developer_mode_status

```
query_developer_mode_status() -> bool
```

Query whether Developer Mode is enabled on the device.

Returns:

| Type   | Description                                         |
| ------ | --------------------------------------------------- |
| `bool` | True if Developer Mode is enabled, False otherwise. |

Raises:

| Type                       | Description                                  |
| -------------------------- | -------------------------------------------- |
| `MessageNotSupportedError` | If the device does not support this command. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def query_developer_mode_status(self) -> bool:
    """
    Query whether Developer Mode is enabled on the device.

    :returns: ``True`` if Developer Mode is enabled, ``False`` otherwise.
    :raises MessageNotSupportedError: If the device does not support this command.
    """
    response = await self._send_recv({"Command": "QueryDeveloperModeStatus"})

    try:
        return response["DeveloperModeStatus"]
    except KeyError as e:
        raise MessageNotSupportedError("QueryDeveloperModeStatus", response) from e
```

### query_nonce

```
query_nonce(personalized_image_type: Optional[str] = None) -> bytes
```

Query the personalization nonce used for image personalization.

Parameters:

| Name                      | Type            | Description                                                               | Default |
| ------------------------- | --------------- | ------------------------------------------------------------------------- | ------- |
| `personalized_image_type` | `Optional[str]` | Optional image type to scope the nonce to, sent as PersonalizedImageType. | `None`  |

Returns:

| Type    | Description                      |
| ------- | -------------------------------- |
| `bytes` | The personalization nonce bytes. |

Raises:

| Type                       | Description                                  |
| -------------------------- | -------------------------------------------- |
| `MessageNotSupportedError` | If the device does not support this command. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def query_nonce(self, personalized_image_type: Optional[str] = None) -> bytes:
    """
    Query the personalization nonce used for image personalization.

    :param personalized_image_type: Optional image type to scope the nonce to, sent as
        ``PersonalizedImageType``.
    :returns: The personalization nonce bytes.
    :raises MessageNotSupportedError: If the device does not support this command.
    """
    request = {"Command": "QueryNonce"}
    if personalized_image_type is not None:
        request["PersonalizedImageType"] = personalized_image_type
    response = await self._send_recv(request)
    try:
        return response["PersonalizationNonce"]
    except KeyError as e:
        raise MessageNotSupportedError("QueryNonce", response) from e
```

### query_personalization_identifiers

```
query_personalization_identifiers(image_type: Optional[str] = None) -> dict[str, Any]
```

Query the device identifiers required to personalize an image (board ID, chip ID, etc.).

Parameters:

| Name         | Type            | Description                                                               | Default |
| ------------ | --------------- | ------------------------------------------------------------------------- | ------- |
| `image_type` | `Optional[str]` | Optional image type to scope the query to, sent as PersonalizedImageType. | `None`  |

Returns:

| Type             | Description                                                    |
| ---------------- | -------------------------------------------------------------- |
| `dict[str, Any]` | Mapping of personalization identifiers reported by the device. |

Raises:

| Type                       | Description                                  |
| -------------------------- | -------------------------------------------- |
| `MessageNotSupportedError` | If the device does not support this command. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def query_personalization_identifiers(self, image_type: Optional[str] = None) -> dict[str, Any]:
    """
    Query the device identifiers required to personalize an image (board ID, chip ID, etc.).

    :param image_type: Optional image type to scope the query to, sent as
        ``PersonalizedImageType``.
    :returns: Mapping of personalization identifiers reported by the device.
    :raises MessageNotSupportedError: If the device does not support this command.
    """
    request = {"Command": "QueryPersonalizationIdentifiers"}

    if image_type is not None:
        request["PersonalizedImageType"] = image_type

    response = await self._send_recv(request)

    try:
        return response["PersonalizationIdentifiers"]
    except KeyError as e:
        raise MessageNotSupportedError from e
```

### query_personalization_manifest

```
query_personalization_manifest(image_type: str, signature: bytes) -> bytes
```

Fetch a personalization manifest already stored on the device for an image.

Parameters:

| Name         | Type    | Description                                  | Default    |
| ------------ | ------- | -------------------------------------------- | ---------- |
| `image_type` | `str`   | Image type whose manifest is requested.      | *required* |
| `signature`  | `bytes` | Signature/digest of the image being queried. | *required* |

Returns:

| Type    | Description                                                                                     |
| ------- | ----------------------------------------------------------------------------------------------- |
| `bytes` | The personalization manifest, returned by the device under ImageSignature but actually an IM4M. |

Raises:

| Type                   | Description                                  |
| ---------------------- | -------------------------------------------- |
| `MissingManifestError` | If the device has no manifest for the image. |

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def query_personalization_manifest(self, image_type: str, signature: bytes) -> bytes:
    """
    Fetch a personalization manifest already stored on the device for an image.

    :param image_type: Image type whose manifest is requested.
    :param signature: Signature/digest of the image being queried.
    :returns: The personalization manifest, returned by the device under ``ImageSignature`` but
        actually an IM4M.
    :raises MissingManifestError: If the device has no manifest for the image.
    """
    response = await self._send_recv({
        "Command": "QueryPersonalizationManifest",
        "PersonalizedImageType": image_type,
        "ImageType": image_type,
        "ImageSignature": signature,
    })
    try:
        # The response "ImageSignature" is actually an IM4M
        return response["ImageSignature"]
    except KeyError as e:
        raise MissingManifestError() from e
```

### roll_personalization_nonce

```
roll_personalization_nonce() -> None
```

Request the device to roll (regenerate) its personalization nonce.

The device may close the connection while handling this command; a resulting `ConnectionTerminatedError` is swallowed and treated as success.

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def roll_personalization_nonce(self) -> None:
    """
    Request the device to roll (regenerate) its personalization nonce.

    The device may close the connection while handling this command; a resulting
    `ConnectionTerminatedError` is swallowed and treated as success.
    """
    try:
        await self._send_recv({"Command": "RollPersonalizationNonce"})
    except ConnectionTerminatedError:
        return
```

### roll_cryptex_nonce

```
roll_cryptex_nonce() -> None
```

Request the device to roll (regenerate) its cryptex nonce.

The device may close the connection while handling this command; a resulting `ConnectionTerminatedError` is swallowed and treated as success.

Source code in `pymobiledevice3/services/mobile_image_mounter.py`

```
async def roll_cryptex_nonce(self) -> None:
    """
    Request the device to roll (regenerate) its cryptex nonce.

    The device may close the connection while handling this command; a resulting
    `ConnectionTerminatedError` is swallowed and treated as success.
    """
    try:
        await self._send_recv({"Command": "RollCryptexNonce"})
    except ConnectionTerminatedError:
        return
```

## pymobiledevice3.services.storage_mounter_bridge.StorageMounterBridgeService

Bases: `RemoteService`

Query the device's image mounter over RemoteXPC (`com.apple.mobile.storage_mounter_proxy.bridge`).

This is the RemoteXPC face of `mobile_storage_proxy`, the daemon behind `MobileImageMounterService`. It takes the same commands, wrapped as `{"XPCRequestDictionary": {"Command": <name>, ...}}`, and answers with the reply keys at the top level. Everything it reports is also available through `MobileImageMounterService`, which is the one to use for mounting; the read-only queries are wrapped here and `invoke` reaches the rest.

Requires an RSD tunnel. Verified on iOS 27.2. Use as an async context manager.

Source code in `pymobiledevice3/services/storage_mounter_bridge.py`

```
class StorageMounterBridgeService(RemoteService):
    """
    Query the device's image mounter over RemoteXPC (``com.apple.mobile.storage_mounter_proxy.bridge``).

    This is the RemoteXPC face of ``mobile_storage_proxy``, the daemon behind
    `MobileImageMounterService`. It takes the same commands, wrapped as
    ``{"XPCRequestDictionary": {"Command": <name>, ...}}``, and answers with the reply keys at the top
    level. Everything it reports is also available through `MobileImageMounterService`, which is the
    one to use for mounting; the read-only queries are wrapped here and `invoke` reaches the rest.

    Requires an RSD tunnel. Verified on iOS 27.2. Use as an async context manager.
    """

    SERVICE_NAME = "com.apple.mobile.storage_mounter_proxy.bridge"

    def __init__(self, rsd: RemoteServiceDiscoveryService) -> None:
        """
        :param rsd: RSD provider used to open the RemoteXPC service.
        """
        super().__init__(rsd, self.SERVICE_NAME)

    async def invoke(self, command: str, **arguments: Any) -> dict[str, Any]:
        """
        Send a command and return its reply.

        :param command: command name, e.g. ``CopyDevices``.
        :param arguments: the command's arguments, sent alongside it.
        :raises StorageMounterBridgeError: if the reply carries an ``Error``.
        """
        request: dict[str, Any] = {"Command": command, "HostProcessName": "pymobiledevice3", **arguments}
        response = await self.service.send_receive_request({"XPCRequestDictionary": request})
        error = response.get("Error")
        if error is not None:
            raise StorageMounterBridgeError(command, error, response.get("DetailedError"))
        return response

    async def copy_devices(self) -> list[dict[str, Any]]:
        """List the mounted images, as `MobileImageMounterService.copy_devices` does."""
        return (await self.invoke("CopyDevices"))["EntryList"]

    async def lookup_image(self, image_type: str) -> list[bytes]:
        """
        Get the signatures of the mounted images of a type.

        :param image_type: e.g. ``Personalized`` or ``Developer``.
        """
        return (await self.invoke("LookupImage", ImageType=image_type))["ImageSignature"]

    async def query_developer_mode_status(self) -> bool:
        """Whether Developer Mode is enabled."""
        return (await self.invoke("QueryDeveloperModeStatus"))["DeveloperModeStatus"]

    async def query_personalization_identifiers(self, image_type: Optional[str] = None) -> dict[str, Any]:
        """
        Get the identifiers a personalized image must be signed for (board, chip, ECID...).

        :param image_type: personalized image type, e.g. ``DeveloperDiskImage``.
        """
        arguments = {} if image_type is None else {"PersonalizedImageType": image_type}
        return (await self.invoke("QueryPersonalizationIdentifiers", **arguments))["PersonalizationIdentifiers"]

    async def query_nonce(self, image_type: Optional[str] = None) -> bytes:
        """
        Get the personalization nonce a signing request must carry.

        :param image_type: personalized image type, e.g. ``DeveloperDiskImage``.
        """
        arguments = {} if image_type is None else {"PersonalizedImageType": image_type}
        return (await self.invoke("QueryNonce", **arguments))["PersonalizationNonce"]
```

### invoke

```
invoke(command: str, **arguments: Any) -> dict[str, Any]
```

Send a command and return its reply.

Parameters:

| Name        | Type  | Description                                 | Default    |
| ----------- | ----- | ------------------------------------------- | ---------- |
| `command`   | `str` | command name, e.g. CopyDevices.             | *required* |
| `arguments` | `Any` | the command's arguments, sent alongside it. | `{}`       |

Raises:

| Type                        | Description                    |
| --------------------------- | ------------------------------ |
| `StorageMounterBridgeError` | if the reply carries an Error. |

Source code in `pymobiledevice3/services/storage_mounter_bridge.py`

```
async def invoke(self, command: str, **arguments: Any) -> dict[str, Any]:
    """
    Send a command and return its reply.

    :param command: command name, e.g. ``CopyDevices``.
    :param arguments: the command's arguments, sent alongside it.
    :raises StorageMounterBridgeError: if the reply carries an ``Error``.
    """
    request: dict[str, Any] = {"Command": command, "HostProcessName": "pymobiledevice3", **arguments}
    response = await self.service.send_receive_request({"XPCRequestDictionary": request})
    error = response.get("Error")
    if error is not None:
        raise StorageMounterBridgeError(command, error, response.get("DetailedError"))
    return response
```

### copy_devices

```
copy_devices() -> list[dict[str, Any]]
```

List the mounted images, as `MobileImageMounterService.copy_devices` does.

Source code in `pymobiledevice3/services/storage_mounter_bridge.py`

```
async def copy_devices(self) -> list[dict[str, Any]]:
    """List the mounted images, as `MobileImageMounterService.copy_devices` does."""
    return (await self.invoke("CopyDevices"))["EntryList"]
```

### lookup_image

```
lookup_image(image_type: str) -> list[bytes]
```

Get the signatures of the mounted images of a type.

Parameters:

| Name         | Type  | Description                     | Default    |
| ------------ | ----- | ------------------------------- | ---------- |
| `image_type` | `str` | e.g. Personalized or Developer. | *required* |

Source code in `pymobiledevice3/services/storage_mounter_bridge.py`

```
async def lookup_image(self, image_type: str) -> list[bytes]:
    """
    Get the signatures of the mounted images of a type.

    :param image_type: e.g. ``Personalized`` or ``Developer``.
    """
    return (await self.invoke("LookupImage", ImageType=image_type))["ImageSignature"]
```

### query_developer_mode_status

```
query_developer_mode_status() -> bool
```

Whether Developer Mode is enabled.

Source code in `pymobiledevice3/services/storage_mounter_bridge.py`

```
async def query_developer_mode_status(self) -> bool:
    """Whether Developer Mode is enabled."""
    return (await self.invoke("QueryDeveloperModeStatus"))["DeveloperModeStatus"]
```

### query_personalization_identifiers

```
query_personalization_identifiers(image_type: Optional[str] = None) -> dict[str, Any]
```

Get the identifiers a personalized image must be signed for (board, chip, ECID...).

Parameters:

| Name         | Type            | Description                                       | Default |
| ------------ | --------------- | ------------------------------------------------- | ------- |
| `image_type` | `Optional[str]` | personalized image type, e.g. DeveloperDiskImage. | `None`  |

Source code in `pymobiledevice3/services/storage_mounter_bridge.py`

```
async def query_personalization_identifiers(self, image_type: Optional[str] = None) -> dict[str, Any]:
    """
    Get the identifiers a personalized image must be signed for (board, chip, ECID...).

    :param image_type: personalized image type, e.g. ``DeveloperDiskImage``.
    """
    arguments = {} if image_type is None else {"PersonalizedImageType": image_type}
    return (await self.invoke("QueryPersonalizationIdentifiers", **arguments))["PersonalizationIdentifiers"]
```

### query_nonce

```
query_nonce(image_type: Optional[str] = None) -> bytes
```

Get the personalization nonce a signing request must carry.

Parameters:

| Name         | Type            | Description                                       | Default |
| ------------ | --------------- | ------------------------------------------------- | ------- |
| `image_type` | `Optional[str]` | personalized image type, e.g. DeveloperDiskImage. | `None`  |

Source code in `pymobiledevice3/services/storage_mounter_bridge.py`

```
async def query_nonce(self, image_type: Optional[str] = None) -> bytes:
    """
    Get the personalization nonce a signing request must carry.

    :param image_type: personalized image type, e.g. ``DeveloperDiskImage``.
    """
    arguments = {} if image_type is None else {"PersonalizedImageType": image_type}
    return (await self.invoke("QueryNonce", **arguments))["PersonalizationNonce"]
```

## DDI over cryptexd (iOS 17+)

`CryptexdService` installs the Developer Disk Image (DDI) as a cryptex, without the image mounter. It is a RemoteXPC service: construct it with a `RemoteServiceDiscoveryService` (it requires an RSD tunnel), not a lockdown client.

`auto_mount` uses it from `CRYPTEX_IMAGE_MIN_VERSION` (iOS 27) on, and then requires an RSD, raising `RSDRequiredError` for a plain lockdown client; `uses_cryptex_image` reports whether a device qualifies. Below that version it mounts the image mounter's `PersonalizedDMG`, since older `cryptexd` versions reject the install. Devices newer than the DDI (e.g. the iPhone 18 series) are not in the `PersonalizedDMG`'s build manifest, so for them the cryptex is the only option.

## pymobiledevice3.services.cryptexd.CryptexdService

Bases: `RemoteService`

Query `cryptexd` over RemoteXPC (`com.apple.security.cryptexd.remote`).

The service takes `{"routine": <name>, "argv": {...}}` requests and answers with either `{"error": 0, "argv": <result>}` on success or `{"cferr": {...}}` on failure, where `error` is a device-side Darwin errno.

All six routines the daemon dispatches are implemented: `read-personalization-id`, `copy-installed`, `get-nonce`, `roll-nonce`, `uninstall` and `install`. The last one delivers its payloads as out-of-band XPC file transfers, so unlike the others it keeps one connection open across the request and the transfers.

Each call opens and closes its own connection, so instances need no `connect()` and are freely reusable.

Requires an iOS 17+ RSD tunnel.

Source code in `pymobiledevice3/services/cryptexd.py`

```
class CryptexdService(RemoteService):
    """
    Query ``cryptexd`` over RemoteXPC (``com.apple.security.cryptexd.remote``).

    The service takes ``{"routine": <name>, "argv": {...}}`` requests and answers with either
    ``{"error": 0, "argv": <result>}`` on success or ``{"cferr": {...}}`` on failure, where
    ``error`` is a device-side Darwin errno.

    All six routines the daemon dispatches are implemented: ``read-personalization-id``,
    ``copy-installed``, ``get-nonce``, ``roll-nonce``, ``uninstall`` and ``install``. The last one
    delivers its payloads as out-of-band XPC file transfers, so unlike the others it keeps one
    connection open across the request and the transfers.

    Each call opens and closes its own connection, so instances need no ``connect()`` and are
    freely reusable.

    Requires an iOS 17+ RSD tunnel.
    """

    SERVICE_NAME = "com.apple.security.cryptexd.remote"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def connect(self) -> None:
        """No-op: `invoke` manages its own connection."""

    async def close(self) -> None:
        """No-op: `invoke` closes the connection it opened."""

    async def invoke(self, routine: str, argv: dict[str, Any]) -> Any:
        """
        Send a single ``routine`` request on a fresh connection and return its ``argv`` payload.

        :param routine: routine name, e.g. ``read-personalization-id``.
        :param argv: named arguments for the routine.
        :raises CryptexdError: if the daemon answered with a ``cferr`` or a non-zero ``error``.
        """
        connection = self.rsd.start_remote_service(self.SERVICE_NAME)
        await connection.connect()
        try:
            response = await connection.send_receive_request({"routine": routine, "argv": argv})
        finally:
            await connection.close()
        return self._unwrap(routine, response)

    @staticmethod
    def _unwrap(routine: str, response: dict[str, Any]) -> Any:
        """Raise on a failed reply, otherwise return its ``argv`` payload."""
        cferr: Optional[dict[str, Any]] = response.get("cferr")
        if cferr is not None:
            user_info: dict[str, Any] = cferr.get("cferr_userinfo") or {}
            raise CryptexdError(
                f"{routine} failed: {user_info.get('NSLocalizedDescription', cferr)} "
                f"({cferr.get('cferr_domain')}: {cferr.get('cferr_code')})"
            )
        # Successful replies carry error=0; read-personalization-id omits the key entirely.
        error = response.get("error", 0)
        if error:
            raise CryptexdError(f"{routine} failed: {describe_errno(error)}")
        return response.get("argv")

    async def install(
        self,
        image: bytes,
        trustcache: bytes,
        im4m: bytes,
        info: bytes,
        volumehash: bytes,
        cryptex1_properties: dict[str, Any],
        image_type_index: int = CryptexAssetType.GDMG,
        persistence: int = DDI_PERSISTENCE,
        nonce_persistence: int = DDI_NONCE_PERSISTENCE,
        auth: int = 0,
    ) -> None:
        """
        Install a cryptex.

        The five payloads are announced in the request as XPC file transfers and then pushed on
        their own streams; the daemon only replies once it has consumed all of them.

        The request shape mirrors what Xcode sends, captured off the wire during a
        ``devicectl`` DDI install. Two details are easy to get wrong: the cryptex is identified
        solely by `info` (a ``CryptexInfoPlist``) — there is no identifier argument, and omitting
        it makes the daemon log every line as ``[anonymous]`` — and the integers inside
        `cryptex1_properties` must be **uint64**, since int64 is rejected with
        ``Cryptex1,NonceDomain [79: Inappropriate file type or format]``.

        The `im4m` must be a *Cryptex1* ticket bound to the current nonce of the identity's
        ``Cryptex1,NonceDomain`` — see `TSSRequest.add_cryptex1_tags`. A ticket personalized
        against any other nonce is rejected while importing the first asset, which the device
        reports as ``invalid asset: ginf`` and logs as
        ``Manifest no longer valid [70: Stale NFS file handle]``.

        :param image: the cryptex disk image, i.e. the build manifest's ``Cryptex1,GenericDmg``.
        :param trustcache: ``Cryptex1,GenericTrustCache``.
        :param im4m: the Cryptex1 personalization ticket.
        :param info: ``Cryptex1,CryptexInfoPlist``; names and versions the cryptex.
        :param volumehash: ``Cryptex1,GenericVolume`` root hash; without it the daemon reports
            "AuthAPFS will not be supported".
        :param cryptex1_properties: the ``Cryptex1,*`` parameters from the build identity.
        :param image_type_index: the image's `CryptexAssetType`.
        :param persistence: cryptex persistence mode.
        :param nonce_persistence: nonce persistence mode.
        :param auth: authentication mode.
        :raises CryptexdError: if the daemon rejected the request, the install failed, or the daemon
            closed the connection or sent no reply within `INSTALL_REPLY_TIMEOUT` seconds.
        :raises DeviceFeatureNotSupportedError: if the device does not advertise the
            ``CryptexInstall`` capability.
        """
        self.rsd.require_feature(self.SERVICE_NAME, FEATURE_CRYPTEX_INSTALL)
        transfers = [
            ("image", image),
            ("trustcache", trustcache),
            ("im4m", im4m),
            ("info", info),
            ("volumehash", volumehash),
        ]
        argv: dict[str, Any] = {
            "auth": XpcUInt64Type(auth),
            "client-version": XpcUInt64Type(CLIENT_VERSION),
            "cryptex1-properties": cryptex1_properties,
            "image-type-index": XpcInt64Type(image_type_index),
            "nonce-persistence": XpcUInt64Type(nonce_persistence),
            "persistence": XpcUInt64Type(persistence),
        }
        for transfer_id, (key, payload) in enumerate(transfers, start=1):
            argv[key] = FileTransferType(transfer_size=len(payload), transfer_id=transfer_id)

        connection = self.rsd.start_remote_service(self.SERVICE_NAME)
        await connection.connect()
        try:
            await connection.send_request({"routine": "install", "argv": argv}, wanting_reply=True)
            for transfer_id, (_, payload) in enumerate(transfers, start=1):
                await connection.send_file_transfer(transfer_id, payload)
            response = await asyncio.wait_for(connection.receive_response(), INSTALL_REPLY_TIMEOUT)
        except asyncio.TimeoutError as e:
            raise CryptexdError(
                f"install failed: cryptexd did not reply within {INSTALL_REPLY_TIMEOUT} seconds of receiving "
                "the payloads, so it most likely failed without replying; "
                "`pymobiledevice3 syslog live -m cryptexd` shows why"
            ) from e
        except ConnectionTerminatedError as e:
            raise CryptexdError(
                "install failed: cryptexd closed the connection without replying, so it most likely "
                "rejected or crashed on the request; `pymobiledevice3 syslog live -m cryptexd` shows why"
            ) from e
        finally:
            await connection.close()
        self._unwrap("install", response)

    @staticmethod
    def _nonce_selector(nonce_domain: Optional[int], nonce_domain_handle: Optional[int]) -> dict[str, Any]:
        """Build the argv selecting a nonce domain, by index or by handle.

        The daemon accepts either form and reports them separately ("nonce domain doesn't exist for
        index: ..." versus "... for handle: ...").
        """
        if nonce_domain is not None and nonce_domain_handle is not None:
            raise ValueError("pass either nonce_domain or nonce_domain_handle, not both")
        if nonce_domain_handle is not None:
            return {"nonce-domain-handle": XpcUInt64Type(nonce_domain_handle)}
        domain = NonceDomain.PDI if nonce_domain is None else nonce_domain
        return {"nonce-domain": XpcUInt64Type(domain)}

    async def cryptex_nonce(self, nonce_domain_handle: int) -> bytes:
        """Read a nonce domain's nonce, unwrapped from the daemon's nonce structure.

        .. note::
            The selector is a **handle**, which is what a build identity's ``Cryptex1,NonceDomain``
            holds — not an index. The two tables overlap but disagree: on an iPhone 11 the DDI
            cryptex nonce is handle 4, which is index 10, while index 4 is an unrelated domain.
            Personalizing against the index-4 nonce produces a ticket the device rejects at import
            with ``Manifest no longer valid [70: Stale NFS file handle]``.

        :param nonce_domain_handle: handle of the nonce domain, e.g. a ``Cryptex1,NonceDomain``.
        """
        return unwrap_nonce(await self.get_nonce(nonce_domain_handle=nonce_domain_handle))

    async def auto_install_ddi(self, restore_dir: Optional[Path] = None) -> InstalledCryptex:
        """
        Personalize and install the DeveloperDiskImage cryptex entirely through ``cryptexd``.

        This is the cryptex equivalent of the image mounter's ``auto-mount``: it assembles the
        payloads, reads the device's personalization identifiers and cryptex nonce, has Apple sign
        a Cryptex1 ticket for them, and installs the result — all over ``cryptexd``, without the
        image mounter.

        :param restore_dir: an unpacked DDI ``Restore`` directory; defaults to the cached download
            from the DeveloperDiskImage repository, so no Xcode installation is required.
        :returns: the installed cryptex, as reported back by `copy_installed`.
        :raises AlreadyMountedError: if a Personalized image is already mounted, be it the DDI
            cryptex or one the image mounter mounted. A DDI cryptex that is installed but no
            longer mounted is replaced instead.
        :raises CryptexdError: if the daemon rejected the image.
        :raises TSSError: if Apple refused to sign the personalization request.
        :raises DeviceFeatureNotSupportedError: below `DDI_CRYPTEX_MIN_VERSION`.
        """
        # Before asking Apple to sign anything the device cannot mount
        require_ddi_cryptex_support(self.rsd.product_version, self.rsd.udid)
        already_installed = await self._installed_ddi()
        mounted = await self._ddi_mounted_by_image_mounter()
        if already_installed is not None and mounted:
            raise AlreadyMountedError(
                f"The {already_installed.identifier} {already_installed.version} cryptex is already installed."
            )
        if mounted:
            raise AlreadyMountedError("A Personalized developer disk image is already mounted by the image mounter.")
        if already_installed is not None:
            # The image mounter can unmount a cryptex's image (`mounter umount-personalized`) while
            # cryptexd keeps the cryptex installed: nothing is at /System/Developer, yet installing
            # over it fails with EEXIST. Observed on iPhone19,4 27.2.1.
            logger.warning(
                f"The {already_installed.identifier} {already_installed.version} cryptex is installed but its "
                "image is not mounted; uninstalling it to install it again"
            )
            await self.uninstall(already_installed.identifier)

        assets = load_cryptex1_assets(restore_dir)
        request = TSSRequest()
        request.add_cryptex1_tags(
            assets.build_identity,
            await self.read_personalization_identifiers(),
            await self.cryptex_nonce(assets.nonce_domain),
        )
        response = await request.send_receive()
        im4m = response.get("Cryptex1,Ticket") or response["ApImg4Ticket"]

        await self.install(
            assets.image,
            assets.trustcache,
            im4m,
            assets.info,
            assets.volumehash,
            assets.cryptex1_properties,
        )
        ddi = await self._installed_ddi()
        if ddi is None:
            raise CryptexdError(f"install reported success but {DDI_CRYPTEX_IDENTIFIER} is not installed")
        return ddi

    async def _ddi_mounted_by_image_mounter(self) -> bool:
        """Whether the image mounter reports a Personalized image mounted at ``/System/Developer``.

        It reports the DDI cryptex while that is mounted, and also an image it mounted itself. The
        latter is not a cryptex, so `copy_installed` does not report it, yet it holds the mount
        path the DDI cryptex needs: installing over it fails with
        ``mkdir custom mount path: /System/Developer [17: File exists]``.
        """
        async with PersonalizedImageMounter(lockdown=self.rsd) as mounter:
            return await mounter.is_image_mounted(PersonalizedImageMounter.IMAGE_TYPE)

    async def uninstall_ddi(self) -> Optional[InstalledCryptex]:
        """
        Uninstall the DeveloperDiskImage cryptex, if one is installed.

        :returns: the cryptex that was uninstalled, or ``None`` if none was installed.
        :raises CryptexdError: if removal failed.
        """
        installed = await self._installed_ddi()
        if installed is not None:
            await self.uninstall(installed.identifier)
        return installed

    async def _installed_ddi(self) -> Optional[InstalledCryptex]:
        """Return the installed DeveloperDiskImage cryptex, or ``None`` if there is none."""
        installed = await self.copy_installed()
        return next((cryptex for cryptex in installed if cryptex.identifier == DDI_CRYPTEX_IDENTIFIER), None)

    async def read_personalization_identifiers(self) -> dict[str, Any]:
        """
        Read the device's AppleImage4 chip instance, used to personalize a cryptex.

        The returned mapping uses the daemon's ``img4_chip_*`` key names, e.g. ``img4_chip_chip``
        (ChipID), ``img4_chip_bord`` (BoardID) and ``img4_chip_ecid`` (ECID).

        :raises DeviceFeatureNotSupportedError: if the device does not advertise the
            ``ReadIdentifiers`` capability.
        """
        self.rsd.require_feature(self.SERVICE_NAME, FEATURE_READ_IDENTIFIERS)
        return await self.invoke("read-personalization-id", {})

    async def copy_installed(self) -> list[InstalledCryptex]:
        """
        List the cryptexes currently installed on the device.

        On a device with a mounted personalized DeveloperDiskImage this reports
        ``com.apple.MobileAsset.DDI`` together with its version.
        """
        argv: dict[str, Any] = await self.invoke("copy-installed", {}) or {}
        entries: list[dict[str, Any]] = argv.get("remote-cryptex-array", [])
        return [
            InstalledCryptex(
                identifier=entry["remote-cryptex-identifier"],
                version=entry["remote-cryptex-version"],
            )
            for entry in entries
        ]

    async def get_nonce(self, nonce_domain: Optional[int] = None, nonce_domain_handle: Optional[int] = None) -> bytes:
        """
        Read the nonce for a nonce domain.

        The returned blob is the nonce structure, not the bare nonce: on current devices it is
        56 bytes carrying the 48-byte nonce at offset 2. `MobileImageMounterService.query_nonce`
        returns those 48 bytes alone.

        :param nonce_domain: index into the daemon's nonce-domain table; defaults to
                             `NonceDomain.PDI` when neither selector is given.
        :param nonce_domain_handle: handle of the nonce domain, as an alternative to `nonce_domain`.
        :raises ValueError: if both selectors are given.
        :raises CryptexdError: if the domain does not exist or has no nonce.
        """
        argv = await self.invoke("get-nonce", self._nonce_selector(nonce_domain, nonce_domain_handle))
        return argv["nonce"]

    async def roll_nonce(self, nonce_domain: Optional[int] = None, nonce_domain_handle: Optional[int] = None) -> None:
        """
        Roll (regenerate) the nonce for a nonce domain.

        This invalidates anything personalized against the previous nonce — notably a mounted
        personalized DeveloperDiskImage, which must be re-personalized and re-mounted afterwards.

        .. warning::
            Unverified: no argv shape found so far actually rolls the nonce. Placing the selector
            in ``argv`` (which is where ``get-nonce`` reads it, and where uint64 works) fails with
            ``key nonce-domain doesn't exist``; placing it at the top level of the request returns
            a reply with no error but leaves the nonce unchanged. The daemon reads it from
            somewhere else again — ``_sub_remote_service_demux`` fetches both selectors with
            ``xpc_dictionary_get_uint64``, so the type is right and only the location is wrong.

        :param nonce_domain: index into the daemon's nonce-domain table; defaults to
                             `NonceDomain.PDI` when neither selector is given.
        :param nonce_domain_handle: handle of the nonce domain, as an alternative to `nonce_domain`.
        :raises ValueError: if both selectors are given.
        :raises CryptexdError: if the domain does not exist or the roll failed.
        """
        await self.invoke("roll-nonce", self._nonce_selector(nonce_domain, nonce_domain_handle))

    async def uninstall(self, identifier: str, version: Optional[str] = None) -> None:
        """
        Uninstall an installed cryptex.

        :param identifier: cryptex identifier as reported by `copy_installed`, e.g.
                           ``com.apple.MobileAsset.DDI``.
        :param version: optional version to scope the removal to.
        :raises CryptexdError: if no such cryptex is installed (``errno 2``) or removal failed.
        :raises DeviceFeatureNotSupportedError: if the device does not advertise the
            ``CryptexInstall`` capability.
        """
        self.rsd.require_feature(self.SERVICE_NAME, FEATURE_CRYPTEX_INSTALL)
        argv: dict[str, Any] = {"remote-cryptex-identifier": identifier}
        if version is not None:
            argv["remote-cryptex-version"] = version
        await self.invoke("uninstall", argv)
```

### connect

```
connect() -> None
```

No-op: `invoke` manages its own connection.

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def connect(self) -> None:
    """No-op: `invoke` manages its own connection."""
```

### close

```
close() -> None
```

No-op: `invoke` closes the connection it opened.

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def close(self) -> None:
    """No-op: `invoke` closes the connection it opened."""
```

### invoke

```
invoke(routine: str, argv: dict[str, Any]) -> Any
```

Send a single `routine` request on a fresh connection and return its `argv` payload.

Parameters:

| Name      | Type             | Description                                 | Default    |
| --------- | ---------------- | ------------------------------------------- | ---------- |
| `routine` | `str`            | routine name, e.g. read-personalization-id. | *required* |
| `argv`    | `dict[str, Any]` | named arguments for the routine.            | *required* |

Raises:

| Type            | Description                                              |
| --------------- | -------------------------------------------------------- |
| `CryptexdError` | if the daemon answered with a cferr or a non-zero error. |

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def invoke(self, routine: str, argv: dict[str, Any]) -> Any:
    """
    Send a single ``routine`` request on a fresh connection and return its ``argv`` payload.

    :param routine: routine name, e.g. ``read-personalization-id``.
    :param argv: named arguments for the routine.
    :raises CryptexdError: if the daemon answered with a ``cferr`` or a non-zero ``error``.
    """
    connection = self.rsd.start_remote_service(self.SERVICE_NAME)
    await connection.connect()
    try:
        response = await connection.send_receive_request({"routine": routine, "argv": argv})
    finally:
        await connection.close()
    return self._unwrap(routine, response)
```

### install

```
install(image: bytes, trustcache: bytes, im4m: bytes, info: bytes, volumehash: bytes, cryptex1_properties: dict[str, Any], image_type_index: int = CryptexAssetType.GDMG, persistence: int = DDI_PERSISTENCE, nonce_persistence: int = DDI_NONCE_PERSISTENCE, auth: int = 0) -> None
```

Install a cryptex.

The five payloads are announced in the request as XPC file transfers and then pushed on their own streams; the daemon only replies once it has consumed all of them.

The request shape mirrors what Xcode sends, captured off the wire during a `devicectl` DDI install. Two details are easy to get wrong: the cryptex is identified solely by `info` (a `CryptexInfoPlist`) — there is no identifier argument, and omitting it makes the daemon log every line as `[anonymous]` — and the integers inside `cryptex1_properties` must be **uint64**, since int64 is rejected with `Cryptex1,NonceDomain [79: Inappropriate file type or format]`.

The `im4m` must be a *Cryptex1* ticket bound to the current nonce of the identity's `Cryptex1,NonceDomain` — see `TSSRequest.add_cryptex1_tags`. A ticket personalized against any other nonce is rejected while importing the first asset, which the device reports as `invalid asset: ginf` and logs as `Manifest no longer valid [70: Stale NFS file handle]`.

Parameters:

| Name                  | Type             | Description                                                                                       | Default                 |
| --------------------- | ---------------- | ------------------------------------------------------------------------------------------------- | ----------------------- |
| `image`               | `bytes`          | the cryptex disk image, i.e. the build manifest's Cryptex1,GenericDmg.                            | *required*              |
| `trustcache`          | `bytes`          | Cryptex1,GenericTrustCache.                                                                       | *required*              |
| `im4m`                | `bytes`          | the Cryptex1 personalization ticket.                                                              | *required*              |
| `info`                | `bytes`          | Cryptex1,CryptexInfoPlist; names and versions the cryptex.                                        | *required*              |
| `volumehash`          | `bytes`          | Cryptex1,GenericVolume root hash; without it the daemon reports "AuthAPFS will not be supported". | *required*              |
| `cryptex1_properties` | `dict[str, Any]` | the Cryptex1,\* parameters from the build identity.                                               | *required*              |
| `image_type_index`    | `int`            | the image's CryptexAssetType.                                                                     | `GDMG`                  |
| `persistence`         | `int`            | cryptex persistence mode.                                                                         | `DDI_PERSISTENCE`       |
| `nonce_persistence`   | `int`            | nonce persistence mode.                                                                           | `DDI_NONCE_PERSISTENCE` |
| `auth`                | `int`            | authentication mode.                                                                              | `0`                     |

Raises:

| Type                             | Description                                                                                                                                        |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CryptexdError`                  | if the daemon rejected the request, the install failed, or the daemon closed the connection or sent no reply within INSTALL_REPLY_TIMEOUT seconds. |
| `DeviceFeatureNotSupportedError` | if the device does not advertise the CryptexInstall capability.                                                                                    |

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def install(
    self,
    image: bytes,
    trustcache: bytes,
    im4m: bytes,
    info: bytes,
    volumehash: bytes,
    cryptex1_properties: dict[str, Any],
    image_type_index: int = CryptexAssetType.GDMG,
    persistence: int = DDI_PERSISTENCE,
    nonce_persistence: int = DDI_NONCE_PERSISTENCE,
    auth: int = 0,
) -> None:
    """
    Install a cryptex.

    The five payloads are announced in the request as XPC file transfers and then pushed on
    their own streams; the daemon only replies once it has consumed all of them.

    The request shape mirrors what Xcode sends, captured off the wire during a
    ``devicectl`` DDI install. Two details are easy to get wrong: the cryptex is identified
    solely by `info` (a ``CryptexInfoPlist``) — there is no identifier argument, and omitting
    it makes the daemon log every line as ``[anonymous]`` — and the integers inside
    `cryptex1_properties` must be **uint64**, since int64 is rejected with
    ``Cryptex1,NonceDomain [79: Inappropriate file type or format]``.

    The `im4m` must be a *Cryptex1* ticket bound to the current nonce of the identity's
    ``Cryptex1,NonceDomain`` — see `TSSRequest.add_cryptex1_tags`. A ticket personalized
    against any other nonce is rejected while importing the first asset, which the device
    reports as ``invalid asset: ginf`` and logs as
    ``Manifest no longer valid [70: Stale NFS file handle]``.

    :param image: the cryptex disk image, i.e. the build manifest's ``Cryptex1,GenericDmg``.
    :param trustcache: ``Cryptex1,GenericTrustCache``.
    :param im4m: the Cryptex1 personalization ticket.
    :param info: ``Cryptex1,CryptexInfoPlist``; names and versions the cryptex.
    :param volumehash: ``Cryptex1,GenericVolume`` root hash; without it the daemon reports
        "AuthAPFS will not be supported".
    :param cryptex1_properties: the ``Cryptex1,*`` parameters from the build identity.
    :param image_type_index: the image's `CryptexAssetType`.
    :param persistence: cryptex persistence mode.
    :param nonce_persistence: nonce persistence mode.
    :param auth: authentication mode.
    :raises CryptexdError: if the daemon rejected the request, the install failed, or the daemon
        closed the connection or sent no reply within `INSTALL_REPLY_TIMEOUT` seconds.
    :raises DeviceFeatureNotSupportedError: if the device does not advertise the
        ``CryptexInstall`` capability.
    """
    self.rsd.require_feature(self.SERVICE_NAME, FEATURE_CRYPTEX_INSTALL)
    transfers = [
        ("image", image),
        ("trustcache", trustcache),
        ("im4m", im4m),
        ("info", info),
        ("volumehash", volumehash),
    ]
    argv: dict[str, Any] = {
        "auth": XpcUInt64Type(auth),
        "client-version": XpcUInt64Type(CLIENT_VERSION),
        "cryptex1-properties": cryptex1_properties,
        "image-type-index": XpcInt64Type(image_type_index),
        "nonce-persistence": XpcUInt64Type(nonce_persistence),
        "persistence": XpcUInt64Type(persistence),
    }
    for transfer_id, (key, payload) in enumerate(transfers, start=1):
        argv[key] = FileTransferType(transfer_size=len(payload), transfer_id=transfer_id)

    connection = self.rsd.start_remote_service(self.SERVICE_NAME)
    await connection.connect()
    try:
        await connection.send_request({"routine": "install", "argv": argv}, wanting_reply=True)
        for transfer_id, (_, payload) in enumerate(transfers, start=1):
            await connection.send_file_transfer(transfer_id, payload)
        response = await asyncio.wait_for(connection.receive_response(), INSTALL_REPLY_TIMEOUT)
    except asyncio.TimeoutError as e:
        raise CryptexdError(
            f"install failed: cryptexd did not reply within {INSTALL_REPLY_TIMEOUT} seconds of receiving "
            "the payloads, so it most likely failed without replying; "
            "`pymobiledevice3 syslog live -m cryptexd` shows why"
        ) from e
    except ConnectionTerminatedError as e:
        raise CryptexdError(
            "install failed: cryptexd closed the connection without replying, so it most likely "
            "rejected or crashed on the request; `pymobiledevice3 syslog live -m cryptexd` shows why"
        ) from e
    finally:
        await connection.close()
    self._unwrap("install", response)
```

### cryptex_nonce

```
cryptex_nonce(nonce_domain_handle: int) -> bytes
```

Read a nonce domain's nonce, unwrapped from the daemon's nonce structure.

.. note:: The selector is a **handle**, which is what a build identity's `Cryptex1,NonceDomain` holds — not an index. The two tables overlap but disagree: on an iPhone 11 the DDI cryptex nonce is handle 4, which is index 10, while index 4 is an unrelated domain. Personalizing against the index-4 nonce produces a ticket the device rejects at import with `Manifest no longer valid [70: Stale NFS file handle]`.

Parameters:

| Name                  | Type  | Description                                              | Default    |
| --------------------- | ----- | -------------------------------------------------------- | ---------- |
| `nonce_domain_handle` | `int` | handle of the nonce domain, e.g. a Cryptex1,NonceDomain. | *required* |

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def cryptex_nonce(self, nonce_domain_handle: int) -> bytes:
    """Read a nonce domain's nonce, unwrapped from the daemon's nonce structure.

    .. note::
        The selector is a **handle**, which is what a build identity's ``Cryptex1,NonceDomain``
        holds — not an index. The two tables overlap but disagree: on an iPhone 11 the DDI
        cryptex nonce is handle 4, which is index 10, while index 4 is an unrelated domain.
        Personalizing against the index-4 nonce produces a ticket the device rejects at import
        with ``Manifest no longer valid [70: Stale NFS file handle]``.

    :param nonce_domain_handle: handle of the nonce domain, e.g. a ``Cryptex1,NonceDomain``.
    """
    return unwrap_nonce(await self.get_nonce(nonce_domain_handle=nonce_domain_handle))
```

### auto_install_ddi

```
auto_install_ddi(restore_dir: Optional[Path] = None) -> InstalledCryptex
```

Personalize and install the DeveloperDiskImage cryptex entirely through `cryptexd`.

This is the cryptex equivalent of the image mounter's `auto-mount`: it assembles the payloads, reads the device's personalization identifiers and cryptex nonce, has Apple sign a Cryptex1 ticket for them, and installs the result — all over `cryptexd`, without the image mounter.

Parameters:

| Name          | Type             | Description                                                                                                                                      | Default |
| ------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------- |
| `restore_dir` | `Optional[Path]` | an unpacked DDI Restore directory; defaults to the cached download from the DeveloperDiskImage repository, so no Xcode installation is required. | `None`  |

Returns:

| Type               | Description                                                |
| ------------------ | ---------------------------------------------------------- |
| `InstalledCryptex` | the installed cryptex, as reported back by copy_installed. |

Raises:

| Type                             | Description                                                                                                                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `AlreadyMountedError`            | if a Personalized image is already mounted, be it the DDI cryptex or one the image mounter mounted. A DDI cryptex that is installed but no longer mounted is replaced instead. |
| `CryptexdError`                  | if the daemon rejected the image.                                                                                                                                              |
| `TSSError`                       | if Apple refused to sign the personalization request.                                                                                                                          |
| `DeviceFeatureNotSupportedError` | below DDI_CRYPTEX_MIN_VERSION.                                                                                                                                                 |

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def auto_install_ddi(self, restore_dir: Optional[Path] = None) -> InstalledCryptex:
    """
    Personalize and install the DeveloperDiskImage cryptex entirely through ``cryptexd``.

    This is the cryptex equivalent of the image mounter's ``auto-mount``: it assembles the
    payloads, reads the device's personalization identifiers and cryptex nonce, has Apple sign
    a Cryptex1 ticket for them, and installs the result — all over ``cryptexd``, without the
    image mounter.

    :param restore_dir: an unpacked DDI ``Restore`` directory; defaults to the cached download
        from the DeveloperDiskImage repository, so no Xcode installation is required.
    :returns: the installed cryptex, as reported back by `copy_installed`.
    :raises AlreadyMountedError: if a Personalized image is already mounted, be it the DDI
        cryptex or one the image mounter mounted. A DDI cryptex that is installed but no
        longer mounted is replaced instead.
    :raises CryptexdError: if the daemon rejected the image.
    :raises TSSError: if Apple refused to sign the personalization request.
    :raises DeviceFeatureNotSupportedError: below `DDI_CRYPTEX_MIN_VERSION`.
    """
    # Before asking Apple to sign anything the device cannot mount
    require_ddi_cryptex_support(self.rsd.product_version, self.rsd.udid)
    already_installed = await self._installed_ddi()
    mounted = await self._ddi_mounted_by_image_mounter()
    if already_installed is not None and mounted:
        raise AlreadyMountedError(
            f"The {already_installed.identifier} {already_installed.version} cryptex is already installed."
        )
    if mounted:
        raise AlreadyMountedError("A Personalized developer disk image is already mounted by the image mounter.")
    if already_installed is not None:
        # The image mounter can unmount a cryptex's image (`mounter umount-personalized`) while
        # cryptexd keeps the cryptex installed: nothing is at /System/Developer, yet installing
        # over it fails with EEXIST. Observed on iPhone19,4 27.2.1.
        logger.warning(
            f"The {already_installed.identifier} {already_installed.version} cryptex is installed but its "
            "image is not mounted; uninstalling it to install it again"
        )
        await self.uninstall(already_installed.identifier)

    assets = load_cryptex1_assets(restore_dir)
    request = TSSRequest()
    request.add_cryptex1_tags(
        assets.build_identity,
        await self.read_personalization_identifiers(),
        await self.cryptex_nonce(assets.nonce_domain),
    )
    response = await request.send_receive()
    im4m = response.get("Cryptex1,Ticket") or response["ApImg4Ticket"]

    await self.install(
        assets.image,
        assets.trustcache,
        im4m,
        assets.info,
        assets.volumehash,
        assets.cryptex1_properties,
    )
    ddi = await self._installed_ddi()
    if ddi is None:
        raise CryptexdError(f"install reported success but {DDI_CRYPTEX_IDENTIFIER} is not installed")
    return ddi
```

### uninstall_ddi

```
uninstall_ddi() -> Optional[InstalledCryptex]
```

Uninstall the DeveloperDiskImage cryptex, if one is installed.

Returns:

| Type                         | Description                                                      |
| ---------------------------- | ---------------------------------------------------------------- |
| `Optional[InstalledCryptex]` | the cryptex that was uninstalled, or None if none was installed. |

Raises:

| Type            | Description        |
| --------------- | ------------------ |
| `CryptexdError` | if removal failed. |

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def uninstall_ddi(self) -> Optional[InstalledCryptex]:
    """
    Uninstall the DeveloperDiskImage cryptex, if one is installed.

    :returns: the cryptex that was uninstalled, or ``None`` if none was installed.
    :raises CryptexdError: if removal failed.
    """
    installed = await self._installed_ddi()
    if installed is not None:
        await self.uninstall(installed.identifier)
    return installed
```

### read_personalization_identifiers

```
read_personalization_identifiers() -> dict[str, Any]
```

Read the device's AppleImage4 chip instance, used to personalize a cryptex.

The returned mapping uses the daemon's `img4_chip_*` key names, e.g. `img4_chip_chip` (ChipID), `img4_chip_bord` (BoardID) and `img4_chip_ecid` (ECID).

Raises:

| Type                             | Description                                                      |
| -------------------------------- | ---------------------------------------------------------------- |
| `DeviceFeatureNotSupportedError` | if the device does not advertise the ReadIdentifiers capability. |

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def read_personalization_identifiers(self) -> dict[str, Any]:
    """
    Read the device's AppleImage4 chip instance, used to personalize a cryptex.

    The returned mapping uses the daemon's ``img4_chip_*`` key names, e.g. ``img4_chip_chip``
    (ChipID), ``img4_chip_bord`` (BoardID) and ``img4_chip_ecid`` (ECID).

    :raises DeviceFeatureNotSupportedError: if the device does not advertise the
        ``ReadIdentifiers`` capability.
    """
    self.rsd.require_feature(self.SERVICE_NAME, FEATURE_READ_IDENTIFIERS)
    return await self.invoke("read-personalization-id", {})
```

### copy_installed

```
copy_installed() -> list[InstalledCryptex]
```

List the cryptexes currently installed on the device.

On a device with a mounted personalized DeveloperDiskImage this reports `com.apple.MobileAsset.DDI` together with its version.

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def copy_installed(self) -> list[InstalledCryptex]:
    """
    List the cryptexes currently installed on the device.

    On a device with a mounted personalized DeveloperDiskImage this reports
    ``com.apple.MobileAsset.DDI`` together with its version.
    """
    argv: dict[str, Any] = await self.invoke("copy-installed", {}) or {}
    entries: list[dict[str, Any]] = argv.get("remote-cryptex-array", [])
    return [
        InstalledCryptex(
            identifier=entry["remote-cryptex-identifier"],
            version=entry["remote-cryptex-version"],
        )
        for entry in entries
    ]
```

### get_nonce

```
get_nonce(nonce_domain: Optional[int] = None, nonce_domain_handle: Optional[int] = None) -> bytes
```

Read the nonce for a nonce domain.

The returned blob is the nonce structure, not the bare nonce: on current devices it is 56 bytes carrying the 48-byte nonce at offset 2. `MobileImageMounterService.query_nonce` returns those 48 bytes alone.

Parameters:

| Name                  | Type            | Description                                                                                             | Default |
| --------------------- | --------------- | ------------------------------------------------------------------------------------------------------- | ------- |
| `nonce_domain`        | `Optional[int]` | index into the daemon's nonce-domain table; defaults to NonceDomain.PDI when neither selector is given. | `None`  |
| `nonce_domain_handle` | `Optional[int]` | handle of the nonce domain, as an alternative to nonce_domain.                                          | `None`  |

Raises:

| Type            | Description                                   |
| --------------- | --------------------------------------------- |
| `ValueError`    | if both selectors are given.                  |
| `CryptexdError` | if the domain does not exist or has no nonce. |

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def get_nonce(self, nonce_domain: Optional[int] = None, nonce_domain_handle: Optional[int] = None) -> bytes:
    """
    Read the nonce for a nonce domain.

    The returned blob is the nonce structure, not the bare nonce: on current devices it is
    56 bytes carrying the 48-byte nonce at offset 2. `MobileImageMounterService.query_nonce`
    returns those 48 bytes alone.

    :param nonce_domain: index into the daemon's nonce-domain table; defaults to
                         `NonceDomain.PDI` when neither selector is given.
    :param nonce_domain_handle: handle of the nonce domain, as an alternative to `nonce_domain`.
    :raises ValueError: if both selectors are given.
    :raises CryptexdError: if the domain does not exist or has no nonce.
    """
    argv = await self.invoke("get-nonce", self._nonce_selector(nonce_domain, nonce_domain_handle))
    return argv["nonce"]
```

### roll_nonce

```
roll_nonce(nonce_domain: Optional[int] = None, nonce_domain_handle: Optional[int] = None) -> None
```

Roll (regenerate) the nonce for a nonce domain.

This invalidates anything personalized against the previous nonce — notably a mounted personalized DeveloperDiskImage, which must be re-personalized and re-mounted afterwards.

.. warning:: Unverified: no argv shape found so far actually rolls the nonce. Placing the selector in `argv` (which is where `get-nonce` reads it, and where uint64 works) fails with `key nonce-domain doesn't exist`; placing it at the top level of the request returns a reply with no error but leaves the nonce unchanged. The daemon reads it from somewhere else again — `_sub_remote_service_demux` fetches both selectors with `xpc_dictionary_get_uint64`, so the type is right and only the location is wrong.

Parameters:

| Name                  | Type            | Description                                                                                             | Default |
| --------------------- | --------------- | ------------------------------------------------------------------------------------------------------- | ------- |
| `nonce_domain`        | `Optional[int]` | index into the daemon's nonce-domain table; defaults to NonceDomain.PDI when neither selector is given. | `None`  |
| `nonce_domain_handle` | `Optional[int]` | handle of the nonce domain, as an alternative to nonce_domain.                                          | `None`  |

Raises:

| Type            | Description                                      |
| --------------- | ------------------------------------------------ |
| `ValueError`    | if both selectors are given.                     |
| `CryptexdError` | if the domain does not exist or the roll failed. |

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def roll_nonce(self, nonce_domain: Optional[int] = None, nonce_domain_handle: Optional[int] = None) -> None:
    """
    Roll (regenerate) the nonce for a nonce domain.

    This invalidates anything personalized against the previous nonce — notably a mounted
    personalized DeveloperDiskImage, which must be re-personalized and re-mounted afterwards.

    .. warning::
        Unverified: no argv shape found so far actually rolls the nonce. Placing the selector
        in ``argv`` (which is where ``get-nonce`` reads it, and where uint64 works) fails with
        ``key nonce-domain doesn't exist``; placing it at the top level of the request returns
        a reply with no error but leaves the nonce unchanged. The daemon reads it from
        somewhere else again — ``_sub_remote_service_demux`` fetches both selectors with
        ``xpc_dictionary_get_uint64``, so the type is right and only the location is wrong.

    :param nonce_domain: index into the daemon's nonce-domain table; defaults to
                         `NonceDomain.PDI` when neither selector is given.
    :param nonce_domain_handle: handle of the nonce domain, as an alternative to `nonce_domain`.
    :raises ValueError: if both selectors are given.
    :raises CryptexdError: if the domain does not exist or the roll failed.
    """
    await self.invoke("roll-nonce", self._nonce_selector(nonce_domain, nonce_domain_handle))
```

### uninstall

```
uninstall(identifier: str, version: Optional[str] = None) -> None
```

Uninstall an installed cryptex.

Parameters:

| Name         | Type            | Description                                                                       | Default    |
| ------------ | --------------- | --------------------------------------------------------------------------------- | ---------- |
| `identifier` | `str`           | cryptex identifier as reported by copy_installed, e.g. com.apple.MobileAsset.DDI. | *required* |
| `version`    | `Optional[str]` | optional version to scope the removal to.                                         | `None`     |

Raises:

| Type                             | Description                                                     |
| -------------------------------- | --------------------------------------------------------------- |
| `CryptexdError`                  | if no such cryptex is installed (errno 2) or removal failed.    |
| `DeviceFeatureNotSupportedError` | if the device does not advertise the CryptexInstall capability. |

Source code in `pymobiledevice3/services/cryptexd.py`

```
async def uninstall(self, identifier: str, version: Optional[str] = None) -> None:
    """
    Uninstall an installed cryptex.

    :param identifier: cryptex identifier as reported by `copy_installed`, e.g.
                       ``com.apple.MobileAsset.DDI``.
    :param version: optional version to scope the removal to.
    :raises CryptexdError: if no such cryptex is installed (``errno 2``) or removal failed.
    :raises DeviceFeatureNotSupportedError: if the device does not advertise the
        ``CryptexInstall`` capability.
    """
    self.rsd.require_feature(self.SERVICE_NAME, FEATURE_CRYPTEX_INSTALL)
    argv: dict[str, Any] = {"remote-cryptex-identifier": identifier}
    if version is not None:
        argv["remote-cryptex-version"] = version
    await self.invoke("uninstall", argv)
```

## pymobiledevice3.services.cryptexd.fetch_cryptex_ddi

```
fetch_cryptex_ddi() -> Path
```

Return a cached Cryptex1 DDI `Restore` directory, downloading it if needed.

The cryptex assets are downloaded from the DeveloperDiskImage repository and cached under the home folder, exactly as `fetch_personalized_ddi` does for the image mounter, so installing a DDI over `cryptexd` needs no Xcode and works on any host. The cache is refreshed when it is missing or when its build id does not match `LATEST_DDI_BUILD_ID`.

Each payload is written to the relative path the downloaded `BuildManifest.plist` declares for it, which makes the cache a `Restore` directory `load_cryptex1_assets` reads directly. A path that would leave the cache directory raises `DevicePathError` before anything is written.

Returns:

| Type   | Description                           |
| ------ | ------------------------------------- |
| `Path` | path to the cached Restore directory. |

Source code in `pymobiledevice3/services/cryptexd.py`

```
def fetch_cryptex_ddi() -> Path:
    """
    Return a cached Cryptex1 DDI ``Restore`` directory, downloading it if needed.

    The cryptex assets are downloaded from the DeveloperDiskImage repository and cached under the
    home folder, exactly as `fetch_personalized_ddi` does for the image mounter, so installing a
    DDI over ``cryptexd`` needs no Xcode and works on any host. The cache is refreshed when it is
    missing or when its build id does not match `LATEST_DDI_BUILD_ID`.

    Each payload is written to the relative path the downloaded ``BuildManifest.plist`` declares
    for it, which makes the cache a `Restore` directory `load_cryptex1_assets` reads directly. A
    path that would leave the cache directory raises `DevicePathError` before anything is written.

    :returns: path to the cached ``Restore`` directory.
    """
    local_path = get_home_folder() / "Xcode_iOS_DDI_Cryptex"
    local_path.mkdir(parents=True, exist_ok=True)
    build_manifest = local_path / "BuildManifest.plist"

    if (
        not build_manifest.exists()
        or plistlib.loads(build_manifest.read_bytes()).get("ProductBuildVersion") != LATEST_DDI_BUILD_ID
    ):
        logger.info("Downloading the Cryptex1 DeveloperDiskImage")
        cryptex_image = DeveloperDiskImageRepository.create().get_cryptex_disk_image()

        identity = _cryptex_build_identity(plistlib.loads(cryptex_image.build_manifest), build_manifest)
        # The manifest is downloaded data: check every destination before writing anything, and
        # write the manifest last so an interrupted download is not mistaken for a complete cache.
        payloads = {
            resolve_device_path(local_path, identity["Manifest"][key]["Info"]["Path"]): getattr(cryptex_image, field)
            for key, field in CRYPTEX1_PAYLOAD_KEYS.items()
        }
        for payload, data in payloads.items():
            payload.parent.mkdir(parents=True, exist_ok=True)
            payload.write_bytes(data)
        build_manifest.write_bytes(cryptex_image.build_manifest)

        downloaded_build_id = plistlib.loads(cryptex_image.build_manifest).get("ProductBuildVersion")
        if downloaded_build_id != LATEST_DDI_BUILD_ID:
            logger.warning(
                f"Downloaded cryptex image has unexpected ProductBuildVersion {downloaded_build_id}. "
                "Please update pymobiledevice3!"
            )
    return local_path
```

## pymobiledevice3.services.cryptexd.InstalledCryptex

A cryptex currently installed on the device (e.g. the mounted DeveloperDiskImage).

Source code in `pymobiledevice3/services/cryptexd.py`

```
@dataclasses.dataclass
class InstalledCryptex:
    """A cryptex currently installed on the device (e.g. the mounted DeveloperDiskImage)."""

    identifier: str
    version: str
```

## pymobiledevice3.services.bt_packet_logger.BtPacketLoggerService

Bases: `LockdownService`

Capture live Bluetooth HCI traffic from the device.

Wraps `com.apple.bluetooth.BTPacketLogger`, which streams Apple PacketLogger records. Use `watch` to iterate the raw records, and `write_to_packetlogger` / `write_to_pcapng` to persist them in a format PacketLogger.app or Wireshark can open.

Source code in `pymobiledevice3/services/bt_packet_logger.py`

```
class BtPacketLoggerService(LockdownService):
    """Capture live Bluetooth HCI traffic from the device.

    Wraps ``com.apple.bluetooth.BTPacketLogger``, which streams Apple PacketLogger records.
    Use `watch` to iterate the raw records, and `write_to_packetlogger` /
    `write_to_pcapng` to persist them in a format PacketLogger.app or Wireshark can open.
    """

    SERVICE_NAME = "com.apple.bluetooth.BTPacketLogger"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown, self.SERVICE_NAME)

    async def watch(self, packets_count: int = -1) -> AsyncGenerator[bytes, None]:
        """Yield raw PacketLogger records as they are captured.

        :param packets_count: Stop after this many records, or -1 to stream forever.
        :return: Generator of raw PacketLogger records (parse with ``parse_packetlogger_record``).
        """
        packet_index = 0
        while packet_index != packets_count:
            packet_length = unpack("<H", await self.service.recvall(SERVICE_PACKET_SIZE_HEADER))[0]
            if packet_length == 0:
                continue
            yield await self.service.recvall(packet_length)
            packet_index += 1

    async def write_to_packetlogger(self, out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
        """Write raw records (e.g. from `watch`) to ``out`` in Apple PacketLogger (.pklg) format.

        :param out: Destination binary stream, flushed after every record.
        :param packet_generator: Source of raw PacketLogger records.
        """
        await write_packetlogger_stream(out, packet_generator)

    async def write_to_pcapng(self, out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
        """Write raw records (e.g. from `watch`) to ``out`` as a pcapng capture Wireshark can open.

        Records are converted to HCI H4 frames (link-type 201, with direction pseudo-header); records
        that don't map to HCI, or are malformed, are skipped. Timestamps are shifted from the device's
        local wall-clock to UTC using the device-reported timezone offset.

        :param out: Destination binary stream, flushed after every packet.
        :param packet_generator: Source of raw PacketLogger records.
        """
        tz_offset_seconds = self.lockdown.all_values.get("TimeZoneOffsetFromUTC") or 0
        await write_pcapng_stream(out, packet_generator, self.lockdown.product_version, tz_offset_seconds)
```

### watch

```
watch(packets_count: int = -1) -> AsyncGenerator[bytes, None]
```

Yield raw PacketLogger records as they are captured.

Parameters:

| Name            | Type  | Description                                            | Default |
| --------------- | ----- | ------------------------------------------------------ | ------- |
| `packets_count` | `int` | Stop after this many records, or -1 to stream forever. | `-1`    |

Returns:

| Type                          | Description                                                                   |
| ----------------------------- | ----------------------------------------------------------------------------- |
| `AsyncGenerator[bytes, None]` | Generator of raw PacketLogger records (parse with parse_packetlogger_record). |

Source code in `pymobiledevice3/services/bt_packet_logger.py`

```
async def watch(self, packets_count: int = -1) -> AsyncGenerator[bytes, None]:
    """Yield raw PacketLogger records as they are captured.

    :param packets_count: Stop after this many records, or -1 to stream forever.
    :return: Generator of raw PacketLogger records (parse with ``parse_packetlogger_record``).
    """
    packet_index = 0
    while packet_index != packets_count:
        packet_length = unpack("<H", await self.service.recvall(SERVICE_PACKET_SIZE_HEADER))[0]
        if packet_length == 0:
            continue
        yield await self.service.recvall(packet_length)
        packet_index += 1
```

### write_to_packetlogger

```
write_to_packetlogger(out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None
```

Write raw records (e.g. from `watch`) to `out` in Apple PacketLogger (.pklg) format.

Parameters:

| Name               | Type                   | Description                                            | Default    |
| ------------------ | ---------------------- | ------------------------------------------------------ | ---------- |
| `out`              | `BinaryIO`             | Destination binary stream, flushed after every record. | *required* |
| `packet_generator` | `AsyncIterable[bytes]` | Source of raw PacketLogger records.                    | *required* |

Source code in `pymobiledevice3/services/bt_packet_logger.py`

```
async def write_to_packetlogger(self, out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
    """Write raw records (e.g. from `watch`) to ``out`` in Apple PacketLogger (.pklg) format.

    :param out: Destination binary stream, flushed after every record.
    :param packet_generator: Source of raw PacketLogger records.
    """
    await write_packetlogger_stream(out, packet_generator)
```

### write_to_pcapng

```
write_to_pcapng(out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None
```

Write raw records (e.g. from `watch`) to `out` as a pcapng capture Wireshark can open.

Records are converted to HCI H4 frames (link-type 201, with direction pseudo-header); records that don't map to HCI, or are malformed, are skipped. Timestamps are shifted from the device's local wall-clock to UTC using the device-reported timezone offset.

Parameters:

| Name               | Type                   | Description                                            | Default    |
| ------------------ | ---------------------- | ------------------------------------------------------ | ---------- |
| `out`              | `BinaryIO`             | Destination binary stream, flushed after every packet. | *required* |
| `packet_generator` | `AsyncIterable[bytes]` | Source of raw PacketLogger records.                    | *required* |

Source code in `pymobiledevice3/services/bt_packet_logger.py`

```
async def write_to_pcapng(self, out: BinaryIO, packet_generator: AsyncIterable[bytes]) -> None:
    """Write raw records (e.g. from `watch`) to ``out`` as a pcapng capture Wireshark can open.

    Records are converted to HCI H4 frames (link-type 201, with direction pseudo-header); records
    that don't map to HCI, or are malformed, are skipped. Timestamps are shifted from the device's
    local wall-clock to UTC using the device-reported timezone offset.

    :param out: Destination binary stream, flushed after every packet.
    :param packet_generator: Source of raw PacketLogger records.
    """
    tz_offset_seconds = self.lockdown.all_values.get("TimeZoneOffsetFromUTC") or 0
    await write_pcapng_stream(out, packet_generator, self.lockdown.product_version, tz_offset_seconds)
```
