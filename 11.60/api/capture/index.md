# Capture, logging & automation

Screenshots, packet capture, the classic syslog relay, and UI automation. (The richer `OsTraceService` log stream lives under [Lockdown services](https://doronz88.github.io/pymobiledevice3/latest/api/services/index.md).)

## pymobiledevice3.services.screenshot.ScreenshotService

Bases: `LockdownService`

Capture a screenshot of the device's screen via the `com.apple.mobile.screenshotr` service.

The service speaks the DeviceLink protocol and requires a developer image (developer mode) to be mounted on the device.

Source code in `pymobiledevice3/services/screenshot.py`

```
class ScreenshotService(LockdownService):
    """
    Capture a screenshot of the device's screen via the ``com.apple.mobile.screenshotr`` service.

    The service speaks the DeviceLink protocol and requires a developer image (developer mode) to be
    mounted on the device.
    """

    SERVICE_NAME = "com.apple.mobile.screenshotr"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown, self.SERVICE_NAME, is_developer_service=True)
        self._did_handshake = False

    async def _handshake(self) -> None:
        if self._did_handshake:
            return
        # DeviceLink messages are list-rooted, unlike the dictionary-rooted request/response
        # services; narrow the received plist accordingly.
        dl_message_version_exchange = cast(list[Any], await self.service.recv_plist())
        version_major = dl_message_version_exchange[1]
        await self.service.send_plist(["DLMessageVersionExchange", "DLVersionsOk", version_major])
        dl_message_device_ready = cast(list[Any], await self.service.recv_plist())
        if dl_message_device_ready[0] != "DLMessageDeviceReady":
            raise ProtocolError("The screenshot service did not report it was ready.")
        self._did_handshake = True

    async def take_screenshot(self) -> bytes:
        """
        Capture the current screen contents.

        Performs the DeviceLink handshake on first use, then requests a single screenshot.

        :returns: Raw image data as returned by the device (typically PNG or TIFF).
        :raises PyMobileDevice3Exception: If the service returns an unexpected response.
        """
        await self._handshake()
        await self.service.send_plist(["DLMessageProcessMessage", {"MessageType": "ScreenShotRequest"}])
        response = cast(list[Any], await self.service.recv_plist())

        assert len(response) == 2
        assert response[0] == "DLMessageProcessMessage"

        if response[1].get("MessageType") == "ScreenShotReply":
            return response[1]["ScreenShotData"]

        raise ProtocolError(f"The screenshot service sent an unexpected reply: {response}")
```

### take_screenshot

```
take_screenshot() -> bytes
```

Capture the current screen contents.

Performs the DeviceLink handshake on first use, then requests a single screenshot.

Returns:

| Type    | Description                                                       |
| ------- | ----------------------------------------------------------------- |
| `bytes` | Raw image data as returned by the device (typically PNG or TIFF). |

Raises:

| Type                       | Description                                    |
| -------------------------- | ---------------------------------------------- |
| `PyMobileDevice3Exception` | If the service returns an unexpected response. |

Source code in `pymobiledevice3/services/screenshot.py`

```
async def take_screenshot(self) -> bytes:
    """
    Capture the current screen contents.

    Performs the DeviceLink handshake on first use, then requests a single screenshot.

    :returns: Raw image data as returned by the device (typically PNG or TIFF).
    :raises PyMobileDevice3Exception: If the service returns an unexpected response.
    """
    await self._handshake()
    await self.service.send_plist(["DLMessageProcessMessage", {"MessageType": "ScreenShotRequest"}])
    response = cast(list[Any], await self.service.recv_plist())

    assert len(response) == 2
    assert response[0] == "DLMessageProcessMessage"

    if response[1].get("MessageType") == "ScreenShotReply":
        return response[1]["ScreenShotData"]

    raise ProtocolError(f"The screenshot service sent an unexpected reply: {response}")
```

## pymobiledevice3.services.pcapd.PcapdService

Bases: `LockdownService`

Capture network traffic from an iOS device.

Starting with iOS 5, Apple added a remote virtual interface (RVI) facility that mirrors the device's network traffic. On macOS the virtual interface is enabled with the `rvictl` command; this service exposes the same capability on other platforms. The service name used depends on the lockdown type (legacy `com.apple.pcapd` for `LockdownClient`, RSD shim otherwise).

Source code in `pymobiledevice3/services/pcapd.py`

```
class PcapdService(LockdownService):
    """
    Capture network traffic from an iOS device.

    Starting with iOS 5, Apple added a remote virtual interface (RVI) facility that mirrors the device's
    network traffic. On macOS the virtual interface is enabled with the ``rvictl`` command; this service
    exposes the same capability on other platforms. The service name used depends on the lockdown type
    (legacy ``com.apple.pcapd`` for `LockdownClient`, RSD shim otherwise).
    """

    RSD_SERVICE_NAME = "com.apple.pcapd.shim.remote"
    SERVICE_NAME = "com.apple.pcapd"

    async def watch(
        self, packets_count: int = -1, process: Optional[str] = None, interface_name: Optional[str] = None
    ) -> AsyncGenerator[DevicePacket, None]:
        """
        Stream captured packets from the device as they arrive.

        Each packet is parsed into its per-packet metadata fields (process pid/name, interface, timing,
        protocol family, etc.) plus the raw frame data. For interfaces that lack a link-layer header
        (and for ``pdp_ip`` cellular packets), a synthetic Ethernet header is prepended to ``data`` so
        the output is valid for standard pcap consumers.

        :param packets_count: Number of packets to yield before stopping; -1 streams indefinitely.
        :param process: If set, only yield packets whose pid (as a string) or process name matches.
        :param interface_name: If set, only yield packets captured on this interface: either its full name
            (``en0``) or its name without the unit number (``en``, matching every unit). pcapd reports the
            two separately, as ``interface_name`` and ``unit``.
        :yields: A parsed `DevicePacket`; ``interface_type`` is an `INTERFACE_NAMES` value and
            ``protocol_family`` a `CrossPlatformAddressFamily` value.
        """
        packet_index = 0
        while packet_index != packets_count:
            d = await self.service.recv_plist()
            if not d:
                break

            packet = parse_device_packet(cast(bytes, d))

            if process is not None and process != str(packet.pid) and process != packet.comm:
                continue

            if interface_name is not None and interface_name not in (
                packet.interface_name,
                f"{packet.interface_name}{packet.unit}",
            ):
                continue

            packet.interface_type = INTERFACE_NAMES(packet.interface_type)
            packet.protocol_family = CrossPlatformAddressFamily(packet.protocol_family)

            if not packet.frame_pre_length:
                # Add fake ethernet header for pdp packets.
                packet.data = ETHERNET_HEADER + packet.data
            elif packet.interface_name == "pdp_ip":
                packet.data = ETHERNET_HEADER + packet.data[4:]

            yield packet

            packet_index += 1

    async def write_to_pcap(self, out: BinaryIO, packet_generator: AsyncIterator[DevicePacket]) -> None:
        """
        Write captured packets to a pcapng stream.

        Consumes an async packet generator (such as `watch`) and writes each packet as an enhanced
        packet block, annotating it with the originating process metadata. Each block carries the
        device's capture time (``seconds``/``microseconds``), or the host's clock if the device sent none.

        :param out: A writable binary file-like object to receive the pcapng data.
        :param packet_generator: Async iterable yielding parsed packets.
        """
        shb: Any = blocks.SectionHeader(
            options={
                "shb_hardware": "artificial",
                "shb_os": "iOS",
                "shb_userappl": "pymobiledevice3",
            }
        )
        shb.new_member(
            blocks.InterfaceDescription,
            link_type=1,
            options={"if_description": "iOS Packet Capture", "if_os": f"iOS {self.lockdown.product_version}"},
        )
        writer: Any = FileWriter(out, shb)

        async for packet in packet_generator:
            if packet.seconds:
                timestamp_microseconds = packet.seconds * 1_000_000 + packet.microseconds
            else:
                timestamp_microseconds = int(time.time() * 1_000_000)
            timestamp_high = (timestamp_microseconds >> 32) & 0xFFFFFFFF
            timestamp_low = timestamp_microseconds & 0xFFFFFFFF

            enhanced_packet = shb.new_member(
                blocks.EnhancedPacket,
                options={
                    "opt_comment": f"PID: {packet.pid}, ProcName: {packet.comm}, EPID: {packet.epid}, "
                    f"EProcName: {packet.ecomm}, SVC: {packet.svc}"
                },
            )

            enhanced_packet.packet_data = packet.data
            enhanced_packet.timestamp_high = timestamp_high
            enhanced_packet.timestamp_low = timestamp_low
            writer.write_block(enhanced_packet)
```

### watch

```
watch(packets_count: int = -1, process: Optional[str] = None, interface_name: Optional[str] = None) -> AsyncGenerator[DevicePacket, None]
```

Stream captured packets from the device as they arrive.

Each packet is parsed into its per-packet metadata fields (process pid/name, interface, timing, protocol family, etc.) plus the raw frame data. For interfaces that lack a link-layer header (and for `pdp_ip` cellular packets), a synthetic Ethernet header is prepended to `data` so the output is valid for standard pcap consumers.

:yields: A parsed `DevicePacket`; `interface_type` is an `INTERFACE_NAMES` value and `protocol_family` a `CrossPlatformAddressFamily` value.

Parameters:

| Name             | Type            | Description                                                                                                                                                                                                    | Default |
| ---------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `packets_count`  | `int`           | Number of packets to yield before stopping; -1 streams indefinitely.                                                                                                                                           | `-1`    |
| `process`        | `Optional[str]` | If set, only yield packets whose pid (as a string) or process name matches.                                                                                                                                    | `None`  |
| `interface_name` | `Optional[str]` | If set, only yield packets captured on this interface: either its full name (en0) or its name without the unit number (en, matching every unit). pcapd reports the two separately, as interface_name and unit. | `None`  |

Source code in `pymobiledevice3/services/pcapd.py`

```
async def watch(
    self, packets_count: int = -1, process: Optional[str] = None, interface_name: Optional[str] = None
) -> AsyncGenerator[DevicePacket, None]:
    """
    Stream captured packets from the device as they arrive.

    Each packet is parsed into its per-packet metadata fields (process pid/name, interface, timing,
    protocol family, etc.) plus the raw frame data. For interfaces that lack a link-layer header
    (and for ``pdp_ip`` cellular packets), a synthetic Ethernet header is prepended to ``data`` so
    the output is valid for standard pcap consumers.

    :param packets_count: Number of packets to yield before stopping; -1 streams indefinitely.
    :param process: If set, only yield packets whose pid (as a string) or process name matches.
    :param interface_name: If set, only yield packets captured on this interface: either its full name
        (``en0``) or its name without the unit number (``en``, matching every unit). pcapd reports the
        two separately, as ``interface_name`` and ``unit``.
    :yields: A parsed `DevicePacket`; ``interface_type`` is an `INTERFACE_NAMES` value and
        ``protocol_family`` a `CrossPlatformAddressFamily` value.
    """
    packet_index = 0
    while packet_index != packets_count:
        d = await self.service.recv_plist()
        if not d:
            break

        packet = parse_device_packet(cast(bytes, d))

        if process is not None and process != str(packet.pid) and process != packet.comm:
            continue

        if interface_name is not None and interface_name not in (
            packet.interface_name,
            f"{packet.interface_name}{packet.unit}",
        ):
            continue

        packet.interface_type = INTERFACE_NAMES(packet.interface_type)
        packet.protocol_family = CrossPlatformAddressFamily(packet.protocol_family)

        if not packet.frame_pre_length:
            # Add fake ethernet header for pdp packets.
            packet.data = ETHERNET_HEADER + packet.data
        elif packet.interface_name == "pdp_ip":
            packet.data = ETHERNET_HEADER + packet.data[4:]

        yield packet

        packet_index += 1
```

### write_to_pcap

```
write_to_pcap(out: BinaryIO, packet_generator: AsyncIterator[DevicePacket]) -> None
```

Write captured packets to a pcapng stream.

Consumes an async packet generator (such as `watch`) and writes each packet as an enhanced packet block, annotating it with the originating process metadata. Each block carries the device's capture time (`seconds`/`microseconds`), or the host's clock if the device sent none.

Parameters:

| Name               | Type                          | Description                                                    | Default    |
| ------------------ | ----------------------------- | -------------------------------------------------------------- | ---------- |
| `out`              | `BinaryIO`                    | A writable binary file-like object to receive the pcapng data. | *required* |
| `packet_generator` | `AsyncIterator[DevicePacket]` | Async iterable yielding parsed packets.                        | *required* |

Source code in `pymobiledevice3/services/pcapd.py`

```
async def write_to_pcap(self, out: BinaryIO, packet_generator: AsyncIterator[DevicePacket]) -> None:
    """
    Write captured packets to a pcapng stream.

    Consumes an async packet generator (such as `watch`) and writes each packet as an enhanced
    packet block, annotating it with the originating process metadata. Each block carries the
    device's capture time (``seconds``/``microseconds``), or the host's clock if the device sent none.

    :param out: A writable binary file-like object to receive the pcapng data.
    :param packet_generator: Async iterable yielding parsed packets.
    """
    shb: Any = blocks.SectionHeader(
        options={
            "shb_hardware": "artificial",
            "shb_os": "iOS",
            "shb_userappl": "pymobiledevice3",
        }
    )
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        options={"if_description": "iOS Packet Capture", "if_os": f"iOS {self.lockdown.product_version}"},
    )
    writer: Any = FileWriter(out, shb)

    async for packet in packet_generator:
        if packet.seconds:
            timestamp_microseconds = packet.seconds * 1_000_000 + packet.microseconds
        else:
            timestamp_microseconds = int(time.time() * 1_000_000)
        timestamp_high = (timestamp_microseconds >> 32) & 0xFFFFFFFF
        timestamp_low = timestamp_microseconds & 0xFFFFFFFF

        enhanced_packet = shb.new_member(
            blocks.EnhancedPacket,
            options={
                "opt_comment": f"PID: {packet.pid}, ProcName: {packet.comm}, EPID: {packet.epid}, "
                f"EProcName: {packet.ecomm}, SVC: {packet.svc}"
            },
        )

        enhanced_packet.packet_data = packet.data
        enhanced_packet.timestamp_high = timestamp_high
        enhanced_packet.timestamp_low = timestamp_low
        writer.write_block(enhanced_packet)
```

## pymobiledevice3.services.syslog.SyslogService

Bases: `LockdownService`

Stream the device's live system log via the `com.apple.syslog_relay` service.

The service name used depends on the lockdown type (legacy `com.apple.syslog_relay` for `LockdownClient`, RSD shim otherwise).

Source code in `pymobiledevice3/services/syslog.py`

```
class SyslogService(LockdownService):
    """
    Stream the device's live system log via the ``com.apple.syslog_relay`` service.

    The service name used depends on the lockdown type (legacy ``com.apple.syslog_relay`` for
    `LockdownClient`, RSD shim otherwise).
    """

    SERVICE_NAME = "com.apple.syslog_relay"
    RSD_SERVICE_NAME = "com.apple.syslog_relay.shim.remote"

    def __init__(self, service_provider: LockdownServiceProvider):
        if isinstance(service_provider, LockdownClient):
            super().__init__(service_provider, self.SERVICE_NAME)
        else:
            super().__init__(service_provider, self.RSD_SERVICE_NAME)

    async def watch(self) -> AsyncGenerator[Union[str, bytes], None]:
        """
        Stream syslog lines from the device as they are emitted.

        Reads the relay in chunks, splits on the syslog line delimiter, buffers any partial trailing
        line until the rest arrives, and decodes each complete line, undoing the relay's vis(3) escaping
        (see `decode_vis`). Empty lines are skipped.

        :yields: A single decoded syslog line (without the trailing delimiter), or the raw bytes
            when the line is not valid UTF-8.
        :raises ConnectionTerminatedError: If the device closes the connection.
        """
        buf = b""
        while True:
            # read in chunks till we have at least one syslog line
            chunk = await self.service.recv_any(CHUNK_SIZE)

            if len(chunk) == 0:
                raise ConnectionTerminatedError()

            buf += chunk

            # SYSLOG_LINE_SPLITTER is used to split each syslog line
            if SYSLOG_LINE_SPLITTER in buf:
                lines = buf.split(SYSLOG_LINE_SPLITTER)

                # handle partial last lines
                if not buf.endswith(SYSLOG_LINE_SPLITTER):
                    buf = lines[-1]
                    lines = lines[:-1]

                for line in lines:
                    if len(line) == 0:
                        continue

                    yield try_decode(decode_vis(line))
```

### watch

```
watch() -> AsyncGenerator[Union[str, bytes], None]
```

Stream syslog lines from the device as they are emitted.

Reads the relay in chunks, splits on the syslog line delimiter, buffers any partial trailing line until the rest arrives, and decodes each complete line, undoing the relay's vis(3) escaping (see `decode_vis`). Empty lines are skipped.

:yields: A single decoded syslog line (without the trailing delimiter), or the raw bytes when the line is not valid UTF-8.

Raises:

| Type                        | Description                          |
| --------------------------- | ------------------------------------ |
| `ConnectionTerminatedError` | If the device closes the connection. |

Source code in `pymobiledevice3/services/syslog.py`

```
async def watch(self) -> AsyncGenerator[Union[str, bytes], None]:
    """
    Stream syslog lines from the device as they are emitted.

    Reads the relay in chunks, splits on the syslog line delimiter, buffers any partial trailing
    line until the rest arrives, and decodes each complete line, undoing the relay's vis(3) escaping
    (see `decode_vis`). Empty lines are skipped.

    :yields: A single decoded syslog line (without the trailing delimiter), or the raw bytes
        when the line is not valid UTF-8.
    :raises ConnectionTerminatedError: If the device closes the connection.
    """
    buf = b""
    while True:
        # read in chunks till we have at least one syslog line
        chunk = await self.service.recv_any(CHUNK_SIZE)

        if len(chunk) == 0:
            raise ConnectionTerminatedError()

        buf += chunk

        # SYSLOG_LINE_SPLITTER is used to split each syslog line
        if SYSLOG_LINE_SPLITTER in buf:
            lines = buf.split(SYSLOG_LINE_SPLITTER)

            # handle partial last lines
            if not buf.endswith(SYSLOG_LINE_SPLITTER):
                buf = lines[-1]
                lines = lines[:-1]

            for line in lines:
                if len(line) == 0:
                    continue

                yield try_decode(decode_vis(line))
```

## pymobiledevice3.services.debugserver_applist.DebugServerAppList

Bases: `LockdownService`

Retrieve the list of installed applications as seen by debugserver, via the `com.apple.debugserver.DVTSecureSocketProxy.applist` service.

Source code in `pymobiledevice3/services/debugserver_applist.py`

```
class DebugServerAppList(LockdownService):
    """
    Retrieve the list of installed applications as seen by debugserver, via the
    ``com.apple.debugserver.DVTSecureSocketProxy.applist`` service.
    """

    SERVICE_NAME = "com.apple.debugserver.DVTSecureSocketProxy.applist"

    def __init__(self, lockdown: LockdownServiceProvider):
        super().__init__(lockdown, self.SERVICE_NAME)

    async def get(self) -> dict[str, Any]:
        """
        Fetch the application list.

        Reads the full plist response from the service and parses it.

        :returns: The parsed application list, keyed by bundle identifier.
        """
        buf = b""
        while b"</plist>" not in buf:
            buf += await self.service.recv_any(CHUNK_SIZE)

        return plistlib.loads(buf)
```

### get

```
get() -> dict[str, Any]
```

Fetch the application list.

Reads the full plist response from the service and parses it.

Returns:

| Type             | Description                                              |
| ---------------- | -------------------------------------------------------- |
| `dict[str, Any]` | The parsed application list, keyed by bundle identifier. |

Source code in `pymobiledevice3/services/debugserver_applist.py`

```
async def get(self) -> dict[str, Any]:
    """
    Fetch the application list.

    Reads the full plist response from the service and parses it.

    :returns: The parsed application list, keyed by bundle identifier.
    """
    buf = b""
    while b"</plist>" not in buf:
        buf += await self.service.recv_any(CHUNK_SIZE)

    return plistlib.loads(buf)
```

## pymobiledevice3.services.accessibilityaudit.AccessibilityAudit

Drive the device's accessibility audit daemon over DTX.

Provides access to accessibility capabilities and settings, on-device audits, the element inspector (focus traversal, simulated activation), and a stream of live accessibility events. Behavior differs across iOS versions (the iOS 15+ branch uses audit *types*, older versions use audit *case IDs*).

Use as an async context manager to establish the connection and flush the daemon's initial messages on entry and tear it down on exit::

```
async with AccessibilityAudit(lockdown) as audit:
    issues = await audit.run_audit(await audit.supported_audits_types())
```

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
class AccessibilityAudit:
    """
    Drive the device's accessibility audit daemon over DTX.

    Provides access to accessibility capabilities and settings, on-device audits, the element
    inspector (focus traversal, simulated activation), and a stream of live accessibility events.
    Behavior differs across iOS versions (the iOS 15+ branch uses audit *types*, older versions use
    audit *case IDs*).

    Use as an async context manager to establish the connection and flush the daemon's initial
    messages on entry and tear it down on exit::

        async with AccessibilityAudit(lockdown) as audit:
            issues = await audit.run_audit(await audit.supported_audits_types())
    """

    SERVICE_NAME = "com.apple.accessibility.axAuditDaemon.remoteserver"
    RSD_SERVICE_NAME = "com.apple.accessibility.axAuditDaemon.remoteserver.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider):
        self._lockdown = lockdown
        self._provider = _AccessibilityAuditProvider(lockdown)
        self._event_queue: typing.Optional[asyncio.Queue[tuple[str, list[typing.Any]]]] = None
        self.product_version = Version(lockdown.product_version)
        self._initial_messages_to_flush = 2 if self.product_version >= Version("15.0") else 1
        self._initial_messages_flushed = False

    async def __aenter__(self):
        try:
            await self._ensure_ready()
        except Exception:
            await self.close()
            raise
        else:
            return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[type[BaseException]],
        exc_val: typing.Optional[BaseException],
        exc_tb: typing.Optional[TracebackType],
    ):
        await self.close()

    async def close(self) -> None:
        """Tear down the event queue and close the underlying DTX connection."""
        if self._event_queue is not None:
            self._provider.dtx.ctx.pop("control_dispatch_queue", None)
            self._event_queue = None
        await self._provider.close()

    def shell(self) -> None:
        """
        Open an interactive IPython shell with the connection ready.

        The service is exposed as ``accessibility`` and the raw DTX channel as ``dtx``; the
        connection is closed when the shell exits.
        """
        from pymobiledevice3.utils import run_in_loop, start_ipython_shell

        run_in_loop(self._ensure_ready())
        try:
            start_ipython_shell(header=SHELL_USAGE, user_ns={"accessibility": self, "dtx": self._provider.dtx})
        finally:
            run_in_loop(self.close())

    async def _invoke(self, selector: str, *args: typing.Any, expects_reply: bool = True) -> typing.Any:
        await self._provider.connect()
        return await self._provider.dtx._ctrl_channel.invoke(selector, *args, expects_reply=expects_reply)

    @staticmethod
    def _extract_event_payload(args: list[typing.Any]) -> typing.Any:
        if not args:
            return None
        payload: typing.Any = args[0] if len(args) == 1 else args
        if isinstance(payload, list) and payload and isinstance(payload[0], dict) and "value" in payload[0]:
            return [x["value"] for x in typing.cast(list[typing.Any], payload)]
        return typing.cast(typing.Any, payload)

    async def _ensure_ready(self) -> None:
        await self._provider.connect()
        if self._event_queue is None:
            self._event_queue = asyncio.Queue()
            self._provider.dtx.ctx["control_dispatch_queue"] = self._event_queue
        if self._initial_messages_flushed:
            return
        for _ in range(self._initial_messages_to_flush):
            try:
                await asyncio.wait_for(self._event_queue.get(), timeout=0.3)
            except asyncio.TimeoutError:
                break
        self._initial_messages_flushed = True

    async def capabilities(self) -> list[str]:
        """
        Query the accessibility capabilities reported by the device.

        :returns: The list of capability identifiers the device supports.
        """
        await self._ensure_ready()
        return await self._invoke("deviceCapabilities")

    async def run_audit(self, value: list[typing.Any]) -> list[AXAuditIssue_v1]:
        """
        Run accessibility audits on the device and wait for the results.

        Begins the requested audits (by audit type on iOS 15+, by audit case ID on older versions)
        and blocks until the device reports completion, ignoring unrelated events in the meantime.

        :param value: The audit types (iOS 15+) or audit case IDs to run.
        :returns: The accessibility issues found by the audits.
        """
        await self._ensure_ready()
        if self.product_version >= Version("15.0"):
            await self._invoke("deviceBeginAuditTypes:", value, expects_reply=False)
        else:
            await self._invoke("deviceBeginAuditCaseIDs:", value, expects_reply=False)

        while True:
            assert self._event_queue is not None
            name, args = await self._event_queue.get()
            if name != "hostDeviceDidCompleteAuditCategoriesWithAuditIssues:":
                continue
            payload = self._extract_event_payload(args)
            if payload is None:
                continue
            raw = deserialize_object(payload)
            issues = typing.cast(list[typing.Any], raw) if isinstance(raw, list) else [raw]
            if issues and isinstance(issues[0], dict) and "value" in issues[0]:
                # older aux-shaped payload: [{"type": ..., "value": [issues]}]
                return typing.cast(list[AXAuditIssue_v1], issues[0]["value"])
            # modern shape: the deserialized payload IS the issue list (empty when the audit passes)
            return typing.cast(list[AXAuditIssue_v1], issues)

    async def supported_audits_types(self) -> list[typing.Any]:
        """
        Query the audit types (iOS 15+) or audit case IDs (older versions) the device supports.

        :returns: The supported audit identifiers, suitable for passing to `run_audit`.
        """
        await self._ensure_ready()
        if self.product_version >= Version("15.0"):
            response = await self._invoke("deviceAllSupportedAuditTypes")
        else:
            response = await self._invoke("deviceAllAuditCaseIDs")
        return deserialize_object(response)

    async def settings(self) -> list[AXAuditDeviceSetting_v1]:
        """
        Read the device's current accessibility settings.

        :returns: The accessibility settings, each as a key/value pair.
        """
        await self._ensure_ready()
        return deserialize_object(await self._invoke("deviceAccessibilitySettings"))

    async def set_app_monitoring_enabled(self, value: bool) -> None:
        """
        Enable or disable monitoring of the foreground app's accessibility elements.

        :param value: True to enable monitoring, False to disable.
        """
        await self._ensure_ready()
        await self._invoke("deviceSetAppMonitoringEnabled:", value, expects_reply=False)

    async def set_monitored_event_type(self, event_type: typing.Optional[int] = None) -> None:
        """
        Set which inspector event type the device should report.

        :param event_type: The event type to monitor; None resets it to 0 (no specific type).
        """
        await self._ensure_ready()
        if event_type is None:
            event_type = 0
        await self._invoke("deviceInspectorSetMonitoredEventType:", event_type, expects_reply=False)

    async def set_show_ignored_elements(self, value: bool) -> None:
        """
        Toggle whether the inspector includes accessibility-ignored elements.

        :param value: True to include ignored elements, False to hide them.
        """
        await self._ensure_ready()
        await self._invoke("deviceInspectorShowIgnoredElements:", int(value), expects_reply=False)

    async def set_show_visuals(self, value: bool) -> None:
        """
        Toggle the on-device visual overlay highlighting inspected elements.

        :param value: True to show the overlay, False to hide it.
        """
        await self._ensure_ready()
        await self._invoke("deviceInspectorShowVisuals:", int(value), expects_reply=False)

    async def iter_events(
        self, app_monitoring_enabled: bool = True, monitored_event_type: typing.Optional[int] = None
    ) -> AsyncGenerator[Event, None]:
        """
        Stream accessibility events from the device indefinitely.

        Configures app monitoring and the monitored event type, then yields every event the device
        publishes.

        :param app_monitoring_enabled: Whether to enable foreground-app monitoring before streaming.
        :param monitored_event_type: The event type to monitor; None means no specific type.
        :yields: Each accessibility `Event` with its deserialized payload.
        """
        await self._ensure_ready()
        await self.set_app_monitoring_enabled(app_monitoring_enabled)
        await self.set_monitored_event_type(monitored_event_type)

        while True:
            assert self._event_queue is not None
            name, args = await self._event_queue.get()
            payload = self._extract_event_payload(args)
            if payload is None:
                continue
            yield Event(name=name, data=deserialize_object(payload))

    async def move_focus_next(self) -> None:
        """Move the inspector focus to the next element."""
        await self.move_focus(Direction.Next)

    async def perform_press(self, element: bytes) -> None:
        """
        Simulate a press/activation on an accessibility element.

        Can only be used for processes that carry the ``task_for_pid-allow`` entitlement.

        :param element: The platform element value identifying the target element.
        """
        await self._ensure_ready()
        serialized_element: dict[str, typing.Any] = {
            "ObjectType": "AXAuditElement_v1",
            "Value": {
                "ObjectType": "passthrough",
                "Value": {
                    "PlatformElementValue_v1": {"ObjectType": "passthrough"},
                    "Value": element,
                },
            },
        }

        action: dict[str, typing.Any] = {
            "ObjectType": "AXAuditElementAttribute_v1",
            "Value": {
                "ObjectType": "passthrough",
                "Value": {
                    "AttributeNameValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": "AXAction-2010",
                    },
                    "DisplayAsTree_v1": {
                        "ObjectType": "passthrough",
                        "Value": 0,
                    },
                    "HumanReadableNameValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": "Activate",
                    },
                    "IsInternal_v1": {
                        "ObjectType": "passthrough",
                        "Value": 0,
                    },
                    "PerformsActionValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": 1,
                    },
                    "SettableValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": 0,
                    },
                    "ValueTypeValue_v1": {
                        "ObjectType": "passthrough",
                        "Value": 1,
                    },
                },
            },
        }

        await self._invoke("deviceElement:performAction:withValue:", serialized_element, action, 0, expects_reply=False)

    @staticmethod
    def _serialize_element(element: bytes) -> dict[str, typing.Any]:
        """Wrap a platform element value as the archived ``AXAuditElement_v1`` the daemon expects."""
        return {
            "ObjectType": "AXAuditElement_v1",
            "Value": {
                "ObjectType": "passthrough",
                "Value": {
                    "PlatformElementValue_v1": {"ObjectType": "passthrough", "Value": element},
                },
            },
        }

    @staticmethod
    def _serialize_attribute(name: str) -> dict[str, typing.Any]:
        """Wrap an attribute name as the archived ``AXAuditElementAttribute_v1`` the daemon expects."""
        return {
            "ObjectType": "AXAuditElementAttribute_v1",
            "Value": {
                "ObjectType": "passthrough",
                "Value": {
                    "AttributeNameValue_v1": {"ObjectType": "passthrough", "Value": name},
                },
            },
        }

    async def element_attribute(self, element: bytes, attribute: str) -> typing.Any:
        """
        Read a single accessibility attribute of an element.

        The daemon resolves only the element that currently holds the inspector focus (see
        `move_focus_and_wait`); other elements read as None.

        :param element: The platform element value identifying the element
            (`AXAuditElement_v1.identifier`).
        :param attribute: The attribute name, for example ``Label``, ``Identifier`` or ``Value``.
        :returns: The deserialized attribute value, or None when the element has no such value.
        """
        await self._ensure_ready()
        reply = await self._invoke(
            "deviceElement:valueForAttribute:", self._serialize_element(element), self._serialize_attribute(attribute)
        )
        return deserialize_object(reply)

    async def element_attributes(self, element: bytes, attributes: list[str]) -> dict[str, typing.Any]:
        """
        Read several accessibility attributes of an element.

        :param element: The platform element value identifying the element.
        :param attributes: The attribute names to read.
        :returns: A mapping of each attribute name to its deserialized value.
        """
        return {attribute: await self.element_attribute(element, attribute) for attribute in attributes}

    async def move_focus(self, direction: Direction) -> None:
        """
        Move the inspector focus in the given direction.

        :param direction: The `Direction` to move the focus (previous, next, first, or last).
        """
        await self._ensure_ready()
        options: dict[str, typing.Any] = {
            "ObjectType": "passthrough",
            "Value": {
                "allowNonAX": {
                    "ObjectType": "passthrough",
                    "Value": 0,
                },
                "direction": {
                    "ObjectType": "passthrough",
                    "Value": direction.value,
                },
                "includeContainers": {
                    "ObjectType": "passthrough",
                    "Value": 1,
                },
            },
        }

        await self._invoke("deviceInspectorMoveWithOptions:", options, expects_reply=False)

    async def move_focus_and_wait(self, direction: Direction, timeout: float = 5.0) -> AXAuditInspectorFocus_v1:
        """
        Move the inspector focus and wait for the element that receives it.

        Enables app monitoring so the device publishes focus changes.

        :param direction: The `Direction` to move the focus.
        :param timeout: Seconds to wait for the focus-change event.
        :returns: The newly focused element.
        :raises TimeoutError: If the device reports no focus change in time.
        """
        await self._ensure_ready()
        await self.set_app_monitoring_enabled(True)
        await self.set_monitored_event_type()
        await self.move_focus(direction)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for an accessibility focus change")
            assert self._event_queue is not None
            try:
                name, args = await asyncio.wait_for(self._event_queue.get(), timeout=remaining)
            except asyncio.TimeoutError as err:
                raise TimeoutError("timed out waiting for an accessibility focus change") from err
            if name != "hostInspectorCurrentElementChanged:":
                continue
            payload = self._extract_event_payload(args)
            if payload is None:
                continue
            data = deserialize_object(payload)
            if isinstance(data, list):
                if not data:
                    continue
                data = typing.cast(list[typing.Any], data)[0]
            return typing.cast(AXAuditInspectorFocus_v1, data)

    async def set_setting(self, name: str, value: typing.Any) -> None:
        """
        Update a single accessibility setting on the device.

        :param name: The setting identifier (matching `AXAuditDeviceSetting_v1.key`).
        :param value: The new value to assign to the setting.
        """
        await self._ensure_ready()
        setting: dict[str, typing.Any] = {
            "ObjectType": "AXAuditDeviceSetting_v1",
            "Value": {
                "ObjectType": "passthrough",
                "Value": {
                    "CurrentValueNumber_v1": {"ObjectType": "passthrough", "Value": True},
                    "EnabledValue_v1": {"ObjectType": "passthrough", "Value": True},
                    "IdentiifierValue_v1": {"ObjectType": "passthrough", "Value": name},
                    "SettingTypeValue_v1": {"ObjectType": "passthrough", "Value": 3},
                    "SliderTickMarksValue_v1": {"ObjectType": "passthrough", "Value": 0},
                },
            },
        }
        await self._invoke(
            "deviceUpdateAccessibilitySetting:withValue:",
            setting,
            {"ObjectType": "passthrough", "Value": value},
            expects_reply=False,
        )

    async def reset_settings(self) -> None:
        """Reset all accessibility settings to their device defaults."""
        await self._ensure_ready()
        await self._invoke("deviceResetToDefaultAccessibilitySettings")

    async def iter_elements(self) -> AsyncGenerator[AXAuditInspectorFocus_v1, None]:
        """
        Walk the focusable accessibility elements of the foreground app.

        Enables app monitoring, then repeatedly advances the focus and yields each newly focused
        element. Stops once an already-seen element is revisited (loop detected). If the focus does
        not advance, it retries; persistent silence raises a timeout.

        :yields: Each focused element as it is reached.
        :raises TimeoutError: If no focus events arrive after repeated retries.
        """
        await self._ensure_ready()
        await self.set_app_monitoring_enabled(True)
        await self.set_monitored_event_type()

        # Every focus change is expected to publish "hostInspectorCurrentElementChanged:".
        await self.move_focus_next()
        visited_identifiers: set[typing.Any] = set()
        consecutive_timeouts = 0

        while True:
            try:
                assert self._event_queue is not None
                name, args = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                consecutive_timeouts = 0
            except asyncio.TimeoutError as err:
                consecutive_timeouts += 1
                if consecutive_timeouts >= 5:
                    raise TimeoutError("timed out waiting for accessibility focus events") from err
                await self.move_focus_next()
                continue
            payload = self._extract_event_payload(args)
            if payload is None:
                continue
            event = Event(name=name, data=deserialize_object(payload))
            if event.name != "hostInspectorCurrentElementChanged:":
                # ignore any other events
                continue

            # each such event should contain exactly one element that became in focus
            if isinstance(event.data, list):
                if not typing.cast(typing.Any, event).data:
                    continue
                current_item = typing.cast(list[typing.Any], event.data)[0]
            else:
                current_item = event.data
            current_identifier = current_item.platform_identifier

            if current_identifier in visited_identifiers:
                break  # Exit if we've seen this element before (loop detected)

            yield current_item
            visited_identifiers.add(current_identifier)
            await self.move_focus_next()
```

### close

```
close() -> None
```

Tear down the event queue and close the underlying DTX connection.

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def close(self) -> None:
    """Tear down the event queue and close the underlying DTX connection."""
    if self._event_queue is not None:
        self._provider.dtx.ctx.pop("control_dispatch_queue", None)
        self._event_queue = None
    await self._provider.close()
```

### shell

```
shell() -> None
```

Open an interactive IPython shell with the connection ready.

The service is exposed as `accessibility` and the raw DTX channel as `dtx`; the connection is closed when the shell exits.

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
def shell(self) -> None:
    """
    Open an interactive IPython shell with the connection ready.

    The service is exposed as ``accessibility`` and the raw DTX channel as ``dtx``; the
    connection is closed when the shell exits.
    """
    from pymobiledevice3.utils import run_in_loop, start_ipython_shell

    run_in_loop(self._ensure_ready())
    try:
        start_ipython_shell(header=SHELL_USAGE, user_ns={"accessibility": self, "dtx": self._provider.dtx})
    finally:
        run_in_loop(self.close())
```

### capabilities

```
capabilities() -> list[str]
```

Query the accessibility capabilities reported by the device.

Returns:

| Type        | Description                                             |
| ----------- | ------------------------------------------------------- |
| `list[str]` | The list of capability identifiers the device supports. |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def capabilities(self) -> list[str]:
    """
    Query the accessibility capabilities reported by the device.

    :returns: The list of capability identifiers the device supports.
    """
    await self._ensure_ready()
    return await self._invoke("deviceCapabilities")
```

### run_audit

```
run_audit(value: list[Any]) -> list[AXAuditIssue_v1]
```

Run accessibility audits on the device and wait for the results.

Begins the requested audits (by audit type on iOS 15+, by audit case ID on older versions) and blocks until the device reports completion, ignoring unrelated events in the meantime.

Parameters:

| Name    | Type        | Description                                         | Default    |
| ------- | ----------- | --------------------------------------------------- | ---------- |
| `value` | `list[Any]` | The audit types (iOS 15+) or audit case IDs to run. | *required* |

Returns:

| Type                    | Description                                   |
| ----------------------- | --------------------------------------------- |
| `list[AXAuditIssue_v1]` | The accessibility issues found by the audits. |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def run_audit(self, value: list[typing.Any]) -> list[AXAuditIssue_v1]:
    """
    Run accessibility audits on the device and wait for the results.

    Begins the requested audits (by audit type on iOS 15+, by audit case ID on older versions)
    and blocks until the device reports completion, ignoring unrelated events in the meantime.

    :param value: The audit types (iOS 15+) or audit case IDs to run.
    :returns: The accessibility issues found by the audits.
    """
    await self._ensure_ready()
    if self.product_version >= Version("15.0"):
        await self._invoke("deviceBeginAuditTypes:", value, expects_reply=False)
    else:
        await self._invoke("deviceBeginAuditCaseIDs:", value, expects_reply=False)

    while True:
        assert self._event_queue is not None
        name, args = await self._event_queue.get()
        if name != "hostDeviceDidCompleteAuditCategoriesWithAuditIssues:":
            continue
        payload = self._extract_event_payload(args)
        if payload is None:
            continue
        raw = deserialize_object(payload)
        issues = typing.cast(list[typing.Any], raw) if isinstance(raw, list) else [raw]
        if issues and isinstance(issues[0], dict) and "value" in issues[0]:
            # older aux-shaped payload: [{"type": ..., "value": [issues]}]
            return typing.cast(list[AXAuditIssue_v1], issues[0]["value"])
        # modern shape: the deserialized payload IS the issue list (empty when the audit passes)
        return typing.cast(list[AXAuditIssue_v1], issues)
```

### supported_audits_types

```
supported_audits_types() -> list[typing.Any]
```

Query the audit types (iOS 15+) or audit case IDs (older versions) the device supports.

Returns:

| Type        | Description                                                         |
| ----------- | ------------------------------------------------------------------- |
| `list[Any]` | The supported audit identifiers, suitable for passing to run_audit. |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def supported_audits_types(self) -> list[typing.Any]:
    """
    Query the audit types (iOS 15+) or audit case IDs (older versions) the device supports.

    :returns: The supported audit identifiers, suitable for passing to `run_audit`.
    """
    await self._ensure_ready()
    if self.product_version >= Version("15.0"):
        response = await self._invoke("deviceAllSupportedAuditTypes")
    else:
        response = await self._invoke("deviceAllAuditCaseIDs")
    return deserialize_object(response)
```

### settings

```
settings() -> list[AXAuditDeviceSetting_v1]
```

Read the device's current accessibility settings.

Returns:

| Type                            | Description                                           |
| ------------------------------- | ----------------------------------------------------- |
| `list[AXAuditDeviceSetting_v1]` | The accessibility settings, each as a key/value pair. |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def settings(self) -> list[AXAuditDeviceSetting_v1]:
    """
    Read the device's current accessibility settings.

    :returns: The accessibility settings, each as a key/value pair.
    """
    await self._ensure_ready()
    return deserialize_object(await self._invoke("deviceAccessibilitySettings"))
```

### set_app_monitoring_enabled

```
set_app_monitoring_enabled(value: bool) -> None
```

Enable or disable monitoring of the foreground app's accessibility elements.

Parameters:

| Name    | Type   | Description                                  | Default    |
| ------- | ------ | -------------------------------------------- | ---------- |
| `value` | `bool` | True to enable monitoring, False to disable. | *required* |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def set_app_monitoring_enabled(self, value: bool) -> None:
    """
    Enable or disable monitoring of the foreground app's accessibility elements.

    :param value: True to enable monitoring, False to disable.
    """
    await self._ensure_ready()
    await self._invoke("deviceSetAppMonitoringEnabled:", value, expects_reply=False)
```

### set_monitored_event_type

```
set_monitored_event_type(event_type: Optional[int] = None) -> None
```

Set which inspector event type the device should report.

Parameters:

| Name         | Type            | Description                                                        | Default |
| ------------ | --------------- | ------------------------------------------------------------------ | ------- |
| `event_type` | `Optional[int]` | The event type to monitor; None resets it to 0 (no specific type). | `None`  |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def set_monitored_event_type(self, event_type: typing.Optional[int] = None) -> None:
    """
    Set which inspector event type the device should report.

    :param event_type: The event type to monitor; None resets it to 0 (no specific type).
    """
    await self._ensure_ready()
    if event_type is None:
        event_type = 0
    await self._invoke("deviceInspectorSetMonitoredEventType:", event_type, expects_reply=False)
```

### set_show_ignored_elements

```
set_show_ignored_elements(value: bool) -> None
```

Toggle whether the inspector includes accessibility-ignored elements.

Parameters:

| Name    | Type   | Description                                           | Default    |
| ------- | ------ | ----------------------------------------------------- | ---------- |
| `value` | `bool` | True to include ignored elements, False to hide them. | *required* |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def set_show_ignored_elements(self, value: bool) -> None:
    """
    Toggle whether the inspector includes accessibility-ignored elements.

    :param value: True to include ignored elements, False to hide them.
    """
    await self._ensure_ready()
    await self._invoke("deviceInspectorShowIgnoredElements:", int(value), expects_reply=False)
```

### set_show_visuals

```
set_show_visuals(value: bool) -> None
```

Toggle the on-device visual overlay highlighting inspected elements.

Parameters:

| Name    | Type   | Description                                 | Default    |
| ------- | ------ | ------------------------------------------- | ---------- |
| `value` | `bool` | True to show the overlay, False to hide it. | *required* |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def set_show_visuals(self, value: bool) -> None:
    """
    Toggle the on-device visual overlay highlighting inspected elements.

    :param value: True to show the overlay, False to hide it.
    """
    await self._ensure_ready()
    await self._invoke("deviceInspectorShowVisuals:", int(value), expects_reply=False)
```

### iter_events

```
iter_events(app_monitoring_enabled: bool = True, monitored_event_type: Optional[int] = None) -> AsyncGenerator[Event, None]
```

Stream accessibility events from the device indefinitely.

Configures app monitoring and the monitored event type, then yields every event the device publishes.

:yields: Each accessibility `Event` with its deserialized payload.

Parameters:

| Name                     | Type            | Description                                                   | Default |
| ------------------------ | --------------- | ------------------------------------------------------------- | ------- |
| `app_monitoring_enabled` | `bool`          | Whether to enable foreground-app monitoring before streaming. | `True`  |
| `monitored_event_type`   | `Optional[int]` | The event type to monitor; None means no specific type.       | `None`  |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def iter_events(
    self, app_monitoring_enabled: bool = True, monitored_event_type: typing.Optional[int] = None
) -> AsyncGenerator[Event, None]:
    """
    Stream accessibility events from the device indefinitely.

    Configures app monitoring and the monitored event type, then yields every event the device
    publishes.

    :param app_monitoring_enabled: Whether to enable foreground-app monitoring before streaming.
    :param monitored_event_type: The event type to monitor; None means no specific type.
    :yields: Each accessibility `Event` with its deserialized payload.
    """
    await self._ensure_ready()
    await self.set_app_monitoring_enabled(app_monitoring_enabled)
    await self.set_monitored_event_type(monitored_event_type)

    while True:
        assert self._event_queue is not None
        name, args = await self._event_queue.get()
        payload = self._extract_event_payload(args)
        if payload is None:
            continue
        yield Event(name=name, data=deserialize_object(payload))
```

### move_focus_next

```
move_focus_next() -> None
```

Move the inspector focus to the next element.

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def move_focus_next(self) -> None:
    """Move the inspector focus to the next element."""
    await self.move_focus(Direction.Next)
```

### perform_press

```
perform_press(element: bytes) -> None
```

Simulate a press/activation on an accessibility element.

Can only be used for processes that carry the `task_for_pid-allow` entitlement.

Parameters:

| Name      | Type    | Description                                                | Default    |
| --------- | ------- | ---------------------------------------------------------- | ---------- |
| `element` | `bytes` | The platform element value identifying the target element. | *required* |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def perform_press(self, element: bytes) -> None:
    """
    Simulate a press/activation on an accessibility element.

    Can only be used for processes that carry the ``task_for_pid-allow`` entitlement.

    :param element: The platform element value identifying the target element.
    """
    await self._ensure_ready()
    serialized_element: dict[str, typing.Any] = {
        "ObjectType": "AXAuditElement_v1",
        "Value": {
            "ObjectType": "passthrough",
            "Value": {
                "PlatformElementValue_v1": {"ObjectType": "passthrough"},
                "Value": element,
            },
        },
    }

    action: dict[str, typing.Any] = {
        "ObjectType": "AXAuditElementAttribute_v1",
        "Value": {
            "ObjectType": "passthrough",
            "Value": {
                "AttributeNameValue_v1": {
                    "ObjectType": "passthrough",
                    "Value": "AXAction-2010",
                },
                "DisplayAsTree_v1": {
                    "ObjectType": "passthrough",
                    "Value": 0,
                },
                "HumanReadableNameValue_v1": {
                    "ObjectType": "passthrough",
                    "Value": "Activate",
                },
                "IsInternal_v1": {
                    "ObjectType": "passthrough",
                    "Value": 0,
                },
                "PerformsActionValue_v1": {
                    "ObjectType": "passthrough",
                    "Value": 1,
                },
                "SettableValue_v1": {
                    "ObjectType": "passthrough",
                    "Value": 0,
                },
                "ValueTypeValue_v1": {
                    "ObjectType": "passthrough",
                    "Value": 1,
                },
            },
        },
    }

    await self._invoke("deviceElement:performAction:withValue:", serialized_element, action, 0, expects_reply=False)
```

### element_attribute

```
element_attribute(element: bytes, attribute: str) -> typing.Any
```

Read a single accessibility attribute of an element.

The daemon resolves only the element that currently holds the inspector focus (see `move_focus_and_wait`); other elements read as None.

Parameters:

| Name        | Type    | Description                                                                        | Default    |
| ----------- | ------- | ---------------------------------------------------------------------------------- | ---------- |
| `element`   | `bytes` | The platform element value identifying the element (AXAuditElement_v1.identifier). | *required* |
| `attribute` | `str`   | The attribute name, for example Label, Identifier or Value.                        | *required* |

Returns:

| Type  | Description                                                                   |
| ----- | ----------------------------------------------------------------------------- |
| `Any` | The deserialized attribute value, or None when the element has no such value. |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def element_attribute(self, element: bytes, attribute: str) -> typing.Any:
    """
    Read a single accessibility attribute of an element.

    The daemon resolves only the element that currently holds the inspector focus (see
    `move_focus_and_wait`); other elements read as None.

    :param element: The platform element value identifying the element
        (`AXAuditElement_v1.identifier`).
    :param attribute: The attribute name, for example ``Label``, ``Identifier`` or ``Value``.
    :returns: The deserialized attribute value, or None when the element has no such value.
    """
    await self._ensure_ready()
    reply = await self._invoke(
        "deviceElement:valueForAttribute:", self._serialize_element(element), self._serialize_attribute(attribute)
    )
    return deserialize_object(reply)
```

### element_attributes

```
element_attributes(element: bytes, attributes: list[str]) -> dict[str, typing.Any]
```

Read several accessibility attributes of an element.

Parameters:

| Name         | Type        | Description                                         | Default    |
| ------------ | ----------- | --------------------------------------------------- | ---------- |
| `element`    | `bytes`     | The platform element value identifying the element. | *required* |
| `attributes` | `list[str]` | The attribute names to read.                        | *required* |

Returns:

| Type             | Description                                                 |
| ---------------- | ----------------------------------------------------------- |
| `dict[str, Any]` | A mapping of each attribute name to its deserialized value. |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def element_attributes(self, element: bytes, attributes: list[str]) -> dict[str, typing.Any]:
    """
    Read several accessibility attributes of an element.

    :param element: The platform element value identifying the element.
    :param attributes: The attribute names to read.
    :returns: A mapping of each attribute name to its deserialized value.
    """
    return {attribute: await self.element_attribute(element, attribute) for attribute in attributes}
```

### move_focus

```
move_focus(direction: Direction) -> None
```

Move the inspector focus in the given direction.

Parameters:

| Name        | Type        | Description                                                       | Default    |
| ----------- | ----------- | ----------------------------------------------------------------- | ---------- |
| `direction` | `Direction` | The Direction to move the focus (previous, next, first, or last). | *required* |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def move_focus(self, direction: Direction) -> None:
    """
    Move the inspector focus in the given direction.

    :param direction: The `Direction` to move the focus (previous, next, first, or last).
    """
    await self._ensure_ready()
    options: dict[str, typing.Any] = {
        "ObjectType": "passthrough",
        "Value": {
            "allowNonAX": {
                "ObjectType": "passthrough",
                "Value": 0,
            },
            "direction": {
                "ObjectType": "passthrough",
                "Value": direction.value,
            },
            "includeContainers": {
                "ObjectType": "passthrough",
                "Value": 1,
            },
        },
    }

    await self._invoke("deviceInspectorMoveWithOptions:", options, expects_reply=False)
```

### move_focus_and_wait

```
move_focus_and_wait(direction: Direction, timeout: float = 5.0) -> AXAuditInspectorFocus_v1
```

Move the inspector focus and wait for the element that receives it.

Enables app monitoring so the device publishes focus changes.

Parameters:

| Name        | Type        | Description                                 | Default    |
| ----------- | ----------- | ------------------------------------------- | ---------- |
| `direction` | `Direction` | The Direction to move the focus.            | *required* |
| `timeout`   | `float`     | Seconds to wait for the focus-change event. | `5.0`      |

Returns:

| Type                       | Description                |
| -------------------------- | -------------------------- |
| `AXAuditInspectorFocus_v1` | The newly focused element. |

Raises:

| Type           | Description                                    |
| -------------- | ---------------------------------------------- |
| `TimeoutError` | If the device reports no focus change in time. |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def move_focus_and_wait(self, direction: Direction, timeout: float = 5.0) -> AXAuditInspectorFocus_v1:
    """
    Move the inspector focus and wait for the element that receives it.

    Enables app monitoring so the device publishes focus changes.

    :param direction: The `Direction` to move the focus.
    :param timeout: Seconds to wait for the focus-change event.
    :returns: The newly focused element.
    :raises TimeoutError: If the device reports no focus change in time.
    """
    await self._ensure_ready()
    await self.set_app_monitoring_enabled(True)
    await self.set_monitored_event_type()
    await self.move_focus(direction)

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError("timed out waiting for an accessibility focus change")
        assert self._event_queue is not None
        try:
            name, args = await asyncio.wait_for(self._event_queue.get(), timeout=remaining)
        except asyncio.TimeoutError as err:
            raise TimeoutError("timed out waiting for an accessibility focus change") from err
        if name != "hostInspectorCurrentElementChanged:":
            continue
        payload = self._extract_event_payload(args)
        if payload is None:
            continue
        data = deserialize_object(payload)
        if isinstance(data, list):
            if not data:
                continue
            data = typing.cast(list[typing.Any], data)[0]
        return typing.cast(AXAuditInspectorFocus_v1, data)
```

### set_setting

```
set_setting(name: str, value: Any) -> None
```

Update a single accessibility setting on the device.

Parameters:

| Name    | Type  | Description                                                    | Default    |
| ------- | ----- | -------------------------------------------------------------- | ---------- |
| `name`  | `str` | The setting identifier (matching AXAuditDeviceSetting_v1.key). | *required* |
| `value` | `Any` | The new value to assign to the setting.                        | *required* |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def set_setting(self, name: str, value: typing.Any) -> None:
    """
    Update a single accessibility setting on the device.

    :param name: The setting identifier (matching `AXAuditDeviceSetting_v1.key`).
    :param value: The new value to assign to the setting.
    """
    await self._ensure_ready()
    setting: dict[str, typing.Any] = {
        "ObjectType": "AXAuditDeviceSetting_v1",
        "Value": {
            "ObjectType": "passthrough",
            "Value": {
                "CurrentValueNumber_v1": {"ObjectType": "passthrough", "Value": True},
                "EnabledValue_v1": {"ObjectType": "passthrough", "Value": True},
                "IdentiifierValue_v1": {"ObjectType": "passthrough", "Value": name},
                "SettingTypeValue_v1": {"ObjectType": "passthrough", "Value": 3},
                "SliderTickMarksValue_v1": {"ObjectType": "passthrough", "Value": 0},
            },
        },
    }
    await self._invoke(
        "deviceUpdateAccessibilitySetting:withValue:",
        setting,
        {"ObjectType": "passthrough", "Value": value},
        expects_reply=False,
    )
```

### reset_settings

```
reset_settings() -> None
```

Reset all accessibility settings to their device defaults.

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def reset_settings(self) -> None:
    """Reset all accessibility settings to their device defaults."""
    await self._ensure_ready()
    await self._invoke("deviceResetToDefaultAccessibilitySettings")
```

### iter_elements

```
iter_elements() -> AsyncGenerator[AXAuditInspectorFocus_v1, None]
```

Walk the focusable accessibility elements of the foreground app.

Enables app monitoring, then repeatedly advances the focus and yields each newly focused element. Stops once an already-seen element is revisited (loop detected). If the focus does not advance, it retries; persistent silence raises a timeout.

:yields: Each focused element as it is reached.

Raises:

| Type           | Description                                       |
| -------------- | ------------------------------------------------- |
| `TimeoutError` | If no focus events arrive after repeated retries. |

Source code in `pymobiledevice3/services/accessibilityaudit.py`

```
async def iter_elements(self) -> AsyncGenerator[AXAuditInspectorFocus_v1, None]:
    """
    Walk the focusable accessibility elements of the foreground app.

    Enables app monitoring, then repeatedly advances the focus and yields each newly focused
    element. Stops once an already-seen element is revisited (loop detected). If the focus does
    not advance, it retries; persistent silence raises a timeout.

    :yields: Each focused element as it is reached.
    :raises TimeoutError: If no focus events arrive after repeated retries.
    """
    await self._ensure_ready()
    await self.set_app_monitoring_enabled(True)
    await self.set_monitored_event_type()

    # Every focus change is expected to publish "hostInspectorCurrentElementChanged:".
    await self.move_focus_next()
    visited_identifiers: set[typing.Any] = set()
    consecutive_timeouts = 0

    while True:
        try:
            assert self._event_queue is not None
            name, args = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
            consecutive_timeouts = 0
        except asyncio.TimeoutError as err:
            consecutive_timeouts += 1
            if consecutive_timeouts >= 5:
                raise TimeoutError("timed out waiting for accessibility focus events") from err
            await self.move_focus_next()
            continue
        payload = self._extract_event_payload(args)
        if payload is None:
            continue
        event = Event(name=name, data=deserialize_object(payload))
        if event.name != "hostInspectorCurrentElementChanged:":
            # ignore any other events
            continue

        # each such event should contain exactly one element that became in focus
        if isinstance(event.data, list):
            if not typing.cast(typing.Any, event).data:
                continue
            current_item = typing.cast(list[typing.Any], event.data)[0]
        else:
            current_item = event.data
        current_identifier = current_item.platform_identifier

        if current_identifier in visited_identifiers:
            break  # Exit if we've seen this element before (loop detected)

        yield current_item
        visited_identifiers.add(current_identifier)
        await self.move_focus_next()
```

## pymobiledevice3.services.webinspector.WebinspectorService

Bases: `LockdownService`

Client for the `com.apple.webinspector` service (`webinspectord`).

Drives Safari/WebKit remote inspection and WebDriver automation: enumerates inspectable applications and their pages, launches applications, and forwards the inspector/automation socket traffic used to build `InspectorSession` and `AutomationSession` objects.

The service maintains a background receive task that dispatches incoming RPC notifications and keeps the cached application/page state up to date. Call `connect` before issuing any requests and `close` when done.

Source code in `pymobiledevice3/services/webinspector.py`

```
class WebinspectorService(LockdownService):
    """Client for the `com.apple.webinspector` service (`webinspectord`).

    Drives Safari/WebKit remote inspection and WebDriver automation: enumerates inspectable
    applications and their pages, launches applications, and forwards the inspector/automation
    socket traffic used to build `InspectorSession` and `AutomationSession` objects.

    The service maintains a background receive task that dispatches incoming RPC notifications
    and keeps the cached application/page state up to date. Call `connect` before issuing any
    requests and `close` when done.
    """

    SERVICE_NAME = "com.apple.webinspector"
    RSD_SERVICE_NAME = "com.apple.webinspector.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown)
        self.connection_id = str(uuid.uuid4()).upper()
        self.state: Optional[str] = None
        self.connected_application: dict[str, Application] = {}
        self.application_pages: dict[str, Any] = {}
        self.wir_message_results: dict[str, Any] = {}
        # Optional observer of every inspector-protocol message crossing the page sockets, as
        # (direction, session id, message); the CDP bridge's --trace recorder plugs in here.
        self.trace: Optional[Callable[[str, str, Any], None]] = None
        self.wir_events: dict[str, deque[Any]] = {}
        self.receive_handlers = {
            "_rpc_reportCurrentState:": self._handle_report_current_state,
            "_rpc_reportConnectedApplicationList:": self._handle_report_connected_application_list,
            "_rpc_reportConnectedDriverList:": self._handle_report_connected_driver_list,
            "_rpc_applicationSentListing:": self._handle_application_sent_listing,
            "_rpc_applicationUpdated:": self._handle_application_updated,
            "_rpc_applicationConnected:": self._handle_application_connected,
            "_rpc_applicationSentData:": self._handle_application_sent_data,
            "_rpc_applicationDisconnected:": self._handle_application_disconnected,
            "_rpc_reportAutomaticInspectionCandidate:": self._handle_report_automatic_inspection_candidate,
        }
        self._recv_task: Optional[asyncio.Task[None]] = None
        # Set once the device's Web Inspector connection drops (a restart, a cable pull). The
        # listing endpoints then serve what was last known instead of raising per request; the
        # bridge stays up rather than spewing a traceback on every landing-page poll.
        self._connection_lost = False
        # Called once when the connection drops, so the caller can act on it - the CDP bridge
        # raises a device-disconnected error so pymobiledevice3's --reconnect can retry the command.
        self.on_connection_lost: Optional[Callable[[], None]] = None
        # Queues handed out by subscribe_*: the receive task publishes into them without waiting,
        # so a subscriber that reacts by talking to the device (whose answers arrive through this
        # same receive task) never deadlocks it.
        self._candidate_subscribers: list[asyncio.Queue[AutomaticInspectionCandidate]] = []
        self._listing_subscribers: list[asyncio.Queue[str]] = []

    async def connect(self) -> None:
        """Establish the WebInspector session and start the background receive task.

        Performs the initial handshake (reporting this client's identifier and processing the
        first reply) while watching for a disabled notification, then spawns the task that keeps
        consuming incoming messages. Safe to call repeatedly; subsequent calls are a no-op once
        the receive task is running.

        :raises WebInspectorNotEnabledError: Web Inspector is disabled on the device.
        """
        if self._recv_task is not None:
            return

        await self._connect_or_raise_disabled()
        self._recv_task = asyncio.create_task(self._receiving_task())

    @property
    def is_connected(self) -> bool:
        """Whether the device's Web Inspector connection is still up."""
        return not self._connection_lost

    @staticmethod
    def _is_connection_lost(error: BaseException) -> bool:
        return isinstance(
            error, (ConnectionError, ConnectionTerminatedError, asyncio.IncompleteReadError, EOFError, OSError)
        )

    def _note_connection_lost(self, error: BaseException) -> None:
        if not self._connection_lost:
            self._connection_lost = True
            self.logger.warning(f"Web Inspector connection to the device lost ({type(error).__name__})")
            if self.on_connection_lost is not None:
                self.on_connection_lost()

    async def close(self):
        """Cancel the background receive task and close the underlying service connection."""
        if self._recv_task is not None:
            self._recv_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, ConnectionTerminatedError):
                await self._recv_task
            self._recv_task = None
        await super().close()

    async def _recv_message(self):
        while True:
            try:
                return await self.service.recv_plist()
            except asyncio.IncompleteReadError:
                await asyncio.sleep(0)

    async def _wait_for_disabled_notification(self, notification_proxy: NotificationProxyService) -> None:
        async for event in notification_proxy.receive_notification():
            if event.get("Name") == WEBINSPECTORD_DISABLED_NOTIFICATION:
                raise WebInspectorNotEnabledError

    async def _connect_or_raise_disabled(self) -> None:
        async with NotificationProxyService(self.lockdown) as notification_proxy:
            await notification_proxy.notify_register_dispatch(WEBINSPECTORD_DISABLED_NOTIFICATION)
            disabled_task = asyncio.create_task(self._wait_for_disabled_notification(notification_proxy))
            try:
                await self._handshake(disabled_task)
            finally:
                disabled_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await disabled_task

    async def _handshake(self, disabled_task: asyncio.Task[None]) -> None:
        """Run the WebInspector handshake, retrying while webinspectord keeps refusing it.

        webinspectord refuses a session by terminating the connection - accepting it and never
        completing the TLS handshake, or closing it right after - and does so for three reasons
        that look identical from here:

        * Web Inspector is disabled on the device.
        * The gate it puts on consecutive sessions has not elapsed: a new session is admitted only
          about ten seconds after the previous one started. DEFAULT_SSL_HANDSHAKE_TIMEOUT now
          outlasts that wait, so a reattach right after a session ended - restarting the CDP bridge,
          or opening an automation session once inspection is done - normally just waits it out.
        * It is not up yet because the device is still booting. `--reconnect` re-runs a command the
          moment lockdownd answers again, which is seconds before webinspectord serves anything.

        Only the first is permanent, so keep trying until the deadline and report the refusal as
        Web Inspector being disabled only if it outlives it. A device that goes away mid-handshake
        is reported as the disconnect it is, so that a caller which retries on a disconnect (the
        CDP bridge under `--reconnect`) does. `disabled_task`, the device's own disabled
        notification, ends the wait immediately.
        """
        deadline = time.monotonic() + HANDSHAKE_RETRY_TIMEOUT
        while True:
            try:
                await self._await_or_raise_disabled(super().connect(), disabled_task)
                await self._await_or_raise_disabled(self._report_identifier(), disabled_task)
                await self._handle_recv(await self._await_or_raise_disabled(self._recv_message(), disabled_task))
            except ConnectionTerminatedError as e:
                if not await self._device_answers():
                    raise
                if time.monotonic() >= deadline:
                    raise WebInspectorNotEnabledError from e
            else:
                return
            self.logger.debug("webinspectord refused the session; retrying")
            # Drop the refused connection so the next attempt starts a session of its own.
            await self.close()
            await asyncio.sleep(HANDSHAKE_RETRY_INTERVAL)

    async def _await_or_raise_disabled(self, coro: Coroutine[Any, Any, Any], disabled_task: asyncio.Task[None]):
        task = asyncio.create_task(coro)
        done, _ = await asyncio.wait(
            {task, disabled_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if disabled_task in done:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await disabled_task
        return await task

    async def _device_answers(self) -> bool:
        """Whether lockdownd still answers.

        A device that went away and one that refused the session both terminate the WebInspector
        connection abruptly; only the one that is still there answers.
        """
        try:
            await self.lockdown.get_date()
        except Exception:
            return False
        return True

    async def _receiving_task(self):
        try:
            while True:
                await self._handle_recv(await self._recv_message())
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            if self._is_connection_lost(error):
                self._note_connection_lost(error)
                return
            raise

    async def automation_session(
        self, app: Application, timeout: float = AUTOMATION_SESSION_TIMEOUT
    ) -> AutomationSession:
        """Start a WebDriver automation session against an application.

        Requests a new automation session, waits for the corresponding automation page to appear,
        sets up its forwarding socket, and waits until the page reports an automation connection id.

        :param app: The application to automate.
        :param timeout: Seconds to wait for each of the two steps the application has to answer.
        :returns: A connected automation session.
        :raises RemoteAutomationNotEnabledError: Remote automation is not available on the device.
        :raises AutomationSessionUnavailableError: The application did not start the session in time,
            typically because another client's automation session holds it.
        """
        if self.state == "WIRAutomationAvailabilityNotAvailable":
            raise RemoteAutomationNotEnabledError()
        session_id = str(uuid.uuid4()).upper()
        await self._forward_automation_session_request(session_id, app.id_)
        await self._forward_get_listing(app.id_)
        try:
            page = await asyncio.wait_for(self._wait_for_page(session_id), timeout)
            await self._forward_socket_setup(session_id, app.id_, page.id_)
            await self._forward_get_listing(app.id_)
            await asyncio.wait_for(self._wait_for_automation_connection(page), timeout)
        except asyncio.TimeoutError:
            raise self._automation_session_unavailable(app, session_id, timeout) from None
        return AutomationSession(SessionProtocol(self, session_id, app, page))

    def _automation_session_unavailable(
        self, app: Application, session_id: str, timeout: float
    ) -> AutomationSessionUnavailableError:
        # An application serves one automation session at a time: while another client holds it (a
        # second pymobiledevice3, a WebDriver, a process orphaned by its parent), new requests go
        # unanswered. The device frees it when that client's connection closes.
        held = any(
            page.type_ == WirTypes.AUTOMATION and page.automation_session_id != session_id
            for page in self.application_pages.get(app.id_, {}).values()
        )
        if held:
            return AutomationSessionUnavailableError(
                f"{app.name} is already held by another automation session. Stop the other client using it "
                f"(another pymobiledevice3 webinspector command or WebDriver), or quit {app.name} on the device "
                f"(`pymobiledevice3 developer dvt pkill --bundle {app.bundle}`), and try again."
            )
        return AutomationSessionUnavailableError(
            f"{app.name} did not start an automation session within {timeout:g} seconds"
        )

    async def inspector_session(self, app: Application, page: Page) -> InspectorSession:
        """Open a Web Inspector session against a specific page of an application.

        :param app: The application owning the page.
        :param page: The page to inspect.
        :returns: A connected inspector session. For non-JavaScript pages the session waits for the
            inspection target before returning.
        """
        session_id = str(uuid.uuid4()).upper()
        return await InspectorSession.create(
            SessionProtocol(self, session_id, app, page, method_prefix=""),
            wait_target=page.type_ != WirTypes.JAVASCRIPT,
        )

    async def get_open_pages(self) -> dict[str, Any]:
        """Request and return the currently open pages of all connected applications.

        :returns: A mapping of application name to the collection of its `Page` objects, including
            only applications that currently report at least one page.
        """
        apps: dict[str, Any] = {}
        # One failing listing (or a lost connection) must not break the whole answer; serve what
        # was last reported instead.
        await asyncio.gather(
            *[self._forward_get_listing(app) for app in self.connected_application], return_exceptions=True
        )
        for app in self.connected_application:
            if self.application_pages.get(app, False):
                apps[self.connected_application[app].name] = self.application_pages[app].values()
        return apps

    async def get_open_application_pages(self, timeout: float) -> list[ApplicationPage]:
        """Enumerate all inspectable application/page pairs across connected applications.

        Queries the connected applications and then waits for `webinspectord` to report their
        listings before collecting the results.

        :param timeout: Seconds to wait for the device to reply with the application listings.
        :returns: A list of `ApplicationPage` pairs, one per reported page.
        """
        # Query all connected applications
        await self._get_connected_applications()

        # Give some time for `webinspectord` to reply with all inspectable applications
        await asyncio.sleep(timeout)

        result: list[ApplicationPage] = []
        for app in self.connected_application:
            if self.application_pages.get(app, False):
                for page in self.application_pages[app].values():
                    result.append(ApplicationPage(self.connected_application[app], page))
        return result

    async def open_app(self, bundle: str, timeout: Union[float, int] = 3) -> Application:
        """Launch an application by bundle identifier and wait for it to connect.

        :param bundle: The bundle identifier of the application to launch.
        :param timeout: Seconds to wait for the application to appear as connected.
        :returns: The connected application.
        :raises LaunchingApplicationError: The application did not connect within the timeout.
        """
        await self._request_application_launch(bundle)
        await self.get_open_pages()
        try:
            return await asyncio.wait_for(self._wait_for_application(bundle), timeout)
        except asyncio.TimeoutError as e:  # not the builtin TimeoutError before Python 3.11
            raise LaunchingApplicationError() from e

    async def send_socket_data(self, session_id: str, app_id: str, page_id: int, data: dict[str, Any]):
        """Forward an inspector/automation protocol message to a page's socket.

        :param session_id: The session identifier owning the socket.
        :param app_id: The target application identifier.
        :param page_id: The target page identifier.
        :param data: The protocol message to send; serialized to JSON before forwarding.
        """
        await self._forward_socket_data(session_id, app_id, page_id, data)

    async def setup_inspector_socket(
        self, session_id: str, app_id: str, page_id: int, automatically_pause: bool = False
    ) -> None:
        """Set up a forwarding socket for an inspector session.

        :param session_id: The session identifier to associate with the socket.
        :param app_id: The target application identifier.
        :param page_id: The target page identifier.
        :param automatically_pause: Ask WebKit to pause the debuggable on its next statement once
            the frontend reports itself initialized (`Inspector.initialized`) - Safari's
            "Automatically Pause Connecting to JSContexts". Honoured by JSContexts, service
            workers and legacy WebViews; a WKWebView's page ignores it.
        """
        await self._forward_socket_setup(session_id, app_id, page_id, automatically_pause=automatically_pause)

    async def set_automatic_inspection_enabled(self, enabled: bool) -> None:
        """Ask `webinspectord` to offer this connection every debuggable an application creates,
        before the application gets to run it (see `AutomaticInspectionCandidate`).

        While any connection has this enabled, every application holds each new JSContext until
        the candidate is answered; subscribe with `subscribe_automatic_inspection` first, and
        switch it off again when done.

        :param enabled: Whether to receive candidates.
        """
        await self._send_message(
            "_rpc_forwardAutomaticInspectionConfiguration:", {"WIRAutomaticInspectionEnabledKey": enabled}
        )

    def subscribe_automatic_inspection(self) -> "asyncio.Queue[AutomaticInspectionCandidate]":
        """Receive automatic-inspection candidates as they are offered.

        A candidate is accepted by setting up an inspector socket for its page and completing the
        frontend handshake, or declined with `reject_automatic_inspection`. Candidates offered while
        nobody is subscribed are declined on the spot, so applications never wait on this client.

        :returns: A queue the candidates are published into; hand it back to
            `unsubscribe_automatic_inspection` when done.
        """
        queue: asyncio.Queue[AutomaticInspectionCandidate] = asyncio.Queue()
        self._candidate_subscribers.append(queue)
        return queue

    def unsubscribe_automatic_inspection(self, queue: "asyncio.Queue[AutomaticInspectionCandidate]") -> None:
        with contextlib.suppress(ValueError):
            self._candidate_subscribers.remove(queue)

    async def reject_automatic_inspection(self, candidate: AutomaticInspectionCandidate) -> None:
        """Decline a candidate, letting the application resume (or be offered to the next debugger).

        :param candidate: The candidate as published by `subscribe_automatic_inspection`.
        """
        await self._send_message(
            "_rpc_forwardAutomaticInspectionRejection:",
            {
                "WIRApplicationIdentifierKey": candidate.app_id,
                "WIRPageIdentifierKey": candidate.page_id,
                "WIRAutomaticInspectionSessionIdentifierKey": candidate.session_id,
            },
        )

    def subscribe_listings(self) -> "asyncio.Queue[str]":
        """Be told whenever an application's page listing arrives - `webinspectord` relays one on
        its own the moment a page opens, closes or navigates.

        :returns: A queue the identifier of the application whose listing changed is published
            into; hand it back to `unsubscribe_listings` when done.
        """
        queue: asyncio.Queue[str] = asyncio.Queue()
        self._listing_subscribers.append(queue)
        return queue

    def unsubscribe_listings(self, queue: "asyncio.Queue[str]") -> None:
        with contextlib.suppress(ValueError):
            self._listing_subscribers.remove(queue)

    async def teardown_inspector_socket(self, session_id: str, app_id: str, page_id: int):
        """Tear down a forwarding socket previously set up for an inspector session.

        Without this, webinspectord considers the session still active and ignores the next
        socket setup for the same page, so a future session never receives its target events.

        :param session_id: The session identifier the socket was associated with.
        :param app_id: The target application identifier.
        :param page_id: The target page identifier.
        """
        await self._forward_did_close(session_id, app_id, page_id)
        self.wir_events.pop(session_id, None)

    def session_events(self, session_id: str) -> deque[Any]:
        """The queue of events `webinspectord` forwarded to one session's socket.

        Events carry no id, so a consumer cannot tell its own from another's by content, and
        WebKit allows one inspector session per page but several across pages. `webinspectord`
        tags every forwarded message with the session it belongs to, so they are queued per
        session: concurrent sessions - two DevTools tabs, two JSContexts - would otherwise
        consume each other's events.

        :param session_id: The session identifier the socket was set up with.
        :returns: The session's queue (a deque, so consuming from the front is O(1)); consumers pop
            from it in place.
        """
        return self.wir_events.setdefault(session_id, deque())

    def find_page_id(self, page_id: str) -> tuple[Application, Page]:
        """Look up the application and page for a known page identifier.

        :param page_id: An identifier as built by `make_target_id`. A bare page identifier is also
            accepted, resolving to the first application reporting it - note that page identifiers
            are only unique per application (every JSContext debuggable is page 1 of its own
            process), so it cannot address them all.
        :returns: A tuple of the owning application and the matching page.
        :raises KeyError: No page with the given identifier is currently known.
        """
        app_id, _, page_key = page_id.rpartition(":")
        if page_key in self.application_pages.get(app_id, {}):
            return self.connected_application[app_id], self.application_pages[app_id][page_key]
        for app_id in self.application_pages:
            for page in self.application_pages[app_id]:
                if page == page_id:
                    return self.connected_application[app_id], self.application_pages[app_id][page_id]
        raise KeyError(f"Page with id {page_id} not found")

    async def flush_input(self, duration: Union[float, int] = 0):
        """Yield control for the given duration to let pending incoming messages be processed.

        :param duration: Seconds to sleep while the background receive task drains input.
        """
        return await asyncio.sleep(duration)

    async def _handle_recv(self, plist: dict[str, Any]):
        await self.receive_handlers[plist["__selector"]](plist["__argument"])

    async def _handle_report_current_state(self, arg: dict[str, Any]):
        self.state = arg.get("WIRAutomationAvailabilityKey", AutomationAvailability.UNKNOWN.value)

    async def _handle_report_connected_application_list(self, arg: dict[str, Any]):
        self.connected_application = {}
        for key, application in arg["WIRApplicationDictionaryKey"].items():
            self.connected_application[key] = Application.from_application_dictionary(application)

            # Immediately also query the application pages
            await self._forward_get_listing(self.connected_application[key].id_)

    async def _handle_report_connected_driver_list(self, arg: dict[str, Any]):
        pass

    async def _handle_application_sent_listing(self, arg: dict[str, Any]):
        app_id = arg["WIRApplicationIdentifierKey"]
        known: dict[str, Page] = self.application_pages.get(app_id, {})
        # A listing is the application's complete set of pages, not a delta: a page missing from it
        # has been closed. Merging one in without dropping those kept every tab ever opened in the
        # listing for the rest of the session. Pages that survive are updated in place - sessions
        # hold references to them.
        pages: dict[str, Page] = {}
        for id_, page in arg["WIRListingKey"].items():
            if id_ in known:
                known[id_].update(page)
                pages[id_] = known[id_]
            else:
                pages[id_] = Page.from_page_dictionary(page)
        self.application_pages[app_id] = pages
        for queue in self._listing_subscribers:
            queue.put_nowait(app_id)

    async def _handle_report_automatic_inspection_candidate(self, arg: dict[str, Any]) -> None:
        candidate = AutomaticInspectionCandidate(
            arg["WIRApplicationIdentifierKey"],
            arg["WIRPageIdentifierKey"],
            arg["WIRAutomaticInspectionSessionIdentifierKey"],
        )
        if not self._candidate_subscribers:
            # Nobody to take it: decline now rather than let the application wait out its timeout.
            await self.reject_automatic_inspection(candidate)
            return
        for queue in self._candidate_subscribers:
            queue.put_nowait(candidate)

    async def _handle_application_updated(self, arg: dict[str, Any]):
        app = Application.from_application_dictionary(arg)
        self.connected_application[app.id_] = app

    async def _handle_application_connected(self, arg: dict[str, Any]):
        app = Application.from_application_dictionary(arg)
        self.connected_application[app.id_] = app

    async def _handle_application_sent_data(self, arg: dict[str, Any]):
        response = json.loads(arg["WIRMessageDataKey"])
        trace = getattr(self, "trace", None)
        if trace is not None:
            trace("device->bridge", arg.get("WIRDestinationKey", ""), response)

        if "id" in response:
            self.wir_message_results[response["id"]] = response
        else:
            self.session_events(arg.get("WIRDestinationKey", "")).append(response)

    async def _handle_application_disconnected(self, arg: dict[str, Any]):
        self.connected_application.pop(arg["WIRApplicationIdentifierKey"], None)
        self.application_pages.pop(arg["WIRApplicationIdentifierKey"], None)

    async def _report_identifier(self):
        await self._send_message("_rpc_reportIdentifier:")

    async def _forward_get_listing(self, app_id: str):
        self.logger.debug(f"Listing app with id {app_id}")
        await self._send_message("_rpc_forwardGetListing:", {"WIRApplicationIdentifierKey": app_id})

    async def _request_application_launch(self, bundle: str):
        await self._send_message("_rpc_requestApplicationLaunch:", {"WIRApplicationBundleIdentifierKey": bundle})

    async def _get_connected_applications(self) -> None:
        await self._send_message("_rpc_getConnectedApplications:", {})

    async def _forward_automation_session_request(self, session_id: str, app_id: str):
        await self._send_message(
            "_rpc_forwardAutomationSessionRequest:",
            {
                "WIRApplicationIdentifierKey": app_id,
                "WIRSessionCapabilitiesKey": {
                    "org.webkit.webdriver.webrtc.allow-insecure-media-capture": True,
                    "org.webkit.webdriver.webrtc.suppress-ice-candidate-filtering": False,
                },
                "WIRSessionIdentifierKey": session_id,
            },
        )

    async def _forward_socket_setup(
        self, session_id: str, app_id: str, page_id: int, automatically_pause: bool = False
    ) -> None:
        await self._send_message(
            "_rpc_forwardSocketSetup:",
            {
                "WIRApplicationIdentifierKey": app_id,
                "WIRPageIdentifierKey": page_id,
                "WIRSenderKey": session_id,
                "WIRMessageDataTypeChunkSupportedKey": 0,
                # Read by inspection targets only; an automation target's setup ignores it.
                "WIRAutomaticallyPause": automatically_pause,
            },
        )

    async def _forward_socket_data(self, session_id: str, app_id: str, page_id: int, data: dict[str, Any]):
        trace = getattr(self, "trace", None)
        if trace is not None:
            trace("bridge->device", session_id, data)
        await self._send_message(
            "_rpc_forwardSocketData:",
            {
                "WIRApplicationIdentifierKey": app_id,
                "WIRPageIdentifierKey": page_id,
                "WIRSessionIdentifierKey": session_id,
                "WIRSenderKey": session_id,
                "WIRSocketDataKey": json.dumps(data).encode(),
            },
        )

    async def _forward_did_close(self, session_id: str, app_id: str, page_id: int):
        await self._send_message(
            "_rpc_forwardDidClose:",
            {
                "WIRApplicationIdentifierKey": app_id,
                "WIRPageIdentifierKey": page_id,
                "WIRSenderKey": session_id,
            },
        )

    async def indicate_web_view(self, app: Application, page: Page, enable: bool) -> None:
        """Highlight a web page's view on the device screen (a translucent overlay, as Safari's
        Develop menu does while hovering a page), or clear the highlight.

        :param app: The application owning the page.
        :param page: The web page to highlight. JSContexts have nothing to highlight.
        :param enable: Whether to show or clear the highlight.
        """
        await self._forward_indicate_web_view(app.id_, page.id_, enable)

    async def _forward_indicate_web_view(self, app_id: str, page_id: int, enable: bool):
        await self._send_message(
            "_rpc_forwardIndicateWebView:",
            {
                "WIRApplicationIdentifierKey": app_id,
                "WIRPageIdentifierKey": page_id,
                "WIRIndicateEnabledKey": enable,
            },
        )

    async def _send_message(self, selector: str, args: Optional[dict[str, Any]] = None):
        if args is None:
            args = {}
        args["WIRConnectionIdentifierKey"] = self.connection_id
        # Never let a send establish the connection. While reconnecting, self._service is None and
        # self.service would lazily run the handshake - a second reader on the socket the reconnect
        # is already reading, which asyncio rejects ("readexactly() called while another coroutine
        # is already waiting"). A send with no live service (lost, or mid-reconnect) is a no-op.
        if self._connection_lost or self._service is None:
            return
        try:
            await self._service.send_plist({"__selector": selector, "__argument": args})
        except (ConnectionError, ConnectionTerminatedError, OSError, EOFError) as error:
            self._note_connection_lost(error)

    async def _wait_for_page(self, session_id: str) -> Page:
        while True:
            for app in self.application_pages.values():
                for page in app.values():
                    if page.type_ == WirTypes.AUTOMATION and page.automation_session_id == session_id:
                        return page
            await asyncio.sleep(0)

    @staticmethod
    async def _wait_for_automation_connection(page: Page) -> None:
        while not page.automation_connection_id:
            await asyncio.sleep(0)

    async def _wait_for_application(self, bundle: str = "", app_id: str = "") -> Application:
        while True:
            for app in self.connected_application.values():
                if bundle and app.bundle == bundle:
                    return app
                if app_id and app.id_ == app_id:
                    return app
            await asyncio.sleep(0)
```

### is_connected

```
is_connected: bool
```

Whether the device's Web Inspector connection is still up.

### connect

```
connect() -> None
```

Establish the WebInspector session and start the background receive task.

Performs the initial handshake (reporting this client's identifier and processing the first reply) while watching for a disabled notification, then spawns the task that keeps consuming incoming messages. Safe to call repeatedly; subsequent calls are a no-op once the receive task is running.

Raises:

| Type                          | Description                              |
| ----------------------------- | ---------------------------------------- |
| `WebInspectorNotEnabledError` | Web Inspector is disabled on the device. |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def connect(self) -> None:
    """Establish the WebInspector session and start the background receive task.

    Performs the initial handshake (reporting this client's identifier and processing the
    first reply) while watching for a disabled notification, then spawns the task that keeps
    consuming incoming messages. Safe to call repeatedly; subsequent calls are a no-op once
    the receive task is running.

    :raises WebInspectorNotEnabledError: Web Inspector is disabled on the device.
    """
    if self._recv_task is not None:
        return

    await self._connect_or_raise_disabled()
    self._recv_task = asyncio.create_task(self._receiving_task())
```

### close

```
close()
```

Cancel the background receive task and close the underlying service connection.

Source code in `pymobiledevice3/services/webinspector.py`

```
async def close(self):
    """Cancel the background receive task and close the underlying service connection."""
    if self._recv_task is not None:
        self._recv_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, ConnectionTerminatedError):
            await self._recv_task
        self._recv_task = None
    await super().close()
```

### automation_session

```
automation_session(app: Application, timeout: float = AUTOMATION_SESSION_TIMEOUT) -> AutomationSession
```

Start a WebDriver automation session against an application.

Requests a new automation session, waits for the corresponding automation page to appear, sets up its forwarding socket, and waits until the page reports an automation connection id.

Parameters:

| Name      | Type          | Description                                                              | Default                      |
| --------- | ------------- | ------------------------------------------------------------------------ | ---------------------------- |
| `app`     | `Application` | The application to automate.                                             | *required*                   |
| `timeout` | `float`       | Seconds to wait for each of the two steps the application has to answer. | `AUTOMATION_SESSION_TIMEOUT` |

Returns:

| Type                | Description                     |
| ------------------- | ------------------------------- |
| `AutomationSession` | A connected automation session. |

Raises:

| Type                                | Description                                                                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `RemoteAutomationNotEnabledError`   | Remote automation is not available on the device.                                                                  |
| `AutomationSessionUnavailableError` | The application did not start the session in time, typically because another client's automation session holds it. |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def automation_session(
    self, app: Application, timeout: float = AUTOMATION_SESSION_TIMEOUT
) -> AutomationSession:
    """Start a WebDriver automation session against an application.

    Requests a new automation session, waits for the corresponding automation page to appear,
    sets up its forwarding socket, and waits until the page reports an automation connection id.

    :param app: The application to automate.
    :param timeout: Seconds to wait for each of the two steps the application has to answer.
    :returns: A connected automation session.
    :raises RemoteAutomationNotEnabledError: Remote automation is not available on the device.
    :raises AutomationSessionUnavailableError: The application did not start the session in time,
        typically because another client's automation session holds it.
    """
    if self.state == "WIRAutomationAvailabilityNotAvailable":
        raise RemoteAutomationNotEnabledError()
    session_id = str(uuid.uuid4()).upper()
    await self._forward_automation_session_request(session_id, app.id_)
    await self._forward_get_listing(app.id_)
    try:
        page = await asyncio.wait_for(self._wait_for_page(session_id), timeout)
        await self._forward_socket_setup(session_id, app.id_, page.id_)
        await self._forward_get_listing(app.id_)
        await asyncio.wait_for(self._wait_for_automation_connection(page), timeout)
    except asyncio.TimeoutError:
        raise self._automation_session_unavailable(app, session_id, timeout) from None
    return AutomationSession(SessionProtocol(self, session_id, app, page))
```

### inspector_session

```
inspector_session(app: Application, page: Page) -> InspectorSession
```

Open a Web Inspector session against a specific page of an application.

Parameters:

| Name   | Type          | Description                      | Default    |
| ------ | ------------- | -------------------------------- | ---------- |
| `app`  | `Application` | The application owning the page. | *required* |
| `page` | `Page`        | The page to inspect.             | *required* |

Returns:

| Type               | Description                                                                                                           |
| ------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `InspectorSession` | A connected inspector session. For non-JavaScript pages the session waits for the inspection target before returning. |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def inspector_session(self, app: Application, page: Page) -> InspectorSession:
    """Open a Web Inspector session against a specific page of an application.

    :param app: The application owning the page.
    :param page: The page to inspect.
    :returns: A connected inspector session. For non-JavaScript pages the session waits for the
        inspection target before returning.
    """
    session_id = str(uuid.uuid4()).upper()
    return await InspectorSession.create(
        SessionProtocol(self, session_id, app, page, method_prefix=""),
        wait_target=page.type_ != WirTypes.JAVASCRIPT,
    )
```

### get_open_pages

```
get_open_pages() -> dict[str, Any]
```

Request and return the currently open pages of all connected applications.

Returns:

| Type             | Description                                                                                                                               |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `dict[str, Any]` | A mapping of application name to the collection of its Page objects, including only applications that currently report at least one page. |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def get_open_pages(self) -> dict[str, Any]:
    """Request and return the currently open pages of all connected applications.

    :returns: A mapping of application name to the collection of its `Page` objects, including
        only applications that currently report at least one page.
    """
    apps: dict[str, Any] = {}
    # One failing listing (or a lost connection) must not break the whole answer; serve what
    # was last reported instead.
    await asyncio.gather(
        *[self._forward_get_listing(app) for app in self.connected_application], return_exceptions=True
    )
    for app in self.connected_application:
        if self.application_pages.get(app, False):
            apps[self.connected_application[app].name] = self.application_pages[app].values()
    return apps
```

### get_open_application_pages

```
get_open_application_pages(timeout: float) -> list[ApplicationPage]
```

Enumerate all inspectable application/page pairs across connected applications.

Queries the connected applications and then waits for `webinspectord` to report their listings before collecting the results.

Parameters:

| Name      | Type    | Description                                                            | Default    |
| --------- | ------- | ---------------------------------------------------------------------- | ---------- |
| `timeout` | `float` | Seconds to wait for the device to reply with the application listings. | *required* |

Returns:

| Type                    | Description                                             |
| ----------------------- | ------------------------------------------------------- |
| `list[ApplicationPage]` | A list of ApplicationPage pairs, one per reported page. |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def get_open_application_pages(self, timeout: float) -> list[ApplicationPage]:
    """Enumerate all inspectable application/page pairs across connected applications.

    Queries the connected applications and then waits for `webinspectord` to report their
    listings before collecting the results.

    :param timeout: Seconds to wait for the device to reply with the application listings.
    :returns: A list of `ApplicationPage` pairs, one per reported page.
    """
    # Query all connected applications
    await self._get_connected_applications()

    # Give some time for `webinspectord` to reply with all inspectable applications
    await asyncio.sleep(timeout)

    result: list[ApplicationPage] = []
    for app in self.connected_application:
        if self.application_pages.get(app, False):
            for page in self.application_pages[app].values():
                result.append(ApplicationPage(self.connected_application[app], page))
    return result
```

### open_app

```
open_app(bundle: str, timeout: Union[float, int] = 3) -> Application
```

Launch an application by bundle identifier and wait for it to connect.

Parameters:

| Name      | Type                | Description                                                 | Default    |
| --------- | ------------------- | ----------------------------------------------------------- | ---------- |
| `bundle`  | `str`               | The bundle identifier of the application to launch.         | *required* |
| `timeout` | `Union[float, int]` | Seconds to wait for the application to appear as connected. | `3`        |

Returns:

| Type          | Description                |
| ------------- | -------------------------- |
| `Application` | The connected application. |

Raises:

| Type                        | Description                                         |
| --------------------------- | --------------------------------------------------- |
| `LaunchingApplicationError` | The application did not connect within the timeout. |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def open_app(self, bundle: str, timeout: Union[float, int] = 3) -> Application:
    """Launch an application by bundle identifier and wait for it to connect.

    :param bundle: The bundle identifier of the application to launch.
    :param timeout: Seconds to wait for the application to appear as connected.
    :returns: The connected application.
    :raises LaunchingApplicationError: The application did not connect within the timeout.
    """
    await self._request_application_launch(bundle)
    await self.get_open_pages()
    try:
        return await asyncio.wait_for(self._wait_for_application(bundle), timeout)
    except asyncio.TimeoutError as e:  # not the builtin TimeoutError before Python 3.11
        raise LaunchingApplicationError() from e
```

### send_socket_data

```
send_socket_data(session_id: str, app_id: str, page_id: int, data: dict[str, Any])
```

Forward an inspector/automation protocol message to a page's socket.

Parameters:

| Name         | Type             | Description                                                         | Default    |
| ------------ | ---------------- | ------------------------------------------------------------------- | ---------- |
| `session_id` | `str`            | The session identifier owning the socket.                           | *required* |
| `app_id`     | `str`            | The target application identifier.                                  | *required* |
| `page_id`    | `int`            | The target page identifier.                                         | *required* |
| `data`       | `dict[str, Any]` | The protocol message to send; serialized to JSON before forwarding. | *required* |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def send_socket_data(self, session_id: str, app_id: str, page_id: int, data: dict[str, Any]):
    """Forward an inspector/automation protocol message to a page's socket.

    :param session_id: The session identifier owning the socket.
    :param app_id: The target application identifier.
    :param page_id: The target page identifier.
    :param data: The protocol message to send; serialized to JSON before forwarding.
    """
    await self._forward_socket_data(session_id, app_id, page_id, data)
```

### setup_inspector_socket

```
setup_inspector_socket(session_id: str, app_id: str, page_id: int, automatically_pause: bool = False) -> None
```

Set up a forwarding socket for an inspector session.

Parameters:

| Name                  | Type   | Description                                                                                                                                                                                                                                                                          | Default    |
| --------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| `session_id`          | `str`  | The session identifier to associate with the socket.                                                                                                                                                                                                                                 | *required* |
| `app_id`              | `str`  | The target application identifier.                                                                                                                                                                                                                                                   | *required* |
| `page_id`             | `int`  | The target page identifier.                                                                                                                                                                                                                                                          | *required* |
| `automatically_pause` | `bool` | Ask WebKit to pause the debuggable on its next statement once the frontend reports itself initialized (Inspector.initialized) - Safari's "Automatically Pause Connecting to JSContexts". Honoured by JSContexts, service workers and legacy WebViews; a WKWebView's page ignores it. | `False`    |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def setup_inspector_socket(
    self, session_id: str, app_id: str, page_id: int, automatically_pause: bool = False
) -> None:
    """Set up a forwarding socket for an inspector session.

    :param session_id: The session identifier to associate with the socket.
    :param app_id: The target application identifier.
    :param page_id: The target page identifier.
    :param automatically_pause: Ask WebKit to pause the debuggable on its next statement once
        the frontend reports itself initialized (`Inspector.initialized`) - Safari's
        "Automatically Pause Connecting to JSContexts". Honoured by JSContexts, service
        workers and legacy WebViews; a WKWebView's page ignores it.
    """
    await self._forward_socket_setup(session_id, app_id, page_id, automatically_pause=automatically_pause)
```

### set_automatic_inspection_enabled

```
set_automatic_inspection_enabled(enabled: bool) -> None
```

Ask `webinspectord` to offer this connection every debuggable an application creates, before the application gets to run it (see `AutomaticInspectionCandidate`).

While any connection has this enabled, every application holds each new JSContext until the candidate is answered; subscribe with `subscribe_automatic_inspection` first, and switch it off again when done.

Parameters:

| Name      | Type   | Description                    | Default    |
| --------- | ------ | ------------------------------ | ---------- |
| `enabled` | `bool` | Whether to receive candidates. | *required* |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def set_automatic_inspection_enabled(self, enabled: bool) -> None:
    """Ask `webinspectord` to offer this connection every debuggable an application creates,
    before the application gets to run it (see `AutomaticInspectionCandidate`).

    While any connection has this enabled, every application holds each new JSContext until
    the candidate is answered; subscribe with `subscribe_automatic_inspection` first, and
    switch it off again when done.

    :param enabled: Whether to receive candidates.
    """
    await self._send_message(
        "_rpc_forwardAutomaticInspectionConfiguration:", {"WIRAutomaticInspectionEnabledKey": enabled}
    )
```

### subscribe_automatic_inspection

```
subscribe_automatic_inspection() -> asyncio.Queue[AutomaticInspectionCandidate]
```

Receive automatic-inspection candidates as they are offered.

A candidate is accepted by setting up an inspector socket for its page and completing the frontend handshake, or declined with `reject_automatic_inspection`. Candidates offered while nobody is subscribed are declined on the spot, so applications never wait on this client.

Returns:

| Type                                  | Description                                                                                            |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `Queue[AutomaticInspectionCandidate]` | A queue the candidates are published into; hand it back to unsubscribe_automatic_inspection when done. |

Source code in `pymobiledevice3/services/webinspector.py`

```
def subscribe_automatic_inspection(self) -> "asyncio.Queue[AutomaticInspectionCandidate]":
    """Receive automatic-inspection candidates as they are offered.

    A candidate is accepted by setting up an inspector socket for its page and completing the
    frontend handshake, or declined with `reject_automatic_inspection`. Candidates offered while
    nobody is subscribed are declined on the spot, so applications never wait on this client.

    :returns: A queue the candidates are published into; hand it back to
        `unsubscribe_automatic_inspection` when done.
    """
    queue: asyncio.Queue[AutomaticInspectionCandidate] = asyncio.Queue()
    self._candidate_subscribers.append(queue)
    return queue
```

### reject_automatic_inspection

```
reject_automatic_inspection(candidate: AutomaticInspectionCandidate) -> None
```

Decline a candidate, letting the application resume (or be offered to the next debugger).

Parameters:

| Name        | Type                           | Description                                                   | Default    |
| ----------- | ------------------------------ | ------------------------------------------------------------- | ---------- |
| `candidate` | `AutomaticInspectionCandidate` | The candidate as published by subscribe_automatic_inspection. | *required* |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def reject_automatic_inspection(self, candidate: AutomaticInspectionCandidate) -> None:
    """Decline a candidate, letting the application resume (or be offered to the next debugger).

    :param candidate: The candidate as published by `subscribe_automatic_inspection`.
    """
    await self._send_message(
        "_rpc_forwardAutomaticInspectionRejection:",
        {
            "WIRApplicationIdentifierKey": candidate.app_id,
            "WIRPageIdentifierKey": candidate.page_id,
            "WIRAutomaticInspectionSessionIdentifierKey": candidate.session_id,
        },
    )
```

### subscribe_listings

```
subscribe_listings() -> asyncio.Queue[str]
```

Be told whenever an application's page listing arrives - `webinspectord` relays one on its own the moment a page opens, closes or navigates.

Returns:

| Type         | Description                                                                                                                        |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `Queue[str]` | A queue the identifier of the application whose listing changed is published into; hand it back to unsubscribe_listings when done. |

Source code in `pymobiledevice3/services/webinspector.py`

```
def subscribe_listings(self) -> "asyncio.Queue[str]":
    """Be told whenever an application's page listing arrives - `webinspectord` relays one on
    its own the moment a page opens, closes or navigates.

    :returns: A queue the identifier of the application whose listing changed is published
        into; hand it back to `unsubscribe_listings` when done.
    """
    queue: asyncio.Queue[str] = asyncio.Queue()
    self._listing_subscribers.append(queue)
    return queue
```

### teardown_inspector_socket

```
teardown_inspector_socket(session_id: str, app_id: str, page_id: int)
```

Tear down a forwarding socket previously set up for an inspector session.

Without this, webinspectord considers the session still active and ignores the next socket setup for the same page, so a future session never receives its target events.

Parameters:

| Name         | Type  | Description                                            | Default    |
| ------------ | ----- | ------------------------------------------------------ | ---------- |
| `session_id` | `str` | The session identifier the socket was associated with. | *required* |
| `app_id`     | `str` | The target application identifier.                     | *required* |
| `page_id`    | `int` | The target page identifier.                            | *required* |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def teardown_inspector_socket(self, session_id: str, app_id: str, page_id: int):
    """Tear down a forwarding socket previously set up for an inspector session.

    Without this, webinspectord considers the session still active and ignores the next
    socket setup for the same page, so a future session never receives its target events.

    :param session_id: The session identifier the socket was associated with.
    :param app_id: The target application identifier.
    :param page_id: The target page identifier.
    """
    await self._forward_did_close(session_id, app_id, page_id)
    self.wir_events.pop(session_id, None)
```

### session_events

```
session_events(session_id: str) -> deque[Any]
```

The queue of events `webinspectord` forwarded to one session's socket.

Events carry no id, so a consumer cannot tell its own from another's by content, and WebKit allows one inspector session per page but several across pages. `webinspectord` tags every forwarded message with the session it belongs to, so they are queued per session: concurrent sessions - two DevTools tabs, two JSContexts - would otherwise consume each other's events.

Parameters:

| Name         | Type  | Description                                        | Default    |
| ------------ | ----- | -------------------------------------------------- | ---------- |
| `session_id` | `str` | The session identifier the socket was set up with. | *required* |

Returns:

| Type         | Description                                                                                         |
| ------------ | --------------------------------------------------------------------------------------------------- |
| `deque[Any]` | The session's queue (a deque, so consuming from the front is O(1)); consumers pop from it in place. |

Source code in `pymobiledevice3/services/webinspector.py`

```
def session_events(self, session_id: str) -> deque[Any]:
    """The queue of events `webinspectord` forwarded to one session's socket.

    Events carry no id, so a consumer cannot tell its own from another's by content, and
    WebKit allows one inspector session per page but several across pages. `webinspectord`
    tags every forwarded message with the session it belongs to, so they are queued per
    session: concurrent sessions - two DevTools tabs, two JSContexts - would otherwise
    consume each other's events.

    :param session_id: The session identifier the socket was set up with.
    :returns: The session's queue (a deque, so consuming from the front is O(1)); consumers pop
        from it in place.
    """
    return self.wir_events.setdefault(session_id, deque())
```

### find_page_id

```
find_page_id(page_id: str) -> tuple[Application, Page]
```

Look up the application and page for a known page identifier.

Parameters:

| Name      | Type  | Description                                                                                                                                                                                                                                                                               | Default    |
| --------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| `page_id` | `str` | An identifier as built by make_target_id. A bare page identifier is also accepted, resolving to the first application reporting it - note that page identifiers are only unique per application (every JSContext debuggable is page 1 of its own process), so it cannot address them all. | *required* |

Returns:

| Type                       | Description                                              |
| -------------------------- | -------------------------------------------------------- |
| `tuple[Application, Page]` | A tuple of the owning application and the matching page. |

Raises:

| Type       | Description                                           |
| ---------- | ----------------------------------------------------- |
| `KeyError` | No page with the given identifier is currently known. |

Source code in `pymobiledevice3/services/webinspector.py`

```
def find_page_id(self, page_id: str) -> tuple[Application, Page]:
    """Look up the application and page for a known page identifier.

    :param page_id: An identifier as built by `make_target_id`. A bare page identifier is also
        accepted, resolving to the first application reporting it - note that page identifiers
        are only unique per application (every JSContext debuggable is page 1 of its own
        process), so it cannot address them all.
    :returns: A tuple of the owning application and the matching page.
    :raises KeyError: No page with the given identifier is currently known.
    """
    app_id, _, page_key = page_id.rpartition(":")
    if page_key in self.application_pages.get(app_id, {}):
        return self.connected_application[app_id], self.application_pages[app_id][page_key]
    for app_id in self.application_pages:
        for page in self.application_pages[app_id]:
            if page == page_id:
                return self.connected_application[app_id], self.application_pages[app_id][page_id]
    raise KeyError(f"Page with id {page_id} not found")
```

### flush_input

```
flush_input(duration: Union[float, int] = 0)
```

Yield control for the given duration to let pending incoming messages be processed.

Parameters:

| Name       | Type                | Description                                                      | Default |
| ---------- | ------------------- | ---------------------------------------------------------------- | ------- |
| `duration` | `Union[float, int]` | Seconds to sleep while the background receive task drains input. | `0`     |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def flush_input(self, duration: Union[float, int] = 0):
    """Yield control for the given duration to let pending incoming messages be processed.

    :param duration: Seconds to sleep while the background receive task drains input.
    """
    return await asyncio.sleep(duration)
```

### indicate_web_view

```
indicate_web_view(app: Application, page: Page, enable: bool) -> None
```

Highlight a web page's view on the device screen (a translucent overlay, as Safari's Develop menu does while hovering a page), or clear the highlight.

Parameters:

| Name     | Type          | Description                                                      | Default    |
| -------- | ------------- | ---------------------------------------------------------------- | ---------- |
| `app`    | `Application` | The application owning the page.                                 | *required* |
| `page`   | `Page`        | The web page to highlight. JSContexts have nothing to highlight. | *required* |
| `enable` | `bool`        | Whether to show or clear the highlight.                          | *required* |

Source code in `pymobiledevice3/services/webinspector.py`

```
async def indicate_web_view(self, app: Application, page: Page, enable: bool) -> None:
    """Highlight a web page's view on the device screen (a translucent overlay, as Safari's
    Develop menu does while hovering a page), or clear the highlight.

    :param app: The application owning the page.
    :param page: The web page to highlight. JSContexts have nothing to highlight.
    :param enable: Whether to show or clear the highlight.
    """
    await self._forward_indicate_web_view(app.id_, page.id_, enable)
```

## pymobiledevice3.services.wda.WdaServiceClient

Async WDA client that reaches the WDA server through a LockdownServiceProvider connection.

Instead of relying on a pre-existing local HTTP forwarder, this client opens a service connection to the WDA port on the device for each request (via usbmux for an RSD-backed provider, otherwise through the provider directly), writes a raw HTTP/1.1 request, and parses the response. It exposes the same WebDriver actions as `WdaClient` as coroutines. The session id returned by `start_session` is cached on `session_id` and used as the default for later calls.

Source code in `pymobiledevice3/services/wda.py`

```
@dataclass
class WdaServiceClient:
    """Async WDA client that reaches the WDA server through a LockdownServiceProvider connection.

    Instead of relying on a pre-existing local HTTP forwarder, this client opens a service
    connection to the WDA port on the device for each request (via usbmux for an RSD-backed
    provider, otherwise through the provider directly), writes a raw HTTP/1.1 request, and parses
    the response. It exposes the same WebDriver actions as `WdaClient` as coroutines. The session
    id returned by `start_session` is cached on `session_id` and used as the default for later calls.
    """

    service_provider: LockdownServiceProvider
    port: int = DEFAULT_WDA_PORT
    timeout: float = 10.0
    session_id: Optional[str] = None

    async def _request_json(self, method: str, path: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Send a WDA request over a service connection and parse JSON."""
        body = b""
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        headers = [
            f"{method} {path} HTTP/1.1",
            "Host: localhost",
            "Connection: close",
        ]
        if payload is not None:
            headers.append("Content-Type: application/json")
        headers.append(f"Content-Length: {len(body)}")
        request_bytes = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body

        if isinstance(self.service_provider, RemoteServiceDiscoveryService):
            conn = await ServiceConnection.create_using_usbmux(
                self.service_provider.udid,
                self.port,
                usbmux_address=getattr(self.service_provider.lockdown, "usbmux_address", None),
            )
        else:
            conn = await self.service_provider.create_service_connection(self.port)
        async with conn:
            await conn.sendall(request_bytes)

            header_bytes, body_prefix = await self._read_until(conn, b"\r\n\r\n")
            header_text = header_bytes.decode("iso-8859-1")
            lines = header_text.split("\r\n")
            status_line = lines[0]
            status_code = int(status_line.split(" ", 2)[1])

            response_headers: dict[str, str] = {}
            for line in lines[1:]:
                if not line:
                    continue
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                response_headers[k.strip().lower()] = v.strip()

            content_length = response_headers.get("content-length")
            if content_length is not None:
                try:
                    length = int(content_length)
                except ValueError:
                    length = 0
                if length <= len(body_prefix):
                    body_bytes = body_prefix[:length]
                else:
                    remainder = length - len(body_prefix)
                    body_bytes = body_prefix + await conn.recvall(remainder)
            else:
                chunks = [body_prefix] if body_prefix else []
                while True:
                    chunk = await conn.recv_any(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                body_bytes = b"".join(chunks)

        try:
            data: dict[str, Any] = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except ValueError as exc:
            raise WdaError(
                f"WDA sent a reply that is not JSON (HTTP status {status_code}).", status_code=status_code
            ) from exc

        if status_code >= 400:
            raise WdaError(WdaClient._format_error(data, status_code), status_code=status_code)

        status = data.get("status")
        if status not in (None, 0, "0"):
            raise WdaError(WdaClient._format_error(data, status_code), status_code=status_code)

        return data

    async def _read_until(self, conn: ServiceConnection, marker: bytes) -> tuple[bytes, bytes]:
        """Read from a connection until a marker is found."""
        buf = b""
        while marker not in buf:
            chunk = await conn.recv_any(65536)
            if not chunk:
                break
            buf += chunk
        if marker not in buf:
            raise WdaError("WDA closed the connection before sending complete HTTP headers.")
        header_bytes, body_prefix = buf.split(marker, 1)
        return header_bytes, body_prefix

    async def start_session(self, bundle_id: Optional[str] = None) -> str:
        """Start a WDA session, optionally launching a specific application.

        :param bundle_id: Bundle identifier of the app to attach the session to; if omitted no
            specific app capability is requested.
        :returns: The created session id, also cached on `session_id`.
        :raises WdaError: WDA did not return a session id.
        """
        caps: dict[str, Any] = {}
        if bundle_id:
            caps["bundleId"] = bundle_id
        payload: dict[str, Any] = {
            "capabilities": {"alwaysMatch": caps},
            "desiredCapabilities": caps,
        }
        data = await self._request_json("POST", "/session", payload)
        session_id = data.get("sessionId")
        if not session_id:
            value = data.get("value")
            if isinstance(value, dict):
                session_id = cast(dict[str, Any], value).get("sessionId")
        if not session_id:
            raise WdaError("WDA did not return a session id when starting the session.")
        self.session_id = session_id
        return session_id

    async def find_element(self, using: str, value: str, session_id: Optional[str] = None) -> str:
        """Locate a single UI element and return its element id.

        :param using: The locator strategy (e.g. `accessibility id`, `class name`, `xpath`).
        :param value: The locator value matched against `using`.
        :param session_id: Session to use; defaults to the cached `session_id`.
        :returns: The resolved element id.
        :raises WdaError: No session id is available, or WDA did not return an element id.
        """
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        data = await self._request_json(
            "POST",
            f"/session/{session_id}/element",
            {"using": using, "value": value},
        )
        element = data.get("value")
        if not isinstance(element, dict):
            raise WdaError(f"WDA returned no element for {using} {value!r}")
        element = cast(dict[str, Any], element)
        element_id = (
            element.get("ELEMENT") or element.get("element-6066-11e4-a52e-4f735466cecf") or element.get("element")
        )
        if not element_id:
            raise WdaError(f"WDA returned an element without an id for {using} {value!r}")
        return element_id

    async def click(self, element_id: str, session_id: Optional[str] = None) -> None:
        """Tap an element by its element id.

        :param element_id: The element id to click.
        :param session_id: Session to use; defaults to the cached `session_id`.
        :raises WdaError: No session id is available.
        """
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        await self._request_json("POST", f"/session/{session_id}/element/{element_id}/click", {})

    async def press_button(self, name: str, session_id: Optional[str] = None) -> None:
        """Press a hardware/device button by name.

        The name is normalized to a WDA button name. When a session is given the session-scoped
        `pressButton` endpoint is tried first, falling back to the session keys endpoint; as a last
        resort, `home` is delivered via the global home-screen endpoint.

        :param name: Button name or alias (e.g. `home`, `volumeUp`, `lock`).
        :param session_id: Session to use; if omitted only the global `home` fallback applies.
        :raises WdaError: WDA supports neither the pressButton nor keys endpoints for this button.
        """
        normalized = normalize_wda_button_name(name)
        payload = {"name": normalized}
        if session_id:
            try:
                await self._request_json("POST", f"/session/{session_id}/wda/pressButton", payload)
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return
            if await self._try_keys_endpoint(session_id, normalized):
                return
        if normalized == "home":
            await self._request_json("POST", "/wda/homescreen", {})
            return
        raise WdaError(
            "This WDA build cannot press buttons: it has neither the pressButton nor the keys endpoint.",
            status_code=404,
        )

    async def unlock(self, session_id: Optional[str] = None) -> None:
        """Unlock the device, trying the session-scoped endpoint then the global one.

        :param session_id: Session to use; defaults to the cached `session_id`.
        :raises WdaError: WDA does not support the unlock endpoint.
        """
        session_id = session_id or self.session_id
        if session_id:
            try:
                await self._request_json("POST", f"/session/{session_id}/wda/unlock", {})
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return
        try:
            await self._request_json("POST", "/wda/unlock", {})
        except WdaError as exc:
            if exc.status_code != 404:
                raise
            raise WdaError(
                "This WDA build cannot unlock the device: it has no unlock endpoint.", status_code=404
            ) from exc

    async def get_source(self, session_id: Optional[str] = None) -> str:
        """Fetch the current UI hierarchy as an XML source tree.

        :param session_id: Session to query; if omitted the global source endpoint is used.
        :returns: The XML source string.
        :raises WdaError: WDA did not return a source string.
        """
        if session_id:
            data = await self._request_json("GET", f"/session/{session_id}/source", None)
        else:
            data = await self._request_json("GET", "/source", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return the UI source tree.")
        return value

    async def get_screenshot(self, session_id: Optional[str] = None) -> bytes:
        """Capture a screenshot and return the decoded PNG bytes.

        :param session_id: Session to query; if omitted the global screenshot endpoint is used.
        :returns: The raw PNG image bytes (base64-decoded from the WDA response).
        :raises WdaError: WDA did not return a screenshot.
        """
        if session_id:
            data = await self._request_json("GET", f"/session/{session_id}/screenshot", None)
        else:
            data = await self._request_json("GET", "/screenshot", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a screenshot.")
        return base64.b64decode(value)

    async def get_status(self) -> dict[str, Any]:
        """Return the WDA `/status` payload describing the server and device state.

        :returns: The parsed status response.
        """
        return await self._request_json("GET", "/status", None)

    async def get_window_size(self, session_id: Optional[str] = None) -> dict[str, Any]:
        """Return the current window size.

        :param session_id: Session to query; required.
        :returns: A mapping with the window dimensions (e.g. `width`, `height`).
        :raises WdaError: No session id is available, or WDA did not return a window size.
        """
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        data = await self._request_json("GET", f"/session/{session_id}/window/size", None)
        value = data.get("value")
        if not isinstance(value, dict):
            raise WdaError("WDA did not return the window size.")
        return cast(dict[str, Any], value)

    async def send_keys(self, text: str, session_id: Optional[str] = None) -> None:
        """Type text into the currently focused element.

        Sends the text as individual characters, trying the `wda/keys` endpoint first and falling
        back to the plain `keys` endpoint if the former is unavailable.

        :param text: The text to type.
        :param session_id: Session to use; required.
        :raises WdaError: No session id is available.
        """
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        payload = {"value": list(text)}
        try:
            await self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
        except WdaError as exc:
            if exc.status_code != 404:
                raise
            await self._request_json("POST", f"/session/{session_id}/keys", payload)

    async def swipe(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        duration: float = 0.2,
        session_id: Optional[str] = None,
    ) -> None:
        """Drag from a start coordinate to an end coordinate over a duration.

        :param start_x: Starting x coordinate.
        :param start_y: Starting y coordinate.
        :param end_x: Ending x coordinate.
        :param end_y: Ending y coordinate.
        :param duration: Gesture duration in seconds.
        :param session_id: Session to use; required.
        :raises WdaError: No session id is available.
        """
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        payload: dict[str, Any] = {
            "fromX": start_x,
            "fromY": start_y,
            "toX": end_x,
            "toY": end_y,
            "duration": duration,
        }
        await self._request_json("POST", f"/session/{session_id}/wda/dragfromtoforduration", payload)

    async def _try_keys_endpoint(self, session_id: Optional[str], normalized: str) -> bool:
        """Try the session keys endpoint for button presses."""
        key = normalize_wda_key_name(normalized)
        payload = {"keys": [key]}
        if session_id:
            try:
                await self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return True
        return False
```

### start_session

```
start_session(bundle_id: Optional[str] = None) -> str
```

Start a WDA session, optionally launching a specific application.

Parameters:

| Name        | Type            | Description                                                                                                | Default |
| ----------- | --------------- | ---------------------------------------------------------------------------------------------------------- | ------- |
| `bundle_id` | `Optional[str]` | Bundle identifier of the app to attach the session to; if omitted no specific app capability is requested. | `None`  |

Returns:

| Type  | Description                                        |
| ----- | -------------------------------------------------- |
| `str` | The created session id, also cached on session_id. |

Raises:

| Type       | Description                      |
| ---------- | -------------------------------- |
| `WdaError` | WDA did not return a session id. |

Source code in `pymobiledevice3/services/wda.py`

```
async def start_session(self, bundle_id: Optional[str] = None) -> str:
    """Start a WDA session, optionally launching a specific application.

    :param bundle_id: Bundle identifier of the app to attach the session to; if omitted no
        specific app capability is requested.
    :returns: The created session id, also cached on `session_id`.
    :raises WdaError: WDA did not return a session id.
    """
    caps: dict[str, Any] = {}
    if bundle_id:
        caps["bundleId"] = bundle_id
    payload: dict[str, Any] = {
        "capabilities": {"alwaysMatch": caps},
        "desiredCapabilities": caps,
    }
    data = await self._request_json("POST", "/session", payload)
    session_id = data.get("sessionId")
    if not session_id:
        value = data.get("value")
        if isinstance(value, dict):
            session_id = cast(dict[str, Any], value).get("sessionId")
    if not session_id:
        raise WdaError("WDA did not return a session id when starting the session.")
    self.session_id = session_id
    return session_id
```

### find_element

```
find_element(using: str, value: str, session_id: Optional[str] = None) -> str
```

Locate a single UI element and return its element id.

Parameters:

| Name         | Type            | Description                                                      | Default    |
| ------------ | --------------- | ---------------------------------------------------------------- | ---------- |
| `using`      | `str`           | The locator strategy (e.g. accessibility id, class name, xpath). | *required* |
| `value`      | `str`           | The locator value matched against using.                         | *required* |
| `session_id` | `Optional[str]` | Session to use; defaults to the cached session_id.               | `None`     |

Returns:

| Type  | Description              |
| ----- | ------------------------ |
| `str` | The resolved element id. |

Raises:

| Type       | Description                                                      |
| ---------- | ---------------------------------------------------------------- |
| `WdaError` | No session id is available, or WDA did not return an element id. |

Source code in `pymobiledevice3/services/wda.py`

```
async def find_element(self, using: str, value: str, session_id: Optional[str] = None) -> str:
    """Locate a single UI element and return its element id.

    :param using: The locator strategy (e.g. `accessibility id`, `class name`, `xpath`).
    :param value: The locator value matched against `using`.
    :param session_id: Session to use; defaults to the cached `session_id`.
    :returns: The resolved element id.
    :raises WdaError: No session id is available, or WDA did not return an element id.
    """
    session_id = session_id or self.session_id
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    data = await self._request_json(
        "POST",
        f"/session/{session_id}/element",
        {"using": using, "value": value},
    )
    element = data.get("value")
    if not isinstance(element, dict):
        raise WdaError(f"WDA returned no element for {using} {value!r}")
    element = cast(dict[str, Any], element)
    element_id = (
        element.get("ELEMENT") or element.get("element-6066-11e4-a52e-4f735466cecf") or element.get("element")
    )
    if not element_id:
        raise WdaError(f"WDA returned an element without an id for {using} {value!r}")
    return element_id
```

### click

```
click(element_id: str, session_id: Optional[str] = None) -> None
```

Tap an element by its element id.

Parameters:

| Name         | Type            | Description                                        | Default    |
| ------------ | --------------- | -------------------------------------------------- | ---------- |
| `element_id` | `str`           | The element id to click.                           | *required* |
| `session_id` | `Optional[str]` | Session to use; defaults to the cached session_id. | `None`     |

Raises:

| Type       | Description                 |
| ---------- | --------------------------- |
| `WdaError` | No session id is available. |

Source code in `pymobiledevice3/services/wda.py`

```
async def click(self, element_id: str, session_id: Optional[str] = None) -> None:
    """Tap an element by its element id.

    :param element_id: The element id to click.
    :param session_id: Session to use; defaults to the cached `session_id`.
    :raises WdaError: No session id is available.
    """
    session_id = session_id or self.session_id
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    await self._request_json("POST", f"/session/{session_id}/element/{element_id}/click", {})
```

### press_button

```
press_button(name: str, session_id: Optional[str] = None) -> None
```

Press a hardware/device button by name.

The name is normalized to a WDA button name. When a session is given the session-scoped `pressButton` endpoint is tried first, falling back to the session keys endpoint; as a last resort, `home` is delivered via the global home-screen endpoint.

Parameters:

| Name         | Type            | Description                                                       | Default    |
| ------------ | --------------- | ----------------------------------------------------------------- | ---------- |
| `name`       | `str`           | Button name or alias (e.g. home, volumeUp, lock).                 | *required* |
| `session_id` | `Optional[str]` | Session to use; if omitted only the global home fallback applies. | `None`     |

Raises:

| Type       | Description                                                              |
| ---------- | ------------------------------------------------------------------------ |
| `WdaError` | WDA supports neither the pressButton nor keys endpoints for this button. |

Source code in `pymobiledevice3/services/wda.py`

```
async def press_button(self, name: str, session_id: Optional[str] = None) -> None:
    """Press a hardware/device button by name.

    The name is normalized to a WDA button name. When a session is given the session-scoped
    `pressButton` endpoint is tried first, falling back to the session keys endpoint; as a last
    resort, `home` is delivered via the global home-screen endpoint.

    :param name: Button name or alias (e.g. `home`, `volumeUp`, `lock`).
    :param session_id: Session to use; if omitted only the global `home` fallback applies.
    :raises WdaError: WDA supports neither the pressButton nor keys endpoints for this button.
    """
    normalized = normalize_wda_button_name(name)
    payload = {"name": normalized}
    if session_id:
        try:
            await self._request_json("POST", f"/session/{session_id}/wda/pressButton", payload)
        except WdaError as exc:
            if exc.status_code != 404:
                raise
        else:
            return
        if await self._try_keys_endpoint(session_id, normalized):
            return
    if normalized == "home":
        await self._request_json("POST", "/wda/homescreen", {})
        return
    raise WdaError(
        "This WDA build cannot press buttons: it has neither the pressButton nor the keys endpoint.",
        status_code=404,
    )
```

### unlock

```
unlock(session_id: Optional[str] = None) -> None
```

Unlock the device, trying the session-scoped endpoint then the global one.

Parameters:

| Name         | Type            | Description                                        | Default |
| ------------ | --------------- | -------------------------------------------------- | ------- |
| `session_id` | `Optional[str]` | Session to use; defaults to the cached session_id. | `None`  |

Raises:

| Type       | Description                               |
| ---------- | ----------------------------------------- |
| `WdaError` | WDA does not support the unlock endpoint. |

Source code in `pymobiledevice3/services/wda.py`

```
async def unlock(self, session_id: Optional[str] = None) -> None:
    """Unlock the device, trying the session-scoped endpoint then the global one.

    :param session_id: Session to use; defaults to the cached `session_id`.
    :raises WdaError: WDA does not support the unlock endpoint.
    """
    session_id = session_id or self.session_id
    if session_id:
        try:
            await self._request_json("POST", f"/session/{session_id}/wda/unlock", {})
        except WdaError as exc:
            if exc.status_code != 404:
                raise
        else:
            return
    try:
        await self._request_json("POST", "/wda/unlock", {})
    except WdaError as exc:
        if exc.status_code != 404:
            raise
        raise WdaError(
            "This WDA build cannot unlock the device: it has no unlock endpoint.", status_code=404
        ) from exc
```

### get_source

```
get_source(session_id: Optional[str] = None) -> str
```

Fetch the current UI hierarchy as an XML source tree.

Parameters:

| Name         | Type            | Description                                                      | Default |
| ------------ | --------------- | ---------------------------------------------------------------- | ------- |
| `session_id` | `Optional[str]` | Session to query; if omitted the global source endpoint is used. | `None`  |

Returns:

| Type  | Description            |
| ----- | ---------------------- |
| `str` | The XML source string. |

Raises:

| Type       | Description                         |
| ---------- | ----------------------------------- |
| `WdaError` | WDA did not return a source string. |

Source code in `pymobiledevice3/services/wda.py`

```
async def get_source(self, session_id: Optional[str] = None) -> str:
    """Fetch the current UI hierarchy as an XML source tree.

    :param session_id: Session to query; if omitted the global source endpoint is used.
    :returns: The XML source string.
    :raises WdaError: WDA did not return a source string.
    """
    if session_id:
        data = await self._request_json("GET", f"/session/{session_id}/source", None)
    else:
        data = await self._request_json("GET", "/source", None)
    value = data.get("value")
    if not isinstance(value, str):
        raise WdaError("WDA did not return the UI source tree.")
    return value
```

### get_screenshot

```
get_screenshot(session_id: Optional[str] = None) -> bytes
```

Capture a screenshot and return the decoded PNG bytes.

Parameters:

| Name         | Type            | Description                                                          | Default |
| ------------ | --------------- | -------------------------------------------------------------------- | ------- |
| `session_id` | `Optional[str]` | Session to query; if omitted the global screenshot endpoint is used. | `None`  |

Returns:

| Type    | Description                                                     |
| ------- | --------------------------------------------------------------- |
| `bytes` | The raw PNG image bytes (base64-decoded from the WDA response). |

Raises:

| Type       | Description                      |
| ---------- | -------------------------------- |
| `WdaError` | WDA did not return a screenshot. |

Source code in `pymobiledevice3/services/wda.py`

```
async def get_screenshot(self, session_id: Optional[str] = None) -> bytes:
    """Capture a screenshot and return the decoded PNG bytes.

    :param session_id: Session to query; if omitted the global screenshot endpoint is used.
    :returns: The raw PNG image bytes (base64-decoded from the WDA response).
    :raises WdaError: WDA did not return a screenshot.
    """
    if session_id:
        data = await self._request_json("GET", f"/session/{session_id}/screenshot", None)
    else:
        data = await self._request_json("GET", "/screenshot", None)
    value = data.get("value")
    if not isinstance(value, str):
        raise WdaError("WDA did not return a screenshot.")
    return base64.b64decode(value)
```

### get_status

```
get_status() -> dict[str, Any]
```

Return the WDA `/status` payload describing the server and device state.

Returns:

| Type             | Description                 |
| ---------------- | --------------------------- |
| `dict[str, Any]` | The parsed status response. |

Source code in `pymobiledevice3/services/wda.py`

```
async def get_status(self) -> dict[str, Any]:
    """Return the WDA `/status` payload describing the server and device state.

    :returns: The parsed status response.
    """
    return await self._request_json("GET", "/status", None)
```

### get_window_size

```
get_window_size(session_id: Optional[str] = None) -> dict[str, Any]
```

Return the current window size.

Parameters:

| Name         | Type            | Description                 | Default |
| ------------ | --------------- | --------------------------- | ------- |
| `session_id` | `Optional[str]` | Session to query; required. | `None`  |

Returns:

| Type             | Description                                                |
| ---------------- | ---------------------------------------------------------- |
| `dict[str, Any]` | A mapping with the window dimensions (e.g. width, height). |

Raises:

| Type       | Description                                                      |
| ---------- | ---------------------------------------------------------------- |
| `WdaError` | No session id is available, or WDA did not return a window size. |

Source code in `pymobiledevice3/services/wda.py`

```
async def get_window_size(self, session_id: Optional[str] = None) -> dict[str, Any]:
    """Return the current window size.

    :param session_id: Session to query; required.
    :returns: A mapping with the window dimensions (e.g. `width`, `height`).
    :raises WdaError: No session id is available, or WDA did not return a window size.
    """
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    data = await self._request_json("GET", f"/session/{session_id}/window/size", None)
    value = data.get("value")
    if not isinstance(value, dict):
        raise WdaError("WDA did not return the window size.")
    return cast(dict[str, Any], value)
```

### send_keys

```
send_keys(text: str, session_id: Optional[str] = None) -> None
```

Type text into the currently focused element.

Sends the text as individual characters, trying the `wda/keys` endpoint first and falling back to the plain `keys` endpoint if the former is unavailable.

Parameters:

| Name         | Type            | Description               | Default    |
| ------------ | --------------- | ------------------------- | ---------- |
| `text`       | `str`           | The text to type.         | *required* |
| `session_id` | `Optional[str]` | Session to use; required. | `None`     |

Raises:

| Type       | Description                 |
| ---------- | --------------------------- |
| `WdaError` | No session id is available. |

Source code in `pymobiledevice3/services/wda.py`

```
async def send_keys(self, text: str, session_id: Optional[str] = None) -> None:
    """Type text into the currently focused element.

    Sends the text as individual characters, trying the `wda/keys` endpoint first and falling
    back to the plain `keys` endpoint if the former is unavailable.

    :param text: The text to type.
    :param session_id: Session to use; required.
    :raises WdaError: No session id is available.
    """
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    payload = {"value": list(text)}
    try:
        await self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
    except WdaError as exc:
        if exc.status_code != 404:
            raise
        await self._request_json("POST", f"/session/{session_id}/keys", payload)
```

### swipe

```
swipe(start_x: int, start_y: int, end_x: int, end_y: int, duration: float = 0.2, session_id: Optional[str] = None) -> None
```

Drag from a start coordinate to an end coordinate over a duration.

Parameters:

| Name         | Type            | Description                  | Default    |
| ------------ | --------------- | ---------------------------- | ---------- |
| `start_x`    | `int`           | Starting x coordinate.       | *required* |
| `start_y`    | `int`           | Starting y coordinate.       | *required* |
| `end_x`      | `int`           | Ending x coordinate.         | *required* |
| `end_y`      | `int`           | Ending y coordinate.         | *required* |
| `duration`   | `float`         | Gesture duration in seconds. | `0.2`      |
| `session_id` | `Optional[str]` | Session to use; required.    | `None`     |

Raises:

| Type       | Description                 |
| ---------- | --------------------------- |
| `WdaError` | No session id is available. |

Source code in `pymobiledevice3/services/wda.py`

```
async def swipe(
    self,
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    duration: float = 0.2,
    session_id: Optional[str] = None,
) -> None:
    """Drag from a start coordinate to an end coordinate over a duration.

    :param start_x: Starting x coordinate.
    :param start_y: Starting y coordinate.
    :param end_x: Ending x coordinate.
    :param end_y: Ending y coordinate.
    :param duration: Gesture duration in seconds.
    :param session_id: Session to use; required.
    :raises WdaError: No session id is available.
    """
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    payload: dict[str, Any] = {
        "fromX": start_x,
        "fromY": start_y,
        "toX": end_x,
        "toY": end_y,
        "duration": duration,
    }
    await self._request_json("POST", f"/session/{session_id}/wda/dragfromtoforduration", payload)
```

## pymobiledevice3.services.wda.WdaClient

Synchronous HTTP client for a running WebDriverAgent (WDA) server.

Talks to WDA over plain HTTP (default `http://127.0.0.1:8100`), expecting WDA to already be reachable at `base_url` (e.g. via a local port forward). Provides session management and the common WebDriver actions: element lookup, click, text input, button presses, swipes, screenshots and source dumps. Once `start_session` is called the returned session id is cached on `session_id` and used as the default for subsequent calls.

Source code in `pymobiledevice3/services/wda.py`

```
@dataclass
class WdaClient:
    """Synchronous HTTP client for a running WebDriverAgent (WDA) server.

    Talks to WDA over plain HTTP (default `http://127.0.0.1:8100`), expecting WDA to already be
    reachable at `base_url` (e.g. via a local port forward). Provides session management and the
    common WebDriver actions: element lookup, click, text input, button presses, swipes,
    screenshots and source dumps. Once `start_session` is called the returned session id is cached
    on `session_id` and used as the default for subsequent calls.
    """

    base_url: str = DEFAULT_WDA_URL
    timeout: float = 10.0
    session_id: Optional[str] = None

    def _url(self, path: str) -> str:
        """Build a full URL for a WDA path."""
        return f"{self.base_url.rstrip('/')}{path}"

    def _request_json(self, method: str, path: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Send an HTTP request and parse the WDA JSON response."""
        resp = requests.request(method, self._url(path), json=payload, timeout=self.timeout)
        data = resp.json()
        status = data.get("status")
        if status not in (None, 0, "0"):
            raise WdaError(self._format_error(data, resp.status_code), status_code=resp.status_code)

        return data

    @staticmethod
    def _format_error(data: dict[str, Any], status_code: int) -> str:
        """Format WDA error payloads."""
        message = data.get("value")
        if isinstance(message, dict):
            message = cast(dict[str, Any], message)
            message = message.get("message") or message.get("error") or message
        return f"WDA rejected the request (HTTP status {status_code}): {message}"

    def start_session(self, bundle_id: Optional[str] = None) -> str:
        """Start a WDA session, optionally launching a specific application.

        :param bundle_id: Bundle identifier of the app to attach the session to; if omitted no
            specific app capability is requested.
        :returns: The created session id, also cached on `session_id`.
        :raises WdaError: WDA did not return a session id.
        """
        caps: dict[str, Any] = {}
        if bundle_id:
            caps["bundleId"] = bundle_id
        payload: dict[str, Any] = {
            "capabilities": {"alwaysMatch": caps},
            "desiredCapabilities": caps,
        }
        data = self._request_json("POST", "/session", payload)
        session_id = data.get("sessionId")
        if not session_id:
            value = data.get("value")
            if isinstance(value, dict):
                session_id = cast(dict[str, Any], value).get("sessionId")
        if not session_id:
            raise WdaError("WDA did not return a session id when starting the session.")
        self.session_id = session_id
        return session_id

    def find_element(self, using: str, value: str, session_id: Optional[str] = None) -> str:
        """Locate a single UI element and return its element id.

        :param using: The locator strategy (e.g. `accessibility id`, `class name`, `xpath`).
        :param value: The locator value matched against `using`.
        :param session_id: Session to use; defaults to the cached `session_id`.
        :returns: The resolved element id.
        :raises WdaError: No session id is available, or WDA did not return an element id.
        """
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        data = self._request_json(
            "POST",
            f"/session/{session_id}/element",
            {"using": using, "value": value},
        )
        element = data.get("value")
        if not isinstance(element, dict):
            raise WdaError(f"WDA returned no element for {using} {value!r}")
        element = cast(dict[str, Any], element)
        element_id = (
            element.get("ELEMENT") or element.get("element-6066-11e4-a52e-4f735466cecf") or element.get("element")
        )
        if not element_id:
            raise WdaError(f"WDA returned an element without an id for {using} {value!r}")
        return element_id

    def click(self, element_id: str, session_id: Optional[str] = None) -> None:
        """Tap an element by its element id.

        :param element_id: The element id to click.
        :param session_id: Session to use; defaults to the cached `session_id`.
        :raises WdaError: No session id is available.
        """
        session_id = session_id or self.session_id
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        self._request_json("POST", f"/session/{session_id}/element/{element_id}/click", {})

    def press_button(self, name: str, session_id: Optional[str] = None) -> None:
        """Press a hardware/device button by name.

        The name is normalized to a WDA button name. When a session is given the session-scoped
        `pressButton` endpoint is tried first, falling back to the session keys endpoint; as a last
        resort, `home` is delivered via the global home-screen endpoint.

        :param name: Button name or alias (e.g. `home`, `volumeUp`, `lock`).
        :param session_id: Session to use; if omitted only the global `home` fallback applies.
        :raises WdaError: WDA supports neither the pressButton nor keys endpoints for this button.
        """
        normalized = normalize_wda_button_name(name)
        payload = {"name": normalized}
        if session_id:
            try:
                self._request_json("POST", f"/session/{session_id}/wda/pressButton", payload)
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return
            if self._try_keys_endpoint(session_id, normalized):
                return
        if normalized == "home":
            self._request_json("POST", "/wda/homescreen", {})
            return
        raise WdaError(
            "This WDA build cannot press buttons: it has neither the pressButton nor the keys endpoint.",
            status_code=404,
        )

    def unlock(self, session_id: Optional[str] = None) -> None:
        """Unlock the device, trying the session-scoped endpoint then the global one.

        :param session_id: Session to use; defaults to the cached `session_id`.
        :raises WdaError: WDA does not support the unlock endpoint.
        """
        session_id = session_id or self.session_id
        if session_id:
            try:
                self._request_json("POST", f"/session/{session_id}/wda/unlock", {})
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return
        try:
            self._request_json("POST", "/wda/unlock", {})
        except WdaError as exc:
            if exc.status_code != 404:
                raise
            raise WdaError(
                "This WDA build cannot unlock the device: it has no unlock endpoint.", status_code=404
            ) from exc

    def get_source(self, session_id: Optional[str] = None) -> str:
        """Fetch the current UI hierarchy as an XML source tree.

        :param session_id: Session to query; if omitted the global source endpoint is used.
        :returns: The XML source string.
        :raises WdaError: WDA did not return a source string.
        """
        if session_id:
            data = self._request_json("GET", f"/session/{session_id}/source", None)
        else:
            data = self._request_json("GET", "/source", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return the UI source tree.")
        return value

    def get_screenshot(self, session_id: Optional[str] = None) -> bytes:
        """Capture a screenshot and return the decoded PNG bytes.

        :param session_id: Session to query; if omitted the global screenshot endpoint is used.
        :returns: The raw PNG image bytes (base64-decoded from the WDA response).
        :raises WdaError: WDA did not return a screenshot.
        """
        if session_id:
            data = self._request_json("GET", f"/session/{session_id}/screenshot", None)
        else:
            data = self._request_json("GET", "/screenshot", None)
        value = data.get("value")
        if not isinstance(value, str):
            raise WdaError("WDA did not return a screenshot.")
        return base64.b64decode(value)

    def get_status(self) -> dict[str, Any]:
        """Return the WDA `/status` payload describing the server and device state.

        :returns: The parsed status response.
        """
        return self._request_json("GET", "/status", None)

    def get_window_size(self, session_id: Optional[str] = None) -> dict[str, Any]:
        """Return the current window size.

        :param session_id: Session to query; required.
        :returns: A mapping with the window dimensions (e.g. `width`, `height`).
        :raises WdaError: No session id is available, or WDA did not return a window size.
        """
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        data = self._request_json("GET", f"/session/{session_id}/window/size", None)
        value = data.get("value")
        if not isinstance(value, dict):
            raise WdaError("WDA did not return the window size.")
        return cast(dict[str, Any], value)

    def send_keys(self, text: str, session_id: Optional[str] = None) -> None:
        """Type text into the currently focused element.

        Sends the text as individual characters, trying the `wda/keys` endpoint first and falling
        back to the plain `keys` endpoint if the former is unavailable.

        :param text: The text to type.
        :param session_id: Session to use; required.
        :raises WdaError: No session id is available.
        """
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        payload = {"value": list(text)}
        try:
            self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
        except WdaError as exc:
            if exc.status_code != 404:
                raise
            self._request_json("POST", f"/session/{session_id}/keys", payload)

    def swipe(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        duration: float = 0.2,
        session_id: Optional[str] = None,
    ) -> None:
        """Drag from a start coordinate to an end coordinate over a duration.

        :param start_x: Starting x coordinate.
        :param start_y: Starting y coordinate.
        :param end_x: Ending x coordinate.
        :param end_y: Ending y coordinate.
        :param duration: Gesture duration in seconds.
        :param session_id: Session to use; required.
        :raises WdaError: No session id is available.
        """
        if not session_id:
            raise WdaError("No WDA session is active. Start a session first or pass a session id.")
        payload: dict[str, Any] = {
            "fromX": start_x,
            "fromY": start_y,
            "toX": end_x,
            "toY": end_y,
            "duration": duration,
        }
        self._request_json("POST", f"/session/{session_id}/wda/dragfromtoforduration", payload)

    def _try_keys_endpoint(self, session_id: Optional[str], normalized: str) -> bool:
        """Try the session keys endpoint for button presses."""
        key = normalize_wda_key_name(normalized)
        payload = {"keys": [key]}
        if session_id:
            try:
                self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
            except WdaError as exc:
                if exc.status_code != 404:
                    raise
            else:
                return True
        return False
```

### start_session

```
start_session(bundle_id: Optional[str] = None) -> str
```

Start a WDA session, optionally launching a specific application.

Parameters:

| Name        | Type            | Description                                                                                                | Default |
| ----------- | --------------- | ---------------------------------------------------------------------------------------------------------- | ------- |
| `bundle_id` | `Optional[str]` | Bundle identifier of the app to attach the session to; if omitted no specific app capability is requested. | `None`  |

Returns:

| Type  | Description                                        |
| ----- | -------------------------------------------------- |
| `str` | The created session id, also cached on session_id. |

Raises:

| Type       | Description                      |
| ---------- | -------------------------------- |
| `WdaError` | WDA did not return a session id. |

Source code in `pymobiledevice3/services/wda.py`

```
def start_session(self, bundle_id: Optional[str] = None) -> str:
    """Start a WDA session, optionally launching a specific application.

    :param bundle_id: Bundle identifier of the app to attach the session to; if omitted no
        specific app capability is requested.
    :returns: The created session id, also cached on `session_id`.
    :raises WdaError: WDA did not return a session id.
    """
    caps: dict[str, Any] = {}
    if bundle_id:
        caps["bundleId"] = bundle_id
    payload: dict[str, Any] = {
        "capabilities": {"alwaysMatch": caps},
        "desiredCapabilities": caps,
    }
    data = self._request_json("POST", "/session", payload)
    session_id = data.get("sessionId")
    if not session_id:
        value = data.get("value")
        if isinstance(value, dict):
            session_id = cast(dict[str, Any], value).get("sessionId")
    if not session_id:
        raise WdaError("WDA did not return a session id when starting the session.")
    self.session_id = session_id
    return session_id
```

### find_element

```
find_element(using: str, value: str, session_id: Optional[str] = None) -> str
```

Locate a single UI element and return its element id.

Parameters:

| Name         | Type            | Description                                                      | Default    |
| ------------ | --------------- | ---------------------------------------------------------------- | ---------- |
| `using`      | `str`           | The locator strategy (e.g. accessibility id, class name, xpath). | *required* |
| `value`      | `str`           | The locator value matched against using.                         | *required* |
| `session_id` | `Optional[str]` | Session to use; defaults to the cached session_id.               | `None`     |

Returns:

| Type  | Description              |
| ----- | ------------------------ |
| `str` | The resolved element id. |

Raises:

| Type       | Description                                                      |
| ---------- | ---------------------------------------------------------------- |
| `WdaError` | No session id is available, or WDA did not return an element id. |

Source code in `pymobiledevice3/services/wda.py`

```
def find_element(self, using: str, value: str, session_id: Optional[str] = None) -> str:
    """Locate a single UI element and return its element id.

    :param using: The locator strategy (e.g. `accessibility id`, `class name`, `xpath`).
    :param value: The locator value matched against `using`.
    :param session_id: Session to use; defaults to the cached `session_id`.
    :returns: The resolved element id.
    :raises WdaError: No session id is available, or WDA did not return an element id.
    """
    session_id = session_id or self.session_id
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    data = self._request_json(
        "POST",
        f"/session/{session_id}/element",
        {"using": using, "value": value},
    )
    element = data.get("value")
    if not isinstance(element, dict):
        raise WdaError(f"WDA returned no element for {using} {value!r}")
    element = cast(dict[str, Any], element)
    element_id = (
        element.get("ELEMENT") or element.get("element-6066-11e4-a52e-4f735466cecf") or element.get("element")
    )
    if not element_id:
        raise WdaError(f"WDA returned an element without an id for {using} {value!r}")
    return element_id
```

### click

```
click(element_id: str, session_id: Optional[str] = None) -> None
```

Tap an element by its element id.

Parameters:

| Name         | Type            | Description                                        | Default    |
| ------------ | --------------- | -------------------------------------------------- | ---------- |
| `element_id` | `str`           | The element id to click.                           | *required* |
| `session_id` | `Optional[str]` | Session to use; defaults to the cached session_id. | `None`     |

Raises:

| Type       | Description                 |
| ---------- | --------------------------- |
| `WdaError` | No session id is available. |

Source code in `pymobiledevice3/services/wda.py`

```
def click(self, element_id: str, session_id: Optional[str] = None) -> None:
    """Tap an element by its element id.

    :param element_id: The element id to click.
    :param session_id: Session to use; defaults to the cached `session_id`.
    :raises WdaError: No session id is available.
    """
    session_id = session_id or self.session_id
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    self._request_json("POST", f"/session/{session_id}/element/{element_id}/click", {})
```

### press_button

```
press_button(name: str, session_id: Optional[str] = None) -> None
```

Press a hardware/device button by name.

The name is normalized to a WDA button name. When a session is given the session-scoped `pressButton` endpoint is tried first, falling back to the session keys endpoint; as a last resort, `home` is delivered via the global home-screen endpoint.

Parameters:

| Name         | Type            | Description                                                       | Default    |
| ------------ | --------------- | ----------------------------------------------------------------- | ---------- |
| `name`       | `str`           | Button name or alias (e.g. home, volumeUp, lock).                 | *required* |
| `session_id` | `Optional[str]` | Session to use; if omitted only the global home fallback applies. | `None`     |

Raises:

| Type       | Description                                                              |
| ---------- | ------------------------------------------------------------------------ |
| `WdaError` | WDA supports neither the pressButton nor keys endpoints for this button. |

Source code in `pymobiledevice3/services/wda.py`

```
def press_button(self, name: str, session_id: Optional[str] = None) -> None:
    """Press a hardware/device button by name.

    The name is normalized to a WDA button name. When a session is given the session-scoped
    `pressButton` endpoint is tried first, falling back to the session keys endpoint; as a last
    resort, `home` is delivered via the global home-screen endpoint.

    :param name: Button name or alias (e.g. `home`, `volumeUp`, `lock`).
    :param session_id: Session to use; if omitted only the global `home` fallback applies.
    :raises WdaError: WDA supports neither the pressButton nor keys endpoints for this button.
    """
    normalized = normalize_wda_button_name(name)
    payload = {"name": normalized}
    if session_id:
        try:
            self._request_json("POST", f"/session/{session_id}/wda/pressButton", payload)
        except WdaError as exc:
            if exc.status_code != 404:
                raise
        else:
            return
        if self._try_keys_endpoint(session_id, normalized):
            return
    if normalized == "home":
        self._request_json("POST", "/wda/homescreen", {})
        return
    raise WdaError(
        "This WDA build cannot press buttons: it has neither the pressButton nor the keys endpoint.",
        status_code=404,
    )
```

### unlock

```
unlock(session_id: Optional[str] = None) -> None
```

Unlock the device, trying the session-scoped endpoint then the global one.

Parameters:

| Name         | Type            | Description                                        | Default |
| ------------ | --------------- | -------------------------------------------------- | ------- |
| `session_id` | `Optional[str]` | Session to use; defaults to the cached session_id. | `None`  |

Raises:

| Type       | Description                               |
| ---------- | ----------------------------------------- |
| `WdaError` | WDA does not support the unlock endpoint. |

Source code in `pymobiledevice3/services/wda.py`

```
def unlock(self, session_id: Optional[str] = None) -> None:
    """Unlock the device, trying the session-scoped endpoint then the global one.

    :param session_id: Session to use; defaults to the cached `session_id`.
    :raises WdaError: WDA does not support the unlock endpoint.
    """
    session_id = session_id or self.session_id
    if session_id:
        try:
            self._request_json("POST", f"/session/{session_id}/wda/unlock", {})
        except WdaError as exc:
            if exc.status_code != 404:
                raise
        else:
            return
    try:
        self._request_json("POST", "/wda/unlock", {})
    except WdaError as exc:
        if exc.status_code != 404:
            raise
        raise WdaError(
            "This WDA build cannot unlock the device: it has no unlock endpoint.", status_code=404
        ) from exc
```

### get_source

```
get_source(session_id: Optional[str] = None) -> str
```

Fetch the current UI hierarchy as an XML source tree.

Parameters:

| Name         | Type            | Description                                                      | Default |
| ------------ | --------------- | ---------------------------------------------------------------- | ------- |
| `session_id` | `Optional[str]` | Session to query; if omitted the global source endpoint is used. | `None`  |

Returns:

| Type  | Description            |
| ----- | ---------------------- |
| `str` | The XML source string. |

Raises:

| Type       | Description                         |
| ---------- | ----------------------------------- |
| `WdaError` | WDA did not return a source string. |

Source code in `pymobiledevice3/services/wda.py`

```
def get_source(self, session_id: Optional[str] = None) -> str:
    """Fetch the current UI hierarchy as an XML source tree.

    :param session_id: Session to query; if omitted the global source endpoint is used.
    :returns: The XML source string.
    :raises WdaError: WDA did not return a source string.
    """
    if session_id:
        data = self._request_json("GET", f"/session/{session_id}/source", None)
    else:
        data = self._request_json("GET", "/source", None)
    value = data.get("value")
    if not isinstance(value, str):
        raise WdaError("WDA did not return the UI source tree.")
    return value
```

### get_screenshot

```
get_screenshot(session_id: Optional[str] = None) -> bytes
```

Capture a screenshot and return the decoded PNG bytes.

Parameters:

| Name         | Type            | Description                                                          | Default |
| ------------ | --------------- | -------------------------------------------------------------------- | ------- |
| `session_id` | `Optional[str]` | Session to query; if omitted the global screenshot endpoint is used. | `None`  |

Returns:

| Type    | Description                                                     |
| ------- | --------------------------------------------------------------- |
| `bytes` | The raw PNG image bytes (base64-decoded from the WDA response). |

Raises:

| Type       | Description                      |
| ---------- | -------------------------------- |
| `WdaError` | WDA did not return a screenshot. |

Source code in `pymobiledevice3/services/wda.py`

```
def get_screenshot(self, session_id: Optional[str] = None) -> bytes:
    """Capture a screenshot and return the decoded PNG bytes.

    :param session_id: Session to query; if omitted the global screenshot endpoint is used.
    :returns: The raw PNG image bytes (base64-decoded from the WDA response).
    :raises WdaError: WDA did not return a screenshot.
    """
    if session_id:
        data = self._request_json("GET", f"/session/{session_id}/screenshot", None)
    else:
        data = self._request_json("GET", "/screenshot", None)
    value = data.get("value")
    if not isinstance(value, str):
        raise WdaError("WDA did not return a screenshot.")
    return base64.b64decode(value)
```

### get_status

```
get_status() -> dict[str, Any]
```

Return the WDA `/status` payload describing the server and device state.

Returns:

| Type             | Description                 |
| ---------------- | --------------------------- |
| `dict[str, Any]` | The parsed status response. |

Source code in `pymobiledevice3/services/wda.py`

```
def get_status(self) -> dict[str, Any]:
    """Return the WDA `/status` payload describing the server and device state.

    :returns: The parsed status response.
    """
    return self._request_json("GET", "/status", None)
```

### get_window_size

```
get_window_size(session_id: Optional[str] = None) -> dict[str, Any]
```

Return the current window size.

Parameters:

| Name         | Type            | Description                 | Default |
| ------------ | --------------- | --------------------------- | ------- |
| `session_id` | `Optional[str]` | Session to query; required. | `None`  |

Returns:

| Type             | Description                                                |
| ---------------- | ---------------------------------------------------------- |
| `dict[str, Any]` | A mapping with the window dimensions (e.g. width, height). |

Raises:

| Type       | Description                                                      |
| ---------- | ---------------------------------------------------------------- |
| `WdaError` | No session id is available, or WDA did not return a window size. |

Source code in `pymobiledevice3/services/wda.py`

```
def get_window_size(self, session_id: Optional[str] = None) -> dict[str, Any]:
    """Return the current window size.

    :param session_id: Session to query; required.
    :returns: A mapping with the window dimensions (e.g. `width`, `height`).
    :raises WdaError: No session id is available, or WDA did not return a window size.
    """
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    data = self._request_json("GET", f"/session/{session_id}/window/size", None)
    value = data.get("value")
    if not isinstance(value, dict):
        raise WdaError("WDA did not return the window size.")
    return cast(dict[str, Any], value)
```

### send_keys

```
send_keys(text: str, session_id: Optional[str] = None) -> None
```

Type text into the currently focused element.

Sends the text as individual characters, trying the `wda/keys` endpoint first and falling back to the plain `keys` endpoint if the former is unavailable.

Parameters:

| Name         | Type            | Description               | Default    |
| ------------ | --------------- | ------------------------- | ---------- |
| `text`       | `str`           | The text to type.         | *required* |
| `session_id` | `Optional[str]` | Session to use; required. | `None`     |

Raises:

| Type       | Description                 |
| ---------- | --------------------------- |
| `WdaError` | No session id is available. |

Source code in `pymobiledevice3/services/wda.py`

```
def send_keys(self, text: str, session_id: Optional[str] = None) -> None:
    """Type text into the currently focused element.

    Sends the text as individual characters, trying the `wda/keys` endpoint first and falling
    back to the plain `keys` endpoint if the former is unavailable.

    :param text: The text to type.
    :param session_id: Session to use; required.
    :raises WdaError: No session id is available.
    """
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    payload = {"value": list(text)}
    try:
        self._request_json("POST", f"/session/{session_id}/wda/keys", payload)
    except WdaError as exc:
        if exc.status_code != 404:
            raise
        self._request_json("POST", f"/session/{session_id}/keys", payload)
```

### swipe

```
swipe(start_x: int, start_y: int, end_x: int, end_y: int, duration: float = 0.2, session_id: Optional[str] = None) -> None
```

Drag from a start coordinate to an end coordinate over a duration.

Parameters:

| Name         | Type            | Description                  | Default    |
| ------------ | --------------- | ---------------------------- | ---------- |
| `start_x`    | `int`           | Starting x coordinate.       | *required* |
| `start_y`    | `int`           | Starting y coordinate.       | *required* |
| `end_x`      | `int`           | Ending x coordinate.         | *required* |
| `end_y`      | `int`           | Ending y coordinate.         | *required* |
| `duration`   | `float`         | Gesture duration in seconds. | `0.2`      |
| `session_id` | `Optional[str]` | Session to use; required.    | `None`     |

Raises:

| Type       | Description                 |
| ---------- | --------------------------- |
| `WdaError` | No session id is available. |

Source code in `pymobiledevice3/services/wda.py`

```
def swipe(
    self,
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    duration: float = 0.2,
    session_id: Optional[str] = None,
) -> None:
    """Drag from a start coordinate to an end coordinate over a duration.

    :param start_x: Starting x coordinate.
    :param start_y: Starting y coordinate.
    :param end_x: Ending x coordinate.
    :param end_y: Ending y coordinate.
    :param duration: Gesture duration in seconds.
    :param session_id: Session to use; required.
    :raises WdaError: No session id is available.
    """
    if not session_id:
        raise WdaError("No WDA session is active. Start a session first or pass a session id.")
    payload: dict[str, Any] = {
        "fromX": start_x,
        "fromY": start_y,
        "toX": end_x,
        "toY": end_y,
        "duration": duration,
    }
    self._request_json("POST", f"/session/{session_id}/wda/dragfromtoforduration", payload)
```
