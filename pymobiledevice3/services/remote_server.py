import asyncio
import copy
import io
import logging
import os
import plistlib
import socket
import uuid
from collections.abc import Awaitable
from contextlib import suppress
from functools import partial
from pprint import pprint
from typing import Any, Callable, ClassVar, Optional

from bpylist2 import archiver
from construct import (
    Adapter,
    Const,
    Container,
    Default,
    GreedyBytes,
    GreedyRange,
    Int16ul,
    Int32sl,
    Int32ul,
    Int64ul,
    Prefixed,
    Select,
    Struct,
    Switch,
    this,
)
from pygments import formatters, highlight, lexers

from pymobiledevice3.exceptions import (
    ChannelClosedError,
    ConnectionTerminatedError,
    DvtException,
    UnrecognizedSelectorError,
)
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.utils import start_ipython_shell

SHELL_USAGE = """
# This shell allows you to send messages to the DVTSecureSocketProxy and receive answers easily.
# Generally speaking, each channel represents a group of actions.
# Calling actions is done using a selector and auxiliary (parameters).
# Receiving answers is done by getting a return value and seldom auxiliary (private / extra parameters).
# To see the available channels, type the following:
developer.supported_identifiers

# In order to send messages, you need to create a channel:
channel = developer.make_channel('com.apple.instruments.server.services.deviceinfo')

# After creating the channel you can call allowed selectors:
channel.runningProcesses()

# If an answer is expected, you can receive it using the receive method:
processes = channel.receive_plist()

# You can also call methods from the broadcast channel
broadcast.someMethod()

# Sometimes the selector requires parameters, You can add them using MessageAux. For example lets kill a process:
channel = developer.make_channel('com.apple.instruments.server.services.processcontrol')
args = MessageAux().append_obj(80) # This will kill pid 80
channel.killPid_(args, expects_reply=False) # Killing a process doesn't require an answer.

# In some rare cases, you might want to receive the auxiliary and the selector return value.
# For that cases you can use the recv_plist method.
return_value, auxiliary = developer.recv_plist()
"""


class BplitAdapter(Adapter):
    def _decode(self, obj, context, path):
        return archiver.unarchive(obj)

    def _encode(self, obj, context, path):
        return archiver.archive(obj)


message_aux_t_struct = Struct(
    "magic" / Default(Int64ul, 0x1F0),
    "aux"
    / Prefixed(
        Int64ul,
        GreedyRange(
            Struct(
                "_empty_dictionary" / Select(Const(0xA, Int32ul), Int32ul),
                "type" / Int32ul,
                "value"
                / Switch(
                    this.type,
                    {2: BplitAdapter(Prefixed(Int32ul, GreedyBytes)), 3: Int32ul, 6: Int64ul},
                    default=GreedyBytes,
                ),
            )
        ),
    ),
)
dtx_message_header_struct = Struct(
    "magic" / Const(0x1F3D5B79, Int32ul),
    "cb" / Int32ul,
    "fragmentId" / Int16ul,
    "fragmentCount" / Int16ul,
    "length" / Int32ul,
    "identifier" / Int32ul,
    "conversationIndex" / Int32ul,
    "channelCode" / Int32sl,
    "expectsReply" / Int32ul,
)
dtx_message_payload_header_struct = Struct(
    "flags" / Int32ul,
    "auxiliaryLength" / Int32ul,
    "totalLength" / Int64ul,
)


class MessageAux:
    def __init__(self):
        self.values = []

    def append_int(self, value: int):
        self.values.append({"type": 3, "value": value})
        return self

    def append_long(self, value: int):
        self.values.append({"type": 6, "value": value})
        return self

    def append_obj(self, value):
        self.values.append({"type": 2, "value": value})
        return self

    def __bytes__(self):
        return message_aux_t_struct.build({"aux": self.values})


class DTTapMessage:
    @staticmethod
    def decode_archive(archive_obj):
        return archive_obj.decode("DTTapMessagePlist")


class NSNull:
    @staticmethod
    def decode_archive(archive_obj):
        return None


class NSError:
    @staticmethod
    def encode_archive(archive_obj):
        return archiver.archive(archive_obj)

    @staticmethod
    def decode_archive(archive_obj):
        user_info = archive_obj.decode("NSUserInfo")
        if user_info.get("NSLocalizedDescription", "").endswith(" - it does not respond to the selector"):
            raise UnrecognizedSelectorError(user_info)
        raise DvtException(archive_obj.decode("NSUserInfo"))


class NSUUID(uuid.UUID):
    @staticmethod
    def uuid4():
        """Generate a random UUID."""
        return NSUUID(bytes=os.urandom(16))

    def encode_archive(self, archive_obj: archiver.ArchivingObject):
        archive_obj.encode("NS.uuidbytes", self.bytes)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return NSUUID(bytes=archive_obj.decode("NS.uuidbytes"))


class NSURL:
    def __init__(self, base, relative):
        self.base = base
        self.relative = relative

    def encode_archive(self, archive_obj: archiver.ArchivingObject):
        archive_obj.encode("NS.base", self.base)
        archive_obj.encode("NS.relative", self.relative)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return NSURL(archive_obj.decode("NS.base"), archive_obj.decode("NS.relative"))


class NSValue:
    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return archive_obj.decode("NS.rectval")


class NSMutableData:
    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return archive_obj.decode("NS.data")


class NSMutableString:
    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return archive_obj.decode("NS.string")


class XCTCapabilities:
    def __init__(self, capabilities: dict):
        self.capabilities = capabilities

    def encode_archive(self, archive_obj: archiver.ArchivingObject):
        archive_obj.encode("capabilities-dictionary", self.capabilities)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return XCTCapabilities(archive_obj.decode("capabilities-dictionary"))

    def __str__(self):
        return f"XCTCapabilities({self.capabilities})"


class XCTestConfiguration:
    _default: ClassVar = {
        # 'testBundleURL': UID(3),
        # 'sessionIdentifier': UID(8), # UUID
        "aggregateStatisticsBeforeCrash": {"XCSuiteRecordsKey": {}},
        "automationFrameworkPath": "/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework",
        "baselineFileRelativePath": None,
        "baselineFileURL": None,
        "defaultTestExecutionTimeAllowance": None,
        "disablePerformanceMetrics": False,
        "emitOSLogs": False,
        "formatVersion": plistlib.UID(2),  # store in UID
        "gatherLocalizableStringsData": False,
        "initializeForUITesting": True,
        "maximumTestExecutionTimeAllowance": None,
        "productModuleName": "WebDriverAgentRunner",  # set to other value is also OK
        "randomExecutionOrderingSeed": None,
        "reportActivities": True,
        "reportResultsToIDE": True,
        "systemAttachmentLifetime": 2,
        "targetApplicationArguments": [],  # maybe useless
        "targetApplicationBundleID": None,
        "targetApplicationEnvironment": None,
        "targetApplicationPath": "/whatever-it-does-not-matter/but-should-not-be-empty",
        "testApplicationDependencies": {},
        "testApplicationUserOverrides": None,
        "testBundleRelativePath": None,
        "testExecutionOrdering": 0,
        "testTimeoutsEnabled": False,
        "testsDrivenByIDE": False,
        "testsMustRunOnMainThread": True,
        "testsToRun": None,
        "testsToSkip": None,
        "treatMissingBaselinesAsFailures": False,
        "userAttachmentLifetime": 0,
        "preferredScreenCaptureFormat": 2,
        "IDECapabilities": XCTCapabilities({
            "expected failure test capability": True,
            "test case run configurations": True,
            "test timeout capability": True,
            "test iterations": True,
            "request diagnostics for specific devices": True,
            "delayed attachment transfer": True,
            "skipped test capability": True,
            "daemon container sandbox extension": True,
            "ubiquitous test identifiers": True,
            "XCTIssue capability": True,
        }),
    }

    def __init__(self, kv: dict):
        assert "testBundleURL" in kv
        assert "sessionIdentifier" in kv
        self._config = copy.deepcopy(self._default)
        self._config.update(kv)

    def encode_archive(self, archive_obj: archiver.ArchivingObject):
        for k, v in self._config.items():
            archive_obj.encode(k, v)

    @staticmethod
    def decode_archive(archive_obj: archiver.ArchivedObject):
        return archive_obj.object


archiver.update_class_map({
    "DTSysmonTapMessage": DTTapMessage,
    "DTTapHeartbeatMessage": DTTapMessage,
    "DTTapStatusMessage": DTTapMessage,
    "DTKTraceTapMessage": DTTapMessage,
    "DTActivityTraceTapMessage": DTTapMessage,
    "DTTapMessage": DTTapMessage,
    "NSNull": NSNull,
    "NSError": NSError,
    "NSUUID": NSUUID,
    "NSURL": NSURL,
    "NSValue": NSValue,
    "NSMutableData": NSMutableData,
    "NSMutableString": NSMutableString,
    "XCTestConfiguration": XCTestConfiguration,
    "XCTCapabilities": XCTCapabilities,
})

archiver.Archive.inline_types = list({*archiver.Archive.inline_types, bytes})


class Channel(int):
    @classmethod
    def create(cls, value: int, service: "RemoteServer"):
        """Attach a `RemoteServer` instance to an integer channel code."""
        channel = cls(value)
        channel._service = service
        return channel

    async def receive_key_value(self):
        """Receive a `(selector, aux)` tuple from this channel."""
        return await self._service.recv_plist(self)

    async def receive_plist(self):
        """Receive and return only the decoded selector/payload object."""
        return (await self._service.recv_plist(self))[0]

    async def receive_message(self):
        """Receive raw decoded message payload bytes and aux values."""
        return (await self._service.recv_message(self))[0]

    async def send_message(self, selector: str, args: MessageAux = None, expects_reply: bool = True):
        """Send a selector call on this channel."""
        await self._service.send_message(self, selector, args, expects_reply=expects_reply)

    @staticmethod
    def _sanitize_name(name: str):
        """
        Sanitize python name to ObjectiveC name.
        """
        name = "_" + name[1:].replace("_", ":") if name.startswith("_") else name.replace("_", ":")
        return name

    def __getitem__(self, item) -> Callable[[MessageAux], Awaitable[Any]]:
        """Return a callable proxy for sending `item` as selector."""
        return partial(self._service.send_message, self, item)

    def __getattr__(self, item) -> Callable[[MessageAux], Awaitable[Any]]:
        """Resolve unknown attributes to Objective-C selector proxies."""
        return self[self._sanitize_name(item)]


class RemoteServer(LockdownService):
    """
    Wrapper to Apple's RemoteServer.
    This server exports several ObjC objects allowing calling their respective selectors.
    The `/Developer/Library/PrivateFrameworks/DVTInstrumentsFoundation.framework/DTServiceHub` service reads the
    configuration stored from `[[NSUserDefaults standardUserDefaults] boolForKey:@"DTXConnectionTracer"]`
    If the value is true, then `/tmp/DTServiceHub[PID].DTXConnection.RANDOM.log` is created and can be used to debug the
    transport protocol.

    For example:

    ```
    root@iPhone (/var/root)# tail -f /tmp/DTServiceHub[369].DTXConnection.qNjM2U.log
    170.887982 x4 resuming [c0]: <DTXConnection 0x100d20670 : x4>
    170.889120 x4   sent   [c0]: < DTXMessage 0x100d52b10 : i2.0 c0 dispatch:[_notifyOfPublishedCapabilities:<NSDictionary 0x100d0e1b0 | 92 key/value pairs>] >
    170.889547 x4 received [c0]: < DTXMessage 0x100d0a550 : i1.0 c0 dispatch:[_notifyOfPublishedCapabilities:<NSDictionary 0x100d16a40 | 2 key/value pairs>] >
    170.892101 x4 received [c0]: < DTXMessage 0x100d0a550 : i3.0e c0 dispatch:[_requestChannelWithCode:[1]identifier :"com.apple.instruments.server.services.deviceinfo"] >
    170.892238 x4   sent   [c0]: < DTXMessage 0x100d61830 : i3.1 c0 >
    170.892973 x4 received [c1f]: < DTXMessage 0x100d0a550 : i4.0e c1 dispatch:[runningProcesses] >
    171.204957 x4   sent   [c1f]: < DTXMessage 0x100c557a0 : i4.1 c1 object:(__NSArrayM*)<NSArray 0x100c199d0 | 245 objects> { <NSDictionary 0x100c167c0 | 5 key/value pairs>, <NSDictionary 0x100d17970 | 5 key/value pairs>, <NSDictionary 0x100d17f40 | 5 key/value pairs>, <NSDictionary 0x100d61750 | 5 key/value pairs>, <NSDictionary 0x100c16760 | 5 key/value pairs>, ...  } >
    171.213326 x4 received [c0]: < DTXMessage : kDTXInterruptionMessage >
    171.213424 x4  handler [c0]: < DTXMessage : i1 kDTXInterruptionMessage >
    171.213477 x4 received [c1f]: < DTXMessage : kDTXInterruptionMessage >
    ```

    For editing the configuration we can simply add the respected key into:
    `/var/mobile/Library/Preferences/.GlobalPreferences.plist` and kill `cfprefsd`

    The valid selectors for triggering can be found using the following Frida script the same way Troy Bowman used for
    iterating all classes which implement the protocol `DTXAllowedRPC`:

    ```shell
    frida -U DTServiceHub
    ```

    ```javascript
    for (var name in ObjC.protocols) {
        var protocol = ObjC.protocols[name]
        if ('DTXAllowedRPC' in protocol.protocols) {
            console.log('@protocol', name)
            console.log('  ' + Object.keys(protocol.methods).join('\n  '))
        }
    }
    ```

    Lifecycle overview:
    - `connect()` establishes the transport, optionally negotiates SSL, and starts `_reader_loop()`.
    - `_reader_loop()` continuously reads frames, reassembles fragments, and enqueues complete messages by channel.
    - API calls (`send_message`, `recv_message`, `recv_plist`) operate on those per-channel queues.
    - `make_channel()` creates and caches channels with single-flight dedup for concurrent callers.
    - `close()` sends `_channelCanceled:`, stops the reader, and closes the underlying lockdown service.
    """

    BROADCAST_CHANNEL = 0
    INSTRUMENTS_MESSAGE_TYPE = 2
    CHANNEL_CLOSED = (None, b"")

    def __init__(
        self,
        lockdown: LockdownServiceProvider,
        service_name,
        remove_ssl_context: bool = True,
        is_developer_service: bool = True,
    ):
        """Initialize connection state, channel registries, and synchronization primitives."""
        super().__init__(lockdown, service_name, is_developer_service=is_developer_service)
        self._remove_ssl_context = remove_ssl_context

        self.supported_identifiers = {}

        # channel_cache, _pending_channel_requests, last_channel_code, channel_messages
        # work together to ensure only one active creator for each channel identifier.
        # They are to be used only within the protection of _channel_lock.
        # In any given moment, for a given channel identifier:
        # - channel_cache contains its channel OR
        # - _pending_channel_requests contains a Future for its creation OR
        # - neither if it has not been requested yet.
        # channel_messages is populated on demand ( on first read or write ),
        # a value of (None, b"") is enqueued when the channel is closed.
        self._channel_lock = asyncio.Lock()
        self.channel_cache: dict[str, Channel] = {}
        self._pending_channel_requests: dict[str, asyncio.Future] = {}
        self.last_channel_code = 0
        self.channel_messages = {self.BROADCAST_CHANNEL: asyncio.Queue()}

        self._fragment_buffers: dict[tuple[int, int, int], bytes] = {}

        # cur_message holds the identifier of the sent messages.
        # It is independent of the identifier of the received messages.
        # Send operations ( self.service.sendall ) and message counting ( self.cur_message++ )
        # must be protected by _send_lock to avoid concurrent writing on the socket.
        self._send_lock = asyncio.Lock()
        self.cur_message = 0

        # reader_task holds the background task responsible for reading from the socket,
        # defragmenting messages, and dispatching them to channel queues.
        # Ensure its existance using _ensure_reader() before any operation that expects incoming messages,
        # and check _reader_closed to detect a closed connection.
        self._reader_lock = asyncio.Lock()
        self._reader_task: Optional[asyncio.Task] = None
        self._reader_closed = False

        self.broadcast = Channel.create(0, self)

    async def _get_channel_queue(self, channel: int) -> asyncio.Queue:
        """Return (or lazily create) the inbound queue for a given channel code."""
        async with self._channel_lock:
            if channel not in self.channel_messages:
                self.channel_messages[channel] = asyncio.Queue()
            return self.channel_messages[channel]

    async def _ensure_reader(self) -> None:
        """Start the background reader task if it is not currently running."""
        async with self._reader_lock:
            if self._reader_closed:
                raise ConnectionTerminatedError()
            if self._reader_task is None:
                self.logger.debug("starting reader task")
                self._reader_task = asyncio.create_task(self._reader_loop(), name="remote-server-reader")
                return
            if not self._reader_task.done():
                return  # reader running
            try:
                e = self._reader_task.exception()
            except asyncio.CancelledError as e1:
                e = e1
            self.logger.exception("reader task exited unexpectedly", exc_info=e)
            raise ConnectionTerminatedError() from e

    async def _stop_reader(self) -> None:
        """Cancel and await the background reader task if present."""
        async with self._reader_lock:
            if self._reader_closed:
                return
            self._reader_closed = True
            t = self._reader_task
        if t is not None:
            self.logger.debug("stopping reader task")
            t.cancel()
            with suppress(asyncio.CancelledError):
                await t

    async def _reader_loop(self) -> None:
        """
        Continuously read raw DTX frames, defragment by message key, and fan out complete
        payloads into per-channel queues.

        Notes:
        - For fragmented messages, the first frame (fragmentId=0) carries only the DTX
          message header. Subsequent fragments carry payload bytes.
        - Fragment assembly is keyed by ``(identifier, conversationIndex, abs(channelCode))``
          to keep request/reply and per-channel streams isolated.
        - Once the final fragment arrives, a normalized single-fragment header and full
          payload are pushed to the channel queue.
        - On exit (error or cancellation), a ``(None, b"")`` sentinel is sent to every
          channel queue so awaiters can terminate promptly.
        """
        try:
            # FIXME: pthread_cond_wait like on the _reader_lock + _reader_closed c
            while True:
                data = await self.service.recvall(dtx_message_header_struct.sizeof())
                mheader = dtx_message_header_struct.parse(data)

                if mheader.fragmentCount > 1 and mheader.fragmentId == 0:
                    # when reading multiple message fragments, the first fragment contains only a message header
                    continue

                chunk = await self.service.recvall(mheader.length)

                # treat both as the negative and positive representation of the channel code in the response
                # the same when performing fragmentation
                received_channel_code = abs(mheader.channelCode)
                fragment_key = (mheader.identifier, mheader.conversationIndex, received_channel_code)
                payload = self._fragment_buffers.get(fragment_key, b"") + chunk
                if mheader.fragmentId == mheader.fragmentCount - 1:
                    self._fragment_buffers.pop(fragment_key, None)
                    assembled_header = mheader.copy()
                    assembled_header.fragmentId = 0
                    assembled_header.fragmentCount = 1
                    assembled_header.channelCode = received_channel_code
                    assembled_header.length = len(payload)
                    self._log_dtx_message("received", assembled_header, payload)
                    (await self._get_channel_queue(received_channel_code)).put_nowait((assembled_header, payload))
                else:
                    self._fragment_buffers[fragment_key] = payload
        except ConnectionResetError:
            self.logger.info("connection reset by peer, stopping reader loop")
            async with self._reader_lock:
                self._reader_closed = True
        finally:
            self.logger.debug("reader loop exiting, closing all channels")
            async with self._channel_lock:
                for q in self.channel_messages.values():
                    q.put_nowait(self.CHANNEL_CLOSED)

    async def connect(self) -> None:
        """Connect transport, complete protocol prerequisites, and ensure reader loop is active."""
        if self._service is None and self._remove_ssl_context:
            attr = await self.lockdown.get_service_connection_attributes(
                self.service_name, include_escrow_bag=self._include_escrow_bag
            )
            self._service = await self.lockdown.create_service_connection(attr["Port"])
            if attr.get("EnableServiceSSL", False) and hasattr(self.lockdown, "ssl_file"):
                # Mirror the legacy sync flow: negotiate SSL once, then strip SSL context for raw DTX traffic.
                # This is currently needed for RemoteServer services (DTX protocol) which only perform the
                # handshake in TLS. This happens for:
                # - AccessibilityAudit service
                # - iOS < 14.0
                with self.lockdown.ssl_file() as f:
                    self._service.setblocking(True)
                    self._service.ssl_start_sync(f)
        else:
            await super().connect()
        if self._remove_ssl_context:
            await self._recreate_connection_without_ssl_context()
        await self._ensure_reader()

    async def _recreate_connection_without_ssl_context(self) -> None:
        """Rebind to the underlying raw socket after TLS bootstrap to keep async stream mode."""
        if self._service is None or self._service.socket is None:
            return

        ssl_socket = self._service.socket
        if not hasattr(ssl_socket, "_sslobj"):
            return

        raw_socket = getattr(ssl_socket, "_sock", None)
        if raw_socket is None:
            # Python 3.14 may not expose ``_sock`` on SSLSocket. Detach the FD
            # and recreate a plain socket so asyncio can attach stream transports.
            fd = ssl_socket.detach()
            raw_socket = socket.socket(fileno=fd)
        else:
            ssl_socket._sslobj = None

        self._service.socket = raw_socket
        self._service.reader = None
        self._service.writer = None
        self._service.socket.setblocking(False)
        await self._service.start()

    def _log_dtx_message(self, direction: str, mheader: Container | bytes, payload: bytes) -> None:
        """Best-effort DEBUG log formatter for DTX packets."""
        if not self.logger.isEnabledFor(logging.DEBUG):
            return

        if isinstance(mheader, bytes):
            mheader = dtx_message_header_struct.parse(mheader)

        s = io.BytesIO(payload)
        pheader = dtx_message_payload_header_struct.parse_stream(s)
        compression = pheader.flags == 0x0707
        if compression:
            raise NotImplementedError("Compressed")

        aux = message_aux_t_struct.parse_stream(s).aux if pheader.auxiliaryLength else None
        obj_size = pheader.totalLength - pheader.auxiliaryLength
        data = s.read(obj_size) if obj_size else None

        with suppress(Exception):
            if pheader.auxiliaryLength:
                aux = [c.value for c in aux]
        with suppress(Exception):
            if obj_size:
                data = archiver.unarchive(data)

        e = "e" if mheader.expectsReply else ""
        self.logger.debug(
            "x%d %-8s [c?]: <DTXMessage: i%d.%d%s c%d t:%d payload:%s aux:%s>",
            self.service.socket.fileno(),
            direction,
            mheader.identifier,
            mheader.conversationIndex,
            e,
            mheader.channelCode,
            pheader.flags,
            data,
            aux,
        )

    def shell(self):
        """Launch an IPython shell preloaded with this server and its broadcast channel."""
        start_ipython_shell(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.Terminal256Formatter(style="native")),
            user_ns={
                "developer": self,
                "broadcast": self.broadcast,
                "MessageAux": MessageAux,
            },
        )

    async def perform_handshake(self):
        """Exchange published-capabilities messages and cache remote supported identifiers."""
        args = MessageAux()
        args.append_obj({"com.apple.private.DTXBlockCompression": 0, "com.apple.private.DTXConnection": 1})

        await self.send_message(0, "_notifyOfPublishedCapabilities:", args, expects_reply=False)
        ret, aux = await self.recv_plist()
        if ret != "_notifyOfPublishedCapabilities:":
            raise ValueError("Invalid answer")
        if not len(aux[0]):
            raise ValueError("Invalid answer")
        self.supported_identifiers = aux[0].value

    async def make_channel(self, identifier: str) -> Channel:
        """
        Get or create a DTX channel for a service identifier.

        Concurrency model:
        - Fast path: return cached channel if already created.
        - Dedup path: if another coroutine is already creating the same identifier,
          await its shared Future instead of issuing another request.
        - Create path: only one coroutine sends ``_requestChannelWithCode:identifier:``
          and later publishes the created channel into ``channel_cache`` while resolving
          the shared Future for waiters.

        The ``_state_lock`` protects all shared mutable state involved in the above:
        ``channel_cache``, ``_pending_channel_requests``, and ``last_channel_code``.
        """
        # NOTE: There is also identifier not in self.supported_identifiers
        # assert identifier in self.supported_identifiers
        async with self._channel_lock:
            existing = self.channel_cache.get(identifier)
            if existing is not None:
                return existing

            pending_request = self._pending_channel_requests.get(identifier)
            if pending_request is None:
                pending_request = asyncio.get_running_loop().create_future()
                self._pending_channel_requests[identifier] = pending_request
                self.last_channel_code += 1
                code = self.last_channel_code
                create_channel = True
            else:
                create_channel = False

        if not create_channel:
            # Another coroutine already owns channel creation for this identifier.
            return await pending_request

        try:
            args = MessageAux().append_int(code).append_obj(identifier)
            await self.send_message(0, "_requestChannelWithCode:identifier:", args)
            ret, _aux = await self.recv_plist()
            assert ret is None
            created_channel = Channel.create(code, self)
            async with self._channel_lock:
                self.channel_cache[identifier] = created_channel
                self._pending_channel_requests.pop(identifier, None)
                pending_request.set_result(created_channel)
        except BaseException as e:
            async with self._channel_lock:
                self.channel_cache.pop(identifier, None)
                self._pending_channel_requests.pop(identifier, None)
                pending_request.set_exception(e)
            raise
        return created_channel

    async def serve_channel(self, identifier: str, channel: Optional[Channel] = None) -> Channel:
        """Accept a reverse-channel request from peer and acknowledge it with an ACK reply."""
        msg, mheader = await self.recv_plist(self.BROADCAST_CHANNEL, return_header=True)
        assert msg[0] == "_requestChannelWithCode:identifier:", f"expected a request for a reverse channel, got: {msg}"
        code = msg[1][0].value
        assert channel is None or channel == code, (
            f"expected a request for a reverse channel with channelCode:{channel}, got:{msg[1][0]}"
        )
        received_identifier = msg[1][1].value
        assert identifier == received_identifier, (
            f"expected a request for a reverse channel with identifier:{identifier}, got:{received_identifier}"
        )
        if channel is None:
            channel = Channel.create(code, self)
        await self.send_reply_ack(self.BROADCAST_CHANNEL, mheader.identifier, None, None)
        return channel

    async def send_message(
        self, channel: int, selector: Optional[str] = None, args: MessageAux = None, expects_reply: bool = True
    ):
        """Serialize and send a DTX method invocation to a specific channel."""
        aux = bytes(args) if args is not None else b""
        sel = archiver.archive(selector) if selector is not None else b""
        flags = self.INSTRUMENTS_MESSAGE_TYPE
        pheader = dtx_message_payload_header_struct.build({
            "flags": flags,
            "auxiliaryLength": len(aux),
            "totalLength": len(aux) + len(sel),
        })

        async with self._send_lock:
            self.cur_message += 1
            mheader = dtx_message_header_struct.build({
                "cb": dtx_message_header_struct.sizeof(),
                "fragmentId": 0,
                "fragmentCount": 1,
                "length": dtx_message_payload_header_struct.sizeof() + len(aux) + len(sel),
                "identifier": self.cur_message,
                "conversationIndex": 0,
                "channelCode": channel,
                "expectsReply": int(expects_reply),
            })
            msg = mheader + pheader + aux + sel
            await self.service.sendall(msg)
            self._log_dtx_message("sent", mheader, pheader + aux + sel)

    async def recv_plist(self, channel: int = BROADCAST_CHANNEL, return_header: bool = False):
        """Receive a channel message and decode plist/archived object payloads."""
        recv_result = await self.recv_message(channel, return_header=return_header)
        if return_header:
            data, aux, mheader = recv_result
        else:
            data, aux = recv_result
        if data is not None:
            try:
                data = archiver.unarchive(data)
            except archiver.MissingClassMapping:
                pprint(plistlib.loads(data))
                raise
            except plistlib.InvalidFileException:
                self.logger.warning(f"got an invalid plist: {data[:40]}")
        if return_header:
            return (data, aux), mheader
        return data, aux

    async def recv_message(self, channel: int = BROADCAST_CHANNEL, return_header: bool = False):
        """Receive one complete DTX payload from a channel queue and parse its framing."""
        mheader, packet_stream = await self._recv_packet_fragments(channel)
        pheader = dtx_message_payload_header_struct.parse_stream(packet_stream)

        compression = (pheader.flags & 0xFF000) >> 12
        if compression:
            raise NotImplementedError("Compressed")

        aux = message_aux_t_struct.parse_stream(packet_stream).aux if pheader.auxiliaryLength else None
        obj_size = pheader.totalLength - pheader.auxiliaryLength
        data = packet_stream.read(obj_size) if obj_size else None
        if return_header:
            return data, aux, mheader
        return data, aux

    # TODO: rewrite the RemoteServer class (possibly even ServiceConnection) to continue consume messages
    # TODO: improve reply correlation by tracking expected replies with message IDs, rather than relying on channel-ordered consumers.

    async def _send_reply(
        self,
        channel: int,
        msg_id: int,
        msg_type: int,
        payload: Optional[object] = None,
        aux: Optional[MessageAux] = None,
    ):
        """Low-level DTX reply sender used by typed reply helpers."""
        payload_bytes = archiver.archive(payload) if payload is not None else b""
        aux_bytes = archiver.archive(aux) if aux is not None else b""
        pheader = dtx_message_payload_header_struct.build({
            "flags": msg_type,
            "auxiliaryLength": len(aux_bytes),
            "totalLength": len(payload_bytes) + len(aux_bytes),
        })
        mheader = dtx_message_header_struct.build({
            "cb": dtx_message_header_struct.sizeof(),
            "fragmentId": 0,
            "fragmentCount": 1,
            "length": dtx_message_payload_header_struct.sizeof() + len(payload_bytes) + len(aux_bytes),
            "identifier": msg_id,
            "conversationIndex": 1,
            "channelCode": channel,
            "expectsReply": (0),
        })
        msg = mheader + pheader + aux_bytes + payload_bytes
        async with self._send_lock:
            await self.service.sendall(msg)
            self._log_dtx_message("sent", mheader, pheader + aux_bytes + payload_bytes)

    async def send_reply(
        self, channel: int, msg_id: int, payload: Optional[object] = None, aux: Optional[MessageAux] = None
    ):
        """Send a success reply (`ResponseWithReturnValueInPayload`) for a request."""
        msg_type = 0x3  # ResponseWithReturnValueInPayload
        await self._send_reply(channel, msg_id, msg_type, payload, aux)

    async def send_reply_error(
        self, channel: int, msg_id: int, payload: Optional[object] = None, aux: Optional[MessageAux] = None
    ):
        """Send an error reply (`DtxTypeError`) for a request."""
        msg_type = 0x4  # DtxTypeError
        await self._send_reply(channel, msg_id, msg_type, payload, aux)

    async def send_reply_ack(
        self, channel: int, msg_id: int, payload: Optional[object] = None, aux: Optional[MessageAux] = None
    ):
        """Send an ACK-only reply for a request."""
        msg_type = 0x0  # Ack
        await self._send_reply(channel, msg_id, msg_type, payload, aux)

    async def _recv_packet_fragments(self, channel: int = BROADCAST_CHANNEL):
        """Await next fully-assembled packet for `channel` from the reader loop."""
        # here the order matters: get the channel and then check for the reader
        queue = await self._get_channel_queue(channel)
        await self._ensure_reader()

        mheader, message = await queue.get()

        if (mheader, message) == self.CHANNEL_CLOSED:
            await self._ensure_reader()  # this will raise ConnectionTerminatedError if the reader is closed
            raise ChannelClosedError()  # otherwise the other end genuinely requested a channel close
        return mheader, io.BytesIO(message)

    def __enter__(self):
        """Synchronous context manager is intentionally unsupported."""
        raise RuntimeError("Use async context manager: `async with ...`")

    async def close(self):
        """Gracefully shut down channels, stop reader loop, and close underlying service."""
        async with self._channel_lock:
            codes = [code for code in self.channel_messages if code > 0]
        if codes:
            aux = MessageAux()
            for code in codes:
                aux.append_int(code)

            try:
                await self.send_message(self.BROADCAST_CHANNEL, "_channelCanceled:", aux, expects_reply=False)
            except OSError:
                # ignore: OSError: [Errno 9] Bad file descriptor
                pass
            except RuntimeError as e:
                # Async generator teardown / interrupted CLI flows may close without a running loop.
                if "no running event loop" not in str(e):
                    raise

        await self._stop_reader()
        await super().close()

    async def __aenter__(self):
        """Connect, handshake, and return this instance for async context manager use."""
        await self.connect()
        await self.perform_handshake()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Ensure graceful shutdown on async context manager exit."""
        await self.close()


class ChannelService:
    """Lazy channel helper for DVT/RemoteServer-backed services."""

    IDENTIFIER: str

    def __init__(self, dvt: "RemoteServer", channel_name: Optional[str] = None) -> None:
        """Store server reference and optional channel identifier override."""
        self._dvt = dvt
        self._channel_name = channel_name if channel_name is not None else self.IDENTIFIER
        self._channel = None

    async def _channel_ref(self) -> Channel:
        """Lazily create and cache the backing channel."""
        if self._channel is None:
            self._channel = await self._dvt.make_channel(self._channel_name)
        return self._channel


class Tap(ChannelService):
    def __init__(self, dvt, channel_name: str, config: dict) -> None:
        """Initialize a tap helper with channel name and tap configuration."""
        super().__init__(dvt, channel_name=channel_name)
        self._config = config
        self.channel = None

    def __enter__(self):
        """Synchronous context manager is intentionally unsupported."""
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aenter__(self):
        """Open channel, configure tap, and start streaming."""
        self.channel = await self._channel_ref()
        await self.channel.setConfig_(MessageAux().append_obj(self._config), expects_reply=False)
        await self.channel.start(expects_reply=False)
        # first message is just kind of an ack
        await self.channel.receive_plist()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Stop tap streaming when leaving async context manager."""
        if self.channel is not None:
            await self.channel.stop(expects_reply=False)

    async def __aiter__(self):
        """Yield messages continuously from the active tap stream."""
        while True:
            for message in await self.channel.receive_plist():
                yield message
