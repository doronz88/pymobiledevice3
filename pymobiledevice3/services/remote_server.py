import io
import plistlib
import typing
from functools import partial
from pprint import pprint
from queue import Queue, Empty

import IPython
from bpylist2 import archiver
from construct import Struct, Default, Int64ul, Prefixed, GreedyRange, Select, Const, Int32ul, Switch, this, \
    GreedyBytes, Adapter, Int16ul, Int32sl
from pygments import highlight, lexers, formatters

from pymobiledevice3.exceptions import DvtException
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService

SHELL_USAGE = '''
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
'''


class BplitAdapter(Adapter):
    def _decode(self, obj, context, path):
        return archiver.unarchive(obj)

    def _encode(self, obj, context, path):
        return archiver.archive(obj)


message_aux_t_struct = Struct(
    'magic' / Default(Int64ul, 0x1f0),
    'aux' / Prefixed(Int64ul, GreedyRange(Struct(
        '_empty_dictionary' / Select(Const(0xa, Int32ul), Int32ul),
        'type' / Int32ul,
        'value' / Switch(this.type, {2: BplitAdapter(Prefixed(Int32ul, GreedyBytes)), 3: Int32ul, 6: Int64ul},
                         default=GreedyBytes),
    )))
)
dtx_message_header_struct = Struct(
    'magic' / Const(0x1F3D5B79, Int32ul),
    'cb' / Int32ul,
    'fragmentId' / Int16ul,
    'fragmentCount' / Int16ul,
    'length' / Int32ul,
    'identifier' / Int32ul,
    'conversationIndex' / Int32ul,
    'channelCode' / Int32sl,
    'expectsReply' / Int32ul,
)
dtx_message_payload_header_struct = Struct(
    'flags' / Int32ul,
    'auxiliaryLength' / Int32ul,
    'totalLength' / Int64ul,
)


class MessageAux:
    def __init__(self):
        self.values = []

    def append_int(self, value: int):
        self.values.append({'type': 3, 'value': value})
        return self

    def append_long(self, value: int):
        self.values.append({'type': 6, 'value': value})
        return self

    def append_obj(self, value):
        self.values.append({'type': 2, 'value': value})
        return self

    def __bytes__(self):
        return message_aux_t_struct.build(dict(aux=self.values))


class DTTapMessage:
    @staticmethod
    def decode_archive(archive_obj):
        return archive_obj.decode('DTTapMessagePlist')


class NSNull:
    @staticmethod
    def decode_archive(archive_obj):
        return None


class NSError:
    @staticmethod
    def decode_archive(archive_obj):
        raise DvtException(archive_obj.decode('NSUserInfo'))


archiver.update_class_map({'DTSysmonTapMessage': DTTapMessage,
                           'DTTapHeartbeatMessage': DTTapMessage,
                           'DTTapStatusMessage': DTTapMessage,
                           'DTKTraceTapMessage': DTTapMessage,
                           'DTActivityTraceTapMessage': DTTapMessage,
                           'NSNull': NSNull,
                           'NSError': NSError})


class Channel(int):
    @classmethod
    def create(cls, value: int, service):
        channel = cls(value)
        channel._service = service
        return channel

    def receive_plist(self):
        return self._service.recv_plist(self)[0]

    def receive_message(self):
        return self._service.recv_message(self)[0]

    @staticmethod
    def _sanitize_name(name: str):
        """
        Sanitize python name to ObjectiveC name.
        """
        if name.startswith('_'):
            name = '_' + name[1:].replace('_', ':')
        else:
            name = name.replace('_', ':')
        return name

    def __getitem__(self, item):
        return partial(self._service.send_message, self, item)

    def __getattr__(self, item):
        return self[self._sanitize_name(item)]


class ChannelFragmenter:
    def __init__(self):
        self._messages = Queue()
        self._packet_data = b''
        self._stream_packet_data = b''

    def get(self):
        return self._messages.get_nowait()

    def add_fragment(self, mheader, chunk):
        if mheader.channelCode >= 0:
            self._packet_data += chunk
            if mheader.fragmentId == mheader.fragmentCount - 1:
                # last message
                self._messages.put(self._packet_data)
                self._packet_data = b''
        else:
            self._stream_packet_data += chunk
            if mheader.fragmentId == mheader.fragmentCount - 1:
                # last message
                self._messages.put(self._stream_packet_data)
                self._stream_packet_data = b''


class RemoteServer(BaseService):
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
    """
    BROADCAST_CHANNEL = 0
    INSTRUMENTS_MESSAGE_TYPE = 2
    EXPECTS_REPLY_MASK = 0x1000

    def __init__(self, lockdown: LockdownClient, service_name, remove_ssl_context=True):
        super().__init__(lockdown, service_name, is_developer_service=True)

        if remove_ssl_context and hasattr(self.service.socket, '_sslobj'):
            self.service.socket._sslobj = None

        self.supported_identifiers = {}
        self.last_channel_code = 0
        self.cur_message = 0
        self.channel_cache = {}
        self.channel_messages = {self.BROADCAST_CHANNEL: ChannelFragmenter()}
        self.broadcast = Channel.create(0, self)

    def shell(self):
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
            user_ns={
                'developer': self,
                'broadcast': self.broadcast,
                'MessageAux': MessageAux,
            })

    def perform_handshake(self):
        args = MessageAux()
        args.append_obj({'com.apple.private.DTXBlockCompression': 0, 'com.apple.private.DTXConnection': 1})
        self.send_message(0, '_notifyOfPublishedCapabilities:', args, expects_reply=False)
        ret, aux = self.recv_plist()
        if ret != '_notifyOfPublishedCapabilities:':
            raise ValueError('Invalid answer')
        if not len(aux[0]):
            raise ValueError('Invalid answer')
        self.supported_identifiers = aux[0].value

    def make_channel(self, identifier) -> Channel:
        assert identifier in self.supported_identifiers
        if identifier in self.channel_cache:
            return self.channel_cache[identifier]

        self.last_channel_code += 1
        code = self.last_channel_code
        args = MessageAux().append_int(code).append_obj(identifier)
        self.send_message(0, '_requestChannelWithCode:identifier:', args)
        ret, aux = self.recv_plist()
        assert ret is None
        channel = Channel.create(code, self)
        self.channel_cache[identifier] = channel
        self.channel_messages[code] = ChannelFragmenter()
        return channel

    def send_message(self, channel: int, selector: str = None, args: MessageAux = None, expects_reply: bool = True):
        self.cur_message += 1

        aux = bytes(args) if args is not None else b''
        sel = archiver.archive(selector) if selector is not None else b''
        flags = self.INSTRUMENTS_MESSAGE_TYPE
        if expects_reply:
            flags |= self.EXPECTS_REPLY_MASK
        pheader = dtx_message_payload_header_struct.build(dict(flags=flags, auxiliaryLength=len(aux),
                                                               totalLength=len(aux) + len(sel)))
        mheader = dtx_message_header_struct.build(dict(
            cb=dtx_message_header_struct.sizeof(),
            fragmentId=0,
            fragmentCount=1,
            length=dtx_message_payload_header_struct.sizeof() + len(aux) + len(sel),
            identifier=self.cur_message,
            conversationIndex=0,
            channelCode=channel,
            expectsReply=int(expects_reply)
        ))
        msg = mheader + pheader + aux + sel
        self.service.sendall(msg)

    def recv_plist(self, channel: int = BROADCAST_CHANNEL):
        data, aux = self.recv_message(channel)
        if data is not None:
            try:
                data = archiver.unarchive(data)
            except archiver.MissingClassMapping as e:
                pprint(plistlib.loads(data))
                raise e
            except plistlib.InvalidFileException:
                self.logger.warning(f'got an invalid plist: {data[:40]}')
        return data, aux

    def recv_message(self, channel: int = BROADCAST_CHANNEL):
        packet_stream = self._recv_packet_fragments(channel)
        pheader = dtx_message_payload_header_struct.parse_stream(packet_stream)

        compression = (pheader.flags & 0xFF000) >> 12
        if compression:
            raise NotImplementedError('Compressed')

        if pheader.auxiliaryLength:
            aux = message_aux_t_struct.parse_stream(packet_stream).aux
        else:
            aux = None
        obj_size = pheader.totalLength - pheader.auxiliaryLength
        data = packet_stream.read(obj_size) if obj_size else None
        return data, aux

    def _recv_packet_fragments(self, channel: int = BROADCAST_CHANNEL):
        while True:
            try:
                # if we already have a message for this channel, just return it
                message = self.channel_messages[channel].get()
                return io.BytesIO(message)
            except Empty:
                # if no message exists for the given channel code, just keep waiting and receive new messages
                # until the waited message queue has at least one message
                data = self.service.recvall(dtx_message_header_struct.sizeof())
                mheader = dtx_message_header_struct.parse(data)

                # treat both as the negative and positive representation of the channel code in the response
                # the same when performing fragmentation
                received_channel_code = abs(mheader.channelCode)

                if received_channel_code not in self.channel_messages:
                    self.channel_messages[received_channel_code] = ChannelFragmenter()

                if not mheader.conversationIndex:
                    if mheader.identifier > self.cur_message:
                        self.cur_message = mheader.identifier

                if mheader.fragmentCount > 1 and mheader.fragmentId == 0:
                    # when reading multiple message fragments, the first fragment contains only a message header
                    continue

                self.channel_messages[received_channel_code].add_fragment(mheader, self.service.recvall(mheader.length))

    def __enter__(self):
        self.perform_handshake()
        return self


class Tap:
    def __init__(self, dvt, channel_name: str, config: typing.Mapping):
        self._dvt = dvt
        self._channel_name = channel_name
        self._channel = None
        self._config = config

    def __enter__(self):
        self._channel = self._dvt.make_channel(self._channel_name)
        self._channel.setConfig_(MessageAux().append_obj(self._config), expects_reply=False)
        self._channel.start(expects_reply=False)

        # first message is just kind of an ack
        self._channel.receive_plist()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._channel.stop(expects_reply=False)

    def __iter__(self):
        while True:
            for result in self._channel.receive_plist():
                yield result
