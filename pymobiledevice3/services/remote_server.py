import io
import logging
import plistlib
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
        raise DvtException(archive_obj.decode('NSUserInfo')['NSLocalizedDescription'])


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


class RemoteServer(object):
    BROADCAST_CHANNEL = 0
    INSTRUMENTS_MESSAGE_TYPE = 2
    EXPECTS_REPLY_MASK = 0x1000

    def __init__(self, lockdown: LockdownClient, service_name, remove_ssl_context=True):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

        self.service = self.lockdown.start_developer_service(service_name)
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
                logging.warning(f'got an invalid plist: {data[:40]}')
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

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class Tap:
    def __init__(self, dvt, channel_name: str, config: dict):
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
