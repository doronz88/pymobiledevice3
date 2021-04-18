import logging
import io
import plistlib
from datetime import datetime
from functools import partial

import IPython
from pygments import highlight, lexers, formatters
from bpylist2 import archiver
from construct import Struct, Int32ul, Int16ul, Int64ul, Const, Prefixed, GreedyBytes, this, Adapter, Select, \
    GreedyRange, Switch

from pymobiledevice3.lockdown import LockdownClient

SHELL_USAGE = '''
# This shell allows you to send messages to the DVTSecureSocketProxy and receive answers easily.
# Generally speaking, each channel represents a group of actions.
# Calling actions is done using a selector and auxiliary (parameters).
# Receiving answers is done by getting a return value and seldom auxiliary (private / extra parameters).
# To see the available channels, type the following:
developer.channels

# In order to send messages, you need to create a channel:
channel = developer.make_channel('com.apple.instruments.server.services.deviceinfo')

# After creating the channel you can call allowed selectors:
channel.runningProcesses()

# If an answer is expected, you can receive it using the receive method:
processes = channel.receive()

# Sometimes the selector requires parameters, You can add them using MessageAux. For example lets kill a process:
channel = developer.make_channel('com.apple.instruments.server.services.processcontrol')
args = MessageAux().append_obj(80) # This will kill pid 80
channel.killPid_(args, expects_reply=False) # Killing a process doesn't require an answer.

# In some rare cases, you might want to receive the auxiliary and the selector return value.
# For that cases you can use the recv_message method.
return_value, auxiliary = developer.recv_message()
'''


class BplitAdapter(Adapter):
    def _decode(self, obj, context, path):
        return archiver.unarchive(obj)

    def _encode(self, obj, context, path):
        return archiver.archive(obj)


dtx_message_header_struct = Struct(
    'magic' / Const(0x1F3D5B79, Int32ul),
    'cb' / Int32ul,
    'fragmentId' / Int16ul,
    'fragmentCount' / Int16ul,
    'length' / Int32ul,
    'identifier' / Int32ul,
    'conversationIndex' / Int32ul,
    'channelCode' / Int32ul,
    'expectsReply' / Int32ul,
)

dtx_message_payload_header_struct = Struct(
    'flags' / Int32ul,
    'auxiliaryLength' / Int32ul,
    'totalLength' / Int64ul,
)

message_aux_t_struct = Struct(
    'magic' / Select(Const(0x1f0, Int64ul), Const(0x1df0, Int64ul)),
    'aux' / Prefixed(Int64ul, GreedyRange(Struct(
        '_empty_dictionary' / Select(Const(0xa, Int32ul), Int32ul),
        'type' / Int32ul,
        'value' / Switch(this.type, {2: BplitAdapter(Prefixed(Int32ul, GreedyBytes)), 3: Int32ul, 4: Int64ul},
                         default=GreedyBytes),
    )))
)


class MessageAux:
    def __init__(self):
        self.values = []

    def append_int(self, value: int):
        self.values.append({'type': 3, 'value': value})
        return self

    def append_long(self, value: int):
        self.values.append({'type': 4, 'value': value})
        return self

    def append_obj(self, value):
        self.values.append({'type': 2, 'value': value})
        return self

    def __bytes__(self):
        return message_aux_t_struct.build(dict(aux=self.values))


class Channel(int):
    @classmethod
    def create(cls, value: int, service):
        channel = cls(value)
        channel._service = service
        return channel

    def receive(self):
        return self._service.recv_message()[0]

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

    def __getattr__(self, item):
        return partial(self._service.send_message, self, self._sanitize_name(item))


class DvtSecureSocketProxyService(object):
    SERVICE_NAME = 'com.apple.instruments.remoteserver.DVTSecureSocketProxy'
    INSTRUMENTS_MESSAGE_TYPE = 2
    EXPECTS_REPLY_MASK = 0x1000
    DEVICEINFO_IDENTIFIER = 'com.apple.instruments.server.services.deviceinfo'
    APP_LISTING_IDENTIFIER = 'com.apple.instruments.server.services.device.applictionListing'
    PROCESS_CONTROL_IDENTIFIER = 'com.apple.instruments.server.services.processcontrol'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.c = self.lockdown.start_service(self.SERVICE_NAME)
        self.channels = {}
        self.cur_channel = 0
        self.cur_message = 0

    def shell(self):
        IPython.embed(
            header=highlight(SHELL_USAGE, lexers.PythonLexer(), formatters.TerminalTrueColorFormatter(style='native')),
            user_ns={
                'developer': self,
                'MessageAux': MessageAux,
            })

    def ls(self, path):
        channel = self.make_channel(self.DEVICEINFO_IDENTIFIER)
        args = MessageAux().append_obj(path)
        self.send_message(
            channel, 'directoryListingForPath:', args
        )
        ret, aux = self.recv_message()
        assert ret
        return ret

    def proclist(self):
        channel = self.make_channel(self.DEVICEINFO_IDENTIFIER)
        self.send_message(channel, 'runningProcesses')
        ret, aux = self.recv_message()
        assert isinstance(ret, list)
        for process in ret:
            if 'startDate' in process:
                process['startDate'] = datetime.fromtimestamp(process['startDate'])
        return ret

    def applist(self):
        channel = self.make_channel(self.APP_LISTING_IDENTIFIER)
        args = MessageAux().append_obj({}).append_obj('')
        self.send_message(channel, 'installedApplicationsMatching:registerUpdateToken:', args)
        ret, aux = self.recv_message()
        assert isinstance(ret, list)
        return ret

    def kill(self, pid):
        channel = self.make_channel(self.PROCESS_CONTROL_IDENTIFIER)
        self.send_message(channel, 'killPid:', MessageAux().append_obj(pid), False)

    def launch(self, bundle_id: str, arguments=None, kill_existing: bool = True, start_suspended: bool = False):
        """
        Launch a process.
        :param bundle_id: Bundle id of the process.
        :param list arguments: List of argument to pass to process.
        :param kill_existing: Whether to kill an existing instance of this process.
        :param start_suspended: Same as WaitForDebugger.
        """
        arguments = [] if arguments is None else arguments
        channel = self.make_channel(self.PROCESS_CONTROL_IDENTIFIER)
        args = MessageAux().append_obj('').append_obj(bundle_id).append_obj({}).append_obj(arguments).append_obj({
            'StartSuspendedKey': start_suspended,
            'KillExisting': kill_existing,
        })
        self.send_message(
            channel, 'launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:', args
        )
        ret, aux = self.recv_message()
        assert ret
        return ret

    def system_information(self):
        return self._request_information('systemInformation')

    def hardware_information(self):
        return self._request_information('hardwareInformation')

    def network_information(self):
        return self._request_information('networkInformation')

    def perform_handshake(self):
        args = MessageAux()
        args.append_obj({'com.apple.private.DTXBlockCompression': 2, 'com.apple.private.DTXConnection': 1})
        self.send_message(0, '_notifyOfPublishedCapabilities:', args, expects_reply=False)
        ret, aux = self.recv_message()
        if ret != '_notifyOfPublishedCapabilities:':
            raise ValueError('Invalid answer')
        if not len(aux[0]):
            raise ValueError('Invalid answer')
        self.channels = aux[0].value

    def make_channel(self, identifier):
        assert identifier in self.channels
        self.cur_channel += 1
        code = self.cur_channel
        args = MessageAux().append_int(code).append_obj(identifier)
        self.send_message(0, '_requestChannelWithCode:identifier:', args)
        ret, aux = self.recv_message()
        assert ret is None
        assert code > 0
        return Channel.create(code, self)

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
        self.c.send(msg)

    def recv_message(self):
        packet_stream = self._recv_packet_fragments()
        pheader = dtx_message_payload_header_struct.parse_stream(packet_stream)

        compression = (pheader.flags & 0xFF000) >> 12
        if compression:
            raise NotImplementedError('Compressed')

        if pheader.auxiliaryLength:
            aux = message_aux_t_struct.parse_stream(packet_stream).aux
        else:
            aux = None
        obj_size = pheader.totalLength - pheader.auxiliaryLength
        data = packet_stream.read(obj_size)
        try:
            ret = archiver.unarchive(data) if obj_size else None
        except archiver.MissingClassMapping as e:
            print(plistlib.loads(data))
            raise e
        return ret, aux

    def _request_information(self, selector_name):
        channel = self.make_channel(self.DEVICEINFO_IDENTIFIER)
        self.send_message(channel, selector_name)
        ret, aux = self.recv_message()
        assert ret
        return ret

    def _recv_packet_fragments(self):
        packet_data = b''
        while True:
            data = self.c.recv_exact(dtx_message_header_struct.sizeof())
            mheader = dtx_message_header_struct.parse(data)
            if not mheader.conversationIndex:
                if mheader.identifier > self.cur_message:
                    self.cur_message = mheader.identifier
            if mheader.fragmentCount > 1 and mheader.fragmentId == 0:
                # when reading multiple message fragments, the first fragment contains only a message header
                continue
            packet_data += self.c.recv_exact(mheader.length)
            if mheader.fragmentId == mheader.fragmentCount - 1:
                break
        return io.BytesIO(packet_data)

    def __enter__(self):
        self.perform_handshake()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
