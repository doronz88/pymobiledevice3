import dataclasses
import math
import os
import struct
from io import BytesIO

from pymobiledevice3.services.remote_server import Tap

CMD_DEFINE_TABLE = 1
CMD_END_ROW = 2
CMD_CONVERT_MACH_CONTINUOUS = 5
CMD_TABLE_RESET = 0x64
CMD_COPY = 0x65
CMD_SENTINEL = 0x68
CMD_STRUCT = 0x69
CMD_PLACEHOLDER_COUNT = 0x6a
CMD_DEBUG = 0x6b


@dataclasses.dataclass
class Table:
    unknown0: str
    unknown2: str
    name: str
    columns: list


def decode_str(s: bytes):
    return s.split(b'\x00', 1)[0].decode()


def ignored_null(s: bytes) -> bytes:
    if len(s) == 0:
        return s

    if s[-1] == 0:
        s = s[:-1]
    return s


def decode_message_format(message) -> str:
    s = ''
    for type_, data in message:
        if data:
            data = ignored_null(data)
        type_ = decode_str(type_)

        if type_ == 'address':
            type_ = 'uint64-hex'

        if type_ in ('narrative-text', 'string'):
            if data is None:
                s += '<None>'
            else:
                s += data.decode()
        elif type_.startswith('uint64'):
            uint64 = struct.unpack('<Q', data.ljust(8, b'\x00'))[0]
            if 'hex' in type_:
                uint64 = hex(uint64)[2:]
                if 'lowercase' in type_:
                    uint64 = uint64.lower()
            s += str(uint64)
        elif 'decimal' in type_:
            uint64 = struct.unpack('<Q', data.ljust(8, b'\x00'))[0]
            s += str(uint64)
        elif type_ in ('data', 'uuid'):
            if data is not None:
                s += b''.join(data).hex()
        else:
            # by default, make sure the data can be concatenated
            s += str(data)
    return s


class ActivityTraceTap(Tap):
    IDENTIFIER = 'com.apple.instruments.server.services.activitytracetap'

    def __init__(self, dvt, enable_http_archive_logging=False):
        # TODO:
        #   reverse: [DTOSLogLoader _handleRecord:], DTTableRowEncoder::*
        #   to understand each row's structure.

        config = {
            'bm': 0,  # buffer mode
            'combineDataScope': 0,
            'machTimebaseDenom': 3,
            'machTimebaseNumer': 125,
            'onlySignposts': 0,
            'pidToInjectCombineDYLIB': '-1',
            'predicate': '(messageType == info OR messageType == debug OR messageType == default OR '
                         'messageType == error OR messageType == fault)',
            'signpostsAndLogs': 1,
            'trackPidToExecNameMapping': True,
            'enableHTTPArchiveLogging': enable_http_archive_logging,
            'targetPID': -3,  # all Process
            'trackExpiredPIDs': 1,
            'ur': 500,
        }

        super().__init__(dvt, self.IDENTIFIER, config)

        self.stack = []
        self.generation = 0
        self.background = 0
        self.tables = []

    def _get_next_message(self):
        message = b''
        while message.startswith(b'bplist') or len(message) == 0:
            # ignore heartbeat messages
            message = self.channel.receive_message()
        self._set_current_message(message)

    def _set_current_message(self, message):
        self._message = BytesIO(message)

    def _seek_relative(self, offset):
        self._message.seek(offset, os.SEEK_CUR)

    def _peek_word(self) -> int:
        buf = self._message.read(2)
        if len(buf) != 2:
            raise EOFError()
        word, = struct.unpack('<H', buf)
        self._message.seek(-2, os.SEEK_CUR)
        return word

    def _read_word(self):
        word = self._peek_word()
        self._message.seek(2, os.SEEK_CUR)
        return word

    def _handle_push(self, word):
        assert word >> 14 in (0b10, 0b11), f'invalid magic for pushed item. word: {hex(word)}'

        count = 0
        imm = 0
        bit_count = 0
        while word >> 14 != 0b11:
            # not end word
            imm = (imm << 14) | (word & 0x3fff)
            word = self._read_word()
            count += 1
            bit_count += 14

        imm = (imm << 14) | (word & 0x3fff)
        bit_count += 14

        imm <<= (8 - bit_count % 8)
        bit_count += 8 - bit_count % 8

        result = imm.to_bytes(math.ceil(bit_count / 8), 'big')
        self.stack.append(result)

        return result

    def _handle_table_reset(self, word):
        """ start new table vector """
        self.generation += 1
        self.background = 0
        self.stack = []

    def _handle_sentinel(self, word):
        """ push a dummy """
        self.stack.append(None)

    def _handle_struct(self, word):
        """ replace last `distance` items with a single one which represents them as a tuple """
        distance = word & 0xff

        if distance == 0xff:
            raise NotImplementedError('long struct')

        new_item = self.stack[-distance:]

        self.stack = self.stack[:-distance]
        self.stack.append(new_item)

    def _handle_define_table(self, word):
        """ define a table struct """
        distance = 4

        table_raw = Table(*self.stack[-distance:])
        table = Table(name=table_raw.name.split(b'\x00', 1)[0].decode(),
                      columns=[c.split(b'\x00', 1)[0].decode() for c in table_raw.columns],
                      unknown0=table_raw.unknown0, unknown2=table_raw.unknown2)

        self.stack = self.stack[:-distance]
        self.tables.append(table)

    def _handle_debug(self, word):
        """ pop last pushed item from stack """
        debug_id = word & 0xff
        item = self.stack[-1]

        reference = int.from_bytes(item, byteorder='little')

        assert reference == len(self.stack) - 1, \
            f'assert debug {debug_id} got reference: {hex(reference)} instead of: {len(self.stack) - 1}  {item}'
        self.stack = self.stack[:-1]

    def _handle_copy(self, word):
        """ copy item at distance from stack """
        distance = word & 0xff
        if distance != 0xff:
            item = self.stack[-distance - 1]
            self.stack.append(item)
        else:
            # long struct - pop distance from stack
            item = self.stack[-1]
            reference = int.from_bytes(item, byteorder='little') - 1
            self.stack = self.stack[:-1]
            self.stack.append(self.stack[reference])

    def _handle_end_row(self, word):
        """ flush current row """
        generation = word & 0xff
        columns = self.tables[generation].columns
        row = self.stack[-len(columns):]
        self.stack = self.stack[:-len(columns)]

        Message = dataclasses.make_dataclass('message', [c.replace('-', '_') for c in columns])
        message = Message(*row)
        message.process = 0 if message.process is None else struct.unpack('<I', message.process[0].ljust(4, b'\x00'))[0]
        message.thread = struct.unpack('<I', message.thread[0].ljust(4, b'\x00'))[0]

        string_fields = ('message_type', 'format_string', 'subsystem', 'category', 'sender_image_path',
                         'event_type', 'name')
        for f in string_fields:
            if hasattr(message, f):
                v = getattr(message, f)
                setattr(message, f, decode_str(v) if v else v)

        if hasattr(message, 'message'):
            return message

    def _handle_placeholder_count(self, word):
        """ remove `count` last items from stack """
        count = word & 0xff
        if count > 0:
            self.stack = self.stack[:-count]

    def _handle_convert_mach_continuous(self, word):
        """ push an item and pop it. effectively do nothing """
        pass

    def _parse(self):
        word = self._read_word()

        operations = {
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
            opcode = word >> 8

            if opcode in operations:
                result = operations[opcode](word)
            else:
                self._handle_push(word)

            if opcode == CMD_END_ROW and result is not None:
                yield result

            try:
                word = self._read_word()
            except EOFError:
                break

    def __iter__(self):
        while True:
            self._get_next_message()
            for message in self._parse():
                yield message
