import struct
import sys

from hexdump import hexdump

from pymobiledevice3.services.dvt.tap import Tap


class ActivityTraceTap(Tap):
    IDENTIFIER = 'com.apple.instruments.server.services.activitytracetap'

    def __init__(self, dvt):
        # TODO:
        #   reverse: [DTOSLogLoader _handleRecord:], DTTableRowEncoder::*
        #   to understand each row's structure.

        config = {
            'bm': 0,  # buffer mode
            'combineDataScope': 0,
            'machTimebaseDenom': 3,
            'machTimebaseNumer': 125,
            'onlySignposts': 0,
            'pidToInjectCombineDYLIB': "-1",
            'predicate': "(messageType == info OR messageType == debug OR messageType == default OR "
                         "messageType == error OR messageType == fault)",
            # 'signpostsAndLogs': 1,
            'signpostsAndLogs': 0,
            'targetPID': "-3",
            'trackExpiredPIDs': 1,
            'ur': 500,
        }

        super().__init__(dvt, self.IDENTIFIER, config)

    def __enter__(self):
        super().__enter__()
        self._parse_tables()
        return self

    def _parse_tables(self):
        self._get_next_message()
        assert self._read_word() >> 8 == 0x64, 'invalid table reset'

        self._read_table()
        self._read_table()
        self._read_table()
        self._read_table()

        for i in range(12):
            print('col value:', self._pop_string())

    def _get_next_message(self):
        message = b''
        while message.startswith(b'bplist') or len(message) == 0:
            # ignore heartbeat messages
            message = self._channel.receive_message()
        self._set_current_message(message)

    def _set_current_message(self, message):
        self._message = message
        self._offset = 0

    def _peek_word(self) -> int:
        word, = struct.unpack('<H', self._message[:2])
        return word

    def _read_word(self):
        if len(self._message) < 2:
            raise EOFError()

        word = self._peek_word()
        self._message = self._message[2:]
        self._offset += 2
        return word

    def _pop(self):
        word = self._read_word()

        if word >> 8 == 0x68:
            # sentinel
            return None

        assert word >> 14 in (0b10, 0b11), 'invalid magic for coloumn string'

        bin_str = ''
        while word >> 14 != 0b11:
            # not string end
            bin_str += bin(word)[4:].rjust(14, '0')
            word = self._read_word()
        bin_str += bin(word)[4:].rjust(14, '0')

        if len(bin_str) % 4 != 0:
            bin_str += '00'

        hex_str = hex(int(bin_str, 2))[2:]
        if len(hex_str) % 2 == 1:
            hex_str = hex_str + '0'
        return bytes.fromhex(hex_str)  # .split(b'\x00', 1)[0].decode('utf8')

    def _read_string_array(self):
        return [s.split(b'\x00', 1)[0].decode('utf8') for s in self._read_array()]

    def _read_array(self):
        result = []
        while self._peek_word() >> 8 != 0x69:
            result.append(self._pop())

        # skip array splitter
        self._read_word()
        self._read_word()
        return result

    def _read_table(self):
        # ignore first two columns
        self._pop()
        self._pop()

        print(f'table_name: {self._pop_string()}')
        print(f'columns: {self._read_string_array()}')

    def _pop_string(self):
        return self._pop().split(b'\x00', 1)[0].decode('utf8')

    def _pop_u16(self):
        return struct.unpack('<H', self._pop())[0]

    def _read_until_word(self, word):
        while self._read_word() != word:
            pass

    def _read_until_debug_id(self, debug_id):
        self._read_until_word((0x6b << 8) | debug_id)

    def _parse(self):
        print(hexdump(self._message[:200]))

        self._pop()
        self._read_until_debug_id(1)

        self._pop()

        sys.exit(0)

    def __iter__(self):
        if len(self._message):
            yield self._parse()

        while True:
            self._get_next_message()
            yield self._parse()
