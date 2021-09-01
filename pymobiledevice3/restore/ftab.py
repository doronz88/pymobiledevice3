from construct import Struct, Int32ub, Int32ul, Const, Array, this, Bytes, Pointer, Default

ftab_entry = Struct(
    'tag' / Bytes(4),
    'offset' / Int32ul,
    'size' / Int32ul,
    'pad_0x0C' / Default(Int32ul, 0),
    'data' / Pointer(this.offset, Bytes(this.size))
)

ftab_header = Struct(
    'always_01' / Int32ul,  # 1
    'always_ff' / Int32ul,  # 0xFFFFFFFF
    'unk_0x08' / Int32ub,  # 0
    'unk_0x0C' / Int32ub,  # 0
    'unk_0x10' / Int32ub,  # 0
    'unk_0x14' / Int32ub,  # 0
    'unk_0x18' / Int32ub,  # 0
    'unk_0x1C' / Int32ub,  # 0
    'tag' / Bytes(4),  # e.g. 'rkos'
    'magic' / Const(b'ftab'),  # 'ftab' magic
    'num_entries' / Int32ul,
    'pad_0x2C' / Int32ub,
    'entries' / Array(this.num_entries, ftab_entry)
)


class Ftab:
    def __init__(self, component_data: bytes):
        self.parsed = ftab_header.parse(component_data)

    @property
    def tag(self):
        return self.parsed.tag

    def get_entry_data(self, tag: bytes) -> bytes:
        for entry in self.parsed.entries:
            if entry.tag == tag:
                return entry.data
        return None

    def add_entry(self, tag: bytes, data: bytes):
        new_offset = self.parsed.entries[-1].offset + self.parsed.entries[-1].size
        new_entry = {'tag': tag, 'offset': new_offset, 'size': len(data), 'data': data}

        self.parsed.num_entries += 1
        self.parsed.entries.append(new_entry)

    @property
    def data(self) -> bytes:
        return ftab_header.build(self.parsed)
