import io
from dataclasses import dataclass, field
from typing import Annotated, Optional

from bytestruct import BinaryStruct, ByteReader, Bytes, Const, u32, u32be

FTAB_MAGIC = b"ftab"


@dataclass
class FtabEntry(BinaryStruct, byte_order="<"):
    tag: Annotated[bytes, Bytes(4)]
    offset: u32  # absolute offset of the payload
    size: u32
    pad_0x0C: u32 = 0
    data: bytes = b""  # the payload, not part of the table entry


@dataclass
class FtabHeader(BinaryStruct, byte_order="<"):
    always_01: u32
    always_ff: u32  # 0xFFFFFFFF
    unk_0x08: u32be  # unk_0x08 .. unk_0x1C are all 0
    unk_0x0C: u32be
    unk_0x10: u32be
    unk_0x14: u32be
    unk_0x18: u32be
    unk_0x1C: u32be
    tag: Annotated[bytes, Bytes(4)]  # e.g. b"rkos"
    magic: Annotated[bytes, Bytes(4), Const(FTAB_MAGIC)]
    num_entries: u32
    pad_0x2C: u32be
    entries: list[FtabEntry] = field(default_factory=list[FtabEntry])  # the entry table follows the header


class Ftab:
    def __init__(self, component_data: bytes):
        reader = ByteReader(component_data)
        self.parsed = FtabHeader.read(reader)
        for _ in range(self.parsed.num_entries):
            entry = FtabEntry.read(reader)
            entry.data = ByteReader(component_data, entry.offset).read(entry.size) if entry.size else b""
            self.parsed.entries.append(entry)

    @property
    def tag(self) -> bytes:
        return self.parsed.tag

    def get_entry_data(self, tag: bytes) -> Optional[bytes]:
        for entry in self.parsed.entries:
            if entry.tag == tag:
                return entry.data
        return None

    def add_entry(self, tag: bytes, data: bytes):
        entries = self.parsed.entries
        entries.append(FtabEntry(tag=tag, offset=0, size=len(data), data=data))
        self.parsed.num_entries = len(entries)
        # The table grew by one entry, so lay the payloads out again right after it (as idevicerestore's
        # ftab_add_entry does): real images pack their first payload directly after the table.
        offset = FtabHeader.SIZE + FtabEntry.SIZE * len(entries)
        for entry in entries:
            entry.offset = offset
            offset += entry.size

    @property
    def data(self) -> bytes:
        header = self.parsed
        stream = io.BytesIO()
        stream.write(header.build())
        for entry in header.entries:
            stream.write(entry.build())
            # Entry payloads live at their absolute offsets; seeking past the end zero-fills the gap.
            table_position = stream.tell()
            stream.seek(entry.offset)
            stream.write(entry.data)
            stream.seek(table_position)
        return stream.getvalue()
