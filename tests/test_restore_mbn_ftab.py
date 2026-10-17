import struct

import pytest
from bytestruct import TruncatedDataError, UnexpectedConstantError

from pymobiledevice3.restore.ftab import Ftab, FtabEntry, FtabHeader
from pymobiledevice3.restore.mbn import (
    MBN_BIN_MAGIC,
    MBN_V1_MAGIC,
    MBN_V2_MAGIC,
    Elf32Ehdr,
    Elf32Phdr,
    Elf64Ehdr,
    Elf64Phdr,
    MbnBinHeader,
    MbnV1Header,
    MbnV2Header,
    MbnV7Header,
    mbn_is_64bit_elf,
    mbn_is_valid_elf,
    mbn_mav25_stitch,
    mbn_stitch,
)


def test_record_sizes() -> None:
    assert (FtabHeader.SIZE, FtabEntry.SIZE) == (0x30, 0x10)
    assert (MbnV1Header.SIZE, MbnV2Header.SIZE, MbnBinHeader.SIZE, MbnV7Header.SIZE) == (0x28, 0x50, 0x18, 0x28)
    assert (Elf32Ehdr.SIZE, Elf64Ehdr.SIZE, Elf32Phdr.SIZE, Elf64Phdr.SIZE) == (52, 64, 32, 56)


def _ftab(entries: list[tuple[bytes, bytes]]) -> bytes:
    header = struct.pack("<II", 1, 0xFFFFFFFF) + bytes(24) + b"rkos" + b"ftab" + struct.pack("<I", len(entries))
    header += bytes(4)
    offset = len(header) + 16 * len(entries)
    table = b""
    payload = b""
    for tag, data in entries:
        table += struct.pack("<4sIII", tag, offset, len(data), 0)
        payload += data
        offset += len(data)
    return header + table + payload


def test_ftab_roundtrip_and_add_entry() -> None:
    # Like real RTKitOS images: the first payload starts right after the entry table.
    raw = _ftab([(b"rkos", b"A" * 7), (b"aaaa", b"B" * 5)])
    ftab = Ftab(raw)
    assert ftab.tag == b"rkos"
    assert ftab.get_entry_data(b"aaaa") == b"B" * 5
    assert ftab.get_entry_data(b"rrko") is None
    assert ftab.data == raw

    ftab.add_entry(b"rrko", b"C" * 4)
    assert ftab.data == _ftab([(b"rkos", b"A" * 7), (b"aaaa", b"B" * 5), (b"rrko", b"C" * 4)])
    rebuilt = Ftab(ftab.data)
    assert [rebuilt.get_entry_data(tag) for tag in (b"rkos", b"aaaa", b"rrko")] == [b"A" * 7, b"B" * 5, b"C" * 4]


def test_ftab_zero_size_entry_may_point_past_the_end() -> None:
    raw = bytearray(_ftab([(b"rkos", b"A" * 7), (b"empt", b"")]))
    struct.pack_into("<I", raw, 0x30 + 16 + 4, 0x1000)  # the empty entry's offset
    assert Ftab(bytes(raw)).get_entry_data(b"empt") == b""


def test_ftab_errors() -> None:
    raw = _ftab([(b"rkos", b"A" * 7)])
    with pytest.raises(UnexpectedConstantError):
        Ftab(raw[:0x24] + b"xtab" + raw[0x28:])
    with pytest.raises(TruncatedDataError):
        Ftab(raw[:-1])


def _elf64(sect_off: int, sect: bytes) -> bytes:
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 0xA4, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, sect_off, 0, 0, len(sect), len(sect), 0x1000)
    head = ehdr + phdr
    return head + bytes(sect_off - len(head)) + sect


def test_mbn_stitch() -> None:
    data = MBN_V1_MAGIC + struct.pack("<9I", 0, 0, 0, 0x10, 0, 0, 0, 0, 0) + bytes(0x10)
    assert mbn_stitch(data, b"\xff" * 4) == data[:-4] + b"\xff" * 4
    assert mbn_stitch(data, bytes(len(data) + 1)) is None

    # v2: data_size at 0x1C excludes the 0x50-byte header
    data = MBN_V2_MAGIC + struct.pack("<18I", 0, 0, 0, 0x50, 0, 0x10, 0, *([0] * 11)) + bytes(0x10)
    assert mbn_stitch(data, b"\xee" * 3) == data[:-3] + b"\xee" * 3
    # BIN: magic at offset 1, total_size at 0x10 includes the header
    data = b"\x00" + MBN_BIN_MAGIC + struct.pack("<4I", 0, 1, 0x20, 0) + bytes(8)
    assert mbn_stitch(data, b"\xdd") == data[:-1] + b"\xdd"
    assert mbn_stitch(MBN_V2_MAGIC + bytes(8), b"\x01") is None  # truncated v2 header

    elf = _elf64(0x100, bytes(0x40))
    assert mbn_is_valid_elf(elf)
    assert mbn_is_64bit_elf(elf)
    assert mbn_stitch(elf, b"\x01\x02") == elf[:-2] + b"\x01\x02"


def test_mbn_mav25_stitch() -> None:
    # dest v7 header: metadata 0x10, hash table 0x10, qti signature 0x8, then room for the OEM signature
    dest_sect = struct.pack("<10I", 0, 7, 0x10, 0, 0, 0x10, 0x8, 0, 0, 0) + bytes(0x10 + 0x10 + 0x8 + 0x10)
    elf = _elf64(0x100, dest_sect)
    src_header = struct.pack("<10I", 0, 7, 0x8, 0, 0, 0x8, 0, 0, 0x4, 0)
    blob = src_header + b"M" * 0x8 + b"H" * 0x8 + b"S" * 0x4
    new_metadata_and_hash = len(src_header) + 0x10

    out = mbn_mav25_stitch(elf, blob)
    assert out is not None
    expected = bytearray(elf)
    expected[0x100 : 0x100 + new_metadata_and_hash] = blob[:new_metadata_and_hash]
    oem_off = 0x100 + new_metadata_and_hash + 0x8
    expected[oem_off : oem_off + 4] = b"S" * 4
    assert out == bytes(expected)

    assert mbn_mav25_stitch(elf, struct.pack("<10I", 0, 6, 0, 0, 0, 0, 0, 0, 0, 0)) is None
