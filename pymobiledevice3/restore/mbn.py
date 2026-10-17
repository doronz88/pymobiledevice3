# mbn.py
# Support for Qualcomm MBN (Modem Binary) formats — Python port
# Mirrors the logic of mbn.c (v1/v2/BIN headers, ELF detection, and v7 stitching)
#
# Copyright (c) 2012 Martin Szulecki
# Copyright (c) 2012 Nikias Bassen
# Copyright (c) 2025 Visual Ehrmanntraut <visual@chefkiss.dev>
#
# Ported to Python by DoronZ <doron88@gmail.com>. Licensed under LGPL-2.1-or-later (same as original).

import logging
from dataclasses import dataclass
from typing import Annotated, Optional, Union

from bytestruct import BinaryStruct, ByteReader, Bytes, Const, u16, u32, u64

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
MBN_V1_MAGIC = b"\x0a\x00\x00\x00"
MBN_V1_MAGIC_SIZE = 4

MBN_V2_MAGIC = b"\xd1\xdc\x4b\x84\x34\x10\xd7\x73"
MBN_V2_MAGIC_SIZE = 8

MBN_BIN_MAGIC = b"\x04\x00\xea\x6c\x69\x48\x55"
MBN_BIN_MAGIC_SIZE = 7
MBN_BIN_MAGIC_OFFSET = 1

# ELF
EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3, EI_CLASS = 0, 1, 2, 3, 4
EI_NIDENT = 16
ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3 = 0x7F, ord("E"), ord("L"), ord("F")
ELFCLASSNONE, ELFCLASS32, ELFCLASS64 = 0, 1, 2

# -----------------------------------------------------------------------------
# Header layouts (little-endian)
# -----------------------------------------------------------------------------


@dataclass
class MbnV1Header(BinaryStruct, byte_order="<"):
    magic: Annotated[bytes, Bytes(MBN_V1_MAGIC_SIZE), Const(MBN_V1_MAGIC)]  # the image type
    unk_0x04: u32
    unk_0x08: u32
    unk_0x0c: u32
    data_size: u32  # total - header size
    sig_offset: u32  # real offset = enc_sig_offset & 0xFFFFFF00
    unk_0x18: u32
    unk_0x1c: u32
    unk_0x20: u32
    unk_0x24: u32


@dataclass
class MbnV2Header(BinaryStruct, byte_order="<"):
    magic: Annotated[bytes, Bytes(MBN_V2_MAGIC_SIZE), Const(MBN_V2_MAGIC)]
    unk_0x08: u32
    unk_0x0c: u32
    unk_0x10: u32
    header_size: u32
    unk_0x18: u32
    data_size: u32  # total - header size
    sig_offset: u32
    unk_0x24: u32
    unk_0x28: u32
    unk_0x2c: u32
    unk_0x30: u32
    unk_0x34: u32
    unk_0x38: u32
    unk_0x3c: u32
    unk_0x40: u32
    unk_0x44: u32
    unk_0x48: u32
    unk_0x4c: u32


@dataclass
class MbnBinHeader(BinaryStruct, byte_order="<"):
    magic: Annotated[bytes, Bytes(8)]  # MBN_BIN_MAGIC at MBN_BIN_MAGIC_OFFSET
    unk_0x08: u32
    version: u32
    total_size: u32  # includes the header
    unk_0x14: u32


@dataclass
class MbnV7Header(BinaryStruct, byte_order="<"):
    """Trailer header at the start of the last ELF segment, used by mbn_mav25_stitch."""

    reserved: u32
    version: u32
    common_metadata_size: u32
    qti_metadata_size: u32
    oem_metadata_size: u32
    hash_table_size: u32
    qti_signature_size: u32
    qti_certificate_chain_size: u32
    oem_signature_size: u32
    oem_certificate_chain_size: u32


# ELF headers (little-endian only, as in mbn.c)


@dataclass
class Elf32Ehdr(BinaryStruct, byte_order="<"):
    e_ident: Annotated[bytes, Bytes(EI_NIDENT)]
    e_type: u16
    e_machine: u16
    e_version: u32
    e_entry: u32
    e_phoff: u32
    e_shoff: u32
    e_flags: u32
    e_ehsize: u16
    e_phentsize: u16
    e_phnum: u16
    e_shentsize: u16
    e_shnum: u16
    e_shstrndx: u16


@dataclass
class Elf64Ehdr(BinaryStruct, byte_order="<"):
    e_ident: Annotated[bytes, Bytes(EI_NIDENT)]
    e_type: u16
    e_machine: u16
    e_version: u32
    e_entry: u64
    e_phoff: u64
    e_shoff: u64
    e_flags: u32
    e_ehsize: u16
    e_phentsize: u16
    e_phnum: u16
    e_shentsize: u16
    e_shnum: u16
    e_shstrndx: u16


@dataclass
class Elf32Phdr(BinaryStruct, byte_order="<"):
    p_type: u32
    p_offset: u32
    p_vaddr: u32
    p_paddr: u32
    p_filesz: u32
    p_memsz: u32
    p_flags: u32
    p_align: u32


@dataclass
class Elf64Phdr(BinaryStruct, byte_order="<"):
    p_type: u32
    p_flags: u32  # moved up compared to ELF32
    p_offset: u64
    p_vaddr: u64
    p_paddr: u64
    p_filesz: u64
    p_memsz: u64
    p_align: u64


ElfEhdr = Union[Elf32Ehdr, Elf64Ehdr]
ElfPhdr = Union[Elf32Phdr, Elf64Phdr]


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


def _is_valid_elf_ident(e_ident: bytes) -> bool:
    return (
        len(e_ident) >= EI_NIDENT
        and e_ident[EI_MAG0] == ELFMAG0
        and e_ident[EI_MAG1] == ELFMAG1
        and e_ident[EI_MAG2] == ELFMAG2
        and e_ident[EI_MAG3] == ELFMAG3
        and e_ident[EI_CLASS] != ELFCLASSNONE
    )


def _read_elf_header(data: bytes) -> Optional[ElfEhdr]:
    if len(data) < EI_NIDENT or not _is_valid_elf_ident(data[:EI_NIDENT]):
        return None
    ehdr_type: type[ElfEhdr]
    if data[EI_CLASS] == ELFCLASS64:
        ehdr_type = Elf64Ehdr
    elif data[EI_CLASS] == ELFCLASS32:
        ehdr_type = Elf32Ehdr
    else:
        return None
    if len(data) < ehdr_type.SIZE:
        return None
    return ehdr_type.parse(data)


def _read_program_headers(data: bytes, hdr: ElfEhdr) -> list[ElfPhdr]:
    if hdr.e_phnum == 0:
        logger.error("%s: ELF has no program sections", "_read_program_headers")
        return []

    phdr_type: type[ElfPhdr] = Elf64Phdr if isinstance(hdr, Elf64Ehdr) else Elf32Phdr
    if hdr.e_phoff + hdr.e_phnum * phdr_type.SIZE > len(data):
        logger.error("%s: Program header table is out of bounds", "_read_program_headers")
        return []

    reader = ByteReader(data, hdr.e_phoff)
    return [phdr_type.read(reader) for _ in range(hdr.e_phnum)]


def _elf_last_segment_end(data: bytes) -> Optional[int]:
    hdr = _read_elf_header(data)
    if hdr is None:
        return None
    phdrs = _read_program_headers(data, hdr)
    if not phdrs:
        return None
    # last by highest p_offset
    last = max(phdrs, key=lambda p: p.p_offset)
    return last.p_offset + last.p_filesz


def _mbn_v7_header_sizes_valid(h: MbnV7Header, sect_size: int) -> bool:
    total = (
        MbnV7Header.SIZE
        + h.common_metadata_size
        + h.qti_metadata_size
        + h.oem_metadata_size
        + h.hash_table_size
        + h.qti_signature_size
        + h.qti_certificate_chain_size
        + h.oem_signature_size
        + h.oem_certificate_chain_size
    )
    return total <= sect_size


def _mbn_v7_header_sizes_expected(h: MbnV7Header) -> bool:
    return (
        (h.qti_metadata_size in (0, 0xE0))
        and (h.oem_metadata_size in (0, 0xE0))
        and (h.oem_signature_size in (0, 0x68))
        and (h.oem_certificate_chain_size in (0, 0xD20))
    )


def _mbn_v7_log(h: MbnV7Header, func: str, prefix: str) -> None:
    logger.debug(
        "%s: %s header {version=0x%x, common_metadata_size=0x%x, qti_metadata_size=0x%x, "
        "oem_metadata_size=0x%x, hash_table_size=0x%x, qti_signature_size=0x%x, "
        "qti_certificate_chain_size=0x%x, oem_signature_size=0x%x, oem_certificate_chain_size=0x%x}",
        func,
        prefix,
        h.version,
        h.common_metadata_size,
        h.qti_metadata_size,
        h.oem_metadata_size,
        h.hash_table_size,
        h.qti_signature_size,
        h.qti_certificate_chain_size,
        h.oem_signature_size,
        h.oem_certificate_chain_size,
    )


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def mbn_stitch(data: bytes, blob: bytes) -> Optional[bytes]:
    """
    Overwrite the tail of `data` with `blob`. Format-aware size logging/checks.
    Returns new bytes or None.
    """
    if not data:
        logger.error("%s: data size is 0", "mbn_stitch")
        return None
    if not blob:
        logger.error("%s: blob size is 0", "mbn_stitch")
        return None

    data_size = len(data)
    blob_size = len(blob)
    parsed_size = 0

    try:
        # MBN v2
        if data_size > MBN_V2_MAGIC_SIZE and data[:MBN_V2_MAGIC_SIZE] == MBN_V2_MAGIC:
            if data_size < MbnV2Header.SIZE:
                logger.error("%s: truncated MBN v2 header", "mbn_stitch")
                return None
            parsed_size = MbnV2Header.parse(data).data_size + MbnV2Header.SIZE
            logger.debug(
                "%s: encountered MBN v2 image, parsed_size = 0x%x",
                "mbn_stitch",
                parsed_size,
            )

        # MBN v1
        elif data_size > MBN_V1_MAGIC_SIZE and data[:MBN_V1_MAGIC_SIZE] == MBN_V1_MAGIC:
            if data_size < MbnV1Header.SIZE:
                logger.error("%s: truncated MBN v1 header", "mbn_stitch")
                return None
            parsed_size = MbnV1Header.parse(data).data_size + MbnV1Header.SIZE
            logger.debug(
                "%s: encountered MBN v1 image, parsed_size = 0x%x",
                "mbn_stitch",
                parsed_size,
            )

        # BIN
        elif (
            data_size > (MBN_BIN_MAGIC_SIZE + MBN_BIN_MAGIC_OFFSET)
            and data[MBN_BIN_MAGIC_OFFSET : MBN_BIN_MAGIC_OFFSET + MBN_BIN_MAGIC_SIZE] == MBN_BIN_MAGIC
        ):
            if data_size < MbnBinHeader.SIZE:
                logger.error("%s: truncated MBN BIN header", "mbn_stitch")
                return None
            parsed_size = MbnBinHeader.parse(data).total_size
            logger.debug(
                "%s: encountered MBN BIN image, parsed_size = 0x%x",
                "mbn_stitch",
                parsed_size,
            )

        # ELF
        else:
            end = _elf_last_segment_end(data)
            if end is not None:
                parsed_size = end
                logger.debug(
                    "%s: encountered ELF image, parsed_size = 0x%x",
                    "mbn_stitch",
                    parsed_size,
                )
            else:
                logger.warning("Unknown file format passed to %s", "mbn_stitch")
                parsed_size = data_size

        if parsed_size != data_size:
            logger.warning(
                "%s: size mismatch for MBN data, expected 0x%x, input size 0x%x",
                "mbn_stitch",
                parsed_size,
                data_size,
            )

        stitch_offset = data_size - blob_size
        if stitch_offset < 0 or stitch_offset + blob_size > data_size:
            logger.error(
                "%s: stitch offset (0x%x) + size (0x%x) is larger than the destination (0x%x)",
                "mbn_stitch",
                stitch_offset,
                blob_size,
                data_size,
            )
            return None

        out = bytearray(data)
        logger.debug(
            "%s: stitching mbn at 0x%x, size 0x%x",
            "mbn_stitch",
            stitch_offset,
            blob_size,
        )
        out[stitch_offset : stitch_offset + blob_size] = blob
        return bytes(out)

    except Exception:
        logger.exception("mbn_stitch")
        return None


def mbn_mav25_stitch(data: bytes, blob: bytes) -> Optional[bytes]:
    """
    Patch an ELF's last program-section area with a v7 trailer from `blob`.
    - Writes new metadata+hash at section start
    - Writes OEM sig+chain after existing dest qti sig+chain
    Returns new bytes or None.
    """
    if not data:
        logger.error("%s: data size is 0", "mbn_mav25_stitch")
        return None
    if not blob:
        logger.error("%s: blob size is 0", "mbn_mav25_stitch")
        return None

    data_size, blob_size = len(data), len(blob)

    ehdr = _read_elf_header(data)
    if ehdr is None:
        logger.error("%s: data is not a valid ELF", "mbn_mav25_stitch")
        return None

    if blob_size < MbnV7Header.SIZE:
        logger.error("%s: header is bigger than blob", "mbn_mav25_stitch")
        return None

    src = MbnV7Header.parse(blob)
    _mbn_v7_log(src, "mbn_mav25_stitch", "src")
    if src.version != 7:
        logger.error(
            "%s: src header version (0x%x) is incorrect",
            "mbn_mav25_stitch",
            src.version,
        )
        return None
    if not _mbn_v7_header_sizes_expected(src):
        logger.warning(
            "%s: header sizes in header are unexpected (qti_metadata_size=0x%x, oem_metadata_size=0x%x, "
            "oem_signature_size=0x%x, oem_certificate_chain_size=0x%x)",
            "mbn_mav25_stitch",
            src.qti_metadata_size,
            src.oem_metadata_size,
            src.oem_signature_size,
            src.oem_certificate_chain_size,
        )

    # last PHDR (by index)
    phdrs = _read_program_headers(data, ehdr)
    if not phdrs:
        return None
    last_ph = phdrs[-1]
    sect_off, sect_size = last_ph.p_offset, last_ph.p_filesz

    if sect_off == 0:
        logger.error("%s: section has 0 offset", "mbn_mav25_stitch")
        return None
    if sect_size == 0:
        logger.error("%s: section has 0 size", "mbn_mav25_stitch")
        return None
    if sect_off + sect_size > data_size:
        logger.error(
            "%s: section (0x%x+0x%x) is bigger than the data",
            "mbn_mav25_stitch",
            sect_off,
            sect_size,
        )
        return None
    if sect_size < MbnV7Header.SIZE:
        logger.error(
            "%s: dest header is bigger than the section (0x%x)",
            "mbn_mav25_stitch",
            sect_size,
        )
        return None

    dest = MbnV7Header.parse(data[sect_off : sect_off + MbnV7Header.SIZE])
    _mbn_v7_log(dest, "mbn_mav25_stitch", "dest")
    if dest.version != 7:
        logger.error(
            "%s: dest header version (0x%x) is incorrect",
            "mbn_mav25_stitch",
            dest.version,
        )
        return None
    if not _mbn_v7_header_sizes_valid(dest, sect_size):
        logger.error(
            (
                "%s: sizes in dest header are invalid (common_metadata_size=0x%x, qti_metadata_size=0x%x, "
                "oem_metadata_size=0x%x, hash_table_size=0x%x, qti_signature_size=0x%x, "
                "qti_certificate_chain_size=0x%x, oem_signature_size=0x%x, "
                "oem_certificate_chain_size=0x%x)"
            ),
            "mbn_mav25_stitch",
            dest.common_metadata_size,
            dest.qti_metadata_size,
            dest.oem_metadata_size,
            dest.hash_table_size,
            dest.qti_signature_size,
            dest.qti_certificate_chain_size,
            dest.oem_signature_size,
            dest.oem_certificate_chain_size,
        )
        return None
    if not _mbn_v7_header_sizes_expected(dest):
        logger.warning(
            "%s: header sizes in dest header are unexpected (qti_metadata_size=0x%x, oem_metadata_size=0x%x, "
            "oem_signature_size=0x%x, oem_certificate_chain_size=0x%x)",
            "mbn_mav25_stitch",
            dest.qti_metadata_size,
            dest.oem_metadata_size,
            dest.oem_signature_size,
            dest.oem_certificate_chain_size,
        )

    # compute new layout from src
    new_metadata_size = MbnV7Header.SIZE + src.common_metadata_size + src.qti_metadata_size + src.oem_metadata_size
    new_metadata_and_hash_table_size = new_metadata_size + src.hash_table_size
    new_oem_sig_and_cert_chain_size = src.oem_signature_size + src.oem_certificate_chain_size

    new_oem_sig_and_cert_chain_off = (
        new_metadata_and_hash_table_size + dest.qti_signature_size + dest.qti_certificate_chain_size
    )

    # bounds
    if new_metadata_and_hash_table_size > blob_size:
        logger.error(
            "%s: new metadata (0x%x) and hash table (0x%x) are bigger than the source (0x%x)",
            "mbn_mav25_stitch",
            new_metadata_size,
            src.hash_table_size,
            blob_size,
        )
        return None
    if new_metadata_and_hash_table_size > sect_size:
        logger.error(
            "%s: new metadata (0x%x) and hash table (0x%x) are bigger than the destination (0x%x)",
            "mbn_mav25_stitch",
            new_metadata_size,
            src.hash_table_size,
            sect_size,
        )
        return None
    if new_metadata_and_hash_table_size + new_oem_sig_and_cert_chain_size > blob_size:
        logger.error(
            "%s: new OEM signature and certificate chain are bigger than the source",
            "mbn_mav25_stitch",
        )
        return None
    if new_oem_sig_and_cert_chain_off + new_oem_sig_and_cert_chain_size > sect_size:
        logger.error(
            "%s: new OEM signature and certificate chain are outside the bounds of the destination",
            "mbn_mav25_stitch",
        )
        return None

    out = bytearray(data)
    # write metadata + hash
    logger.debug(
        "%s: stitching mbn at 0x%x (0x%x bytes)",
        "mbn_mav25_stitch",
        sect_off,
        new_metadata_and_hash_table_size,
    )
    out[sect_off : sect_off + new_metadata_and_hash_table_size] = blob[:new_metadata_and_hash_table_size]

    # write OEM sig + chain
    logger.debug(
        "%s: stitching mbn at 0x%x (0x%x bytes)",
        "mbn_mav25_stitch",
        sect_off + new_oem_sig_and_cert_chain_off,
        new_oem_sig_and_cert_chain_size,
    )
    start = new_metadata_and_hash_table_size
    end = start + new_oem_sig_and_cert_chain_size

    slice_start = sect_off + new_oem_sig_and_cert_chain_off
    slice_end = sect_off + new_oem_sig_and_cert_chain_off + new_oem_sig_and_cert_chain_size
    out[slice_start:slice_end] = blob[start:end]

    return bytes(out)


# -----------------------------------------------------------------------------
# Tiny helpers (optional)
# -----------------------------------------------------------------------------


def mbn_is_valid_elf(buf: bytes) -> bool:
    return len(buf) >= EI_NIDENT and _is_valid_elf_ident(buf[:EI_NIDENT])


def mbn_is_64bit_elf(buf: bytes) -> bool:
    return len(buf) >= EI_NIDENT and buf[EI_CLASS] == ELFCLASS64
