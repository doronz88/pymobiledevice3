# mbn.py
# Support for Qualcomm MBN (Modem Binary) formats — Python port
# Mirrors the logic of mbn.c (v1/v2/BIN headers, ELF detection, and v7 stitching)
#
# Copyright (c) 2012 Martin Szulecki
# Copyright (c) 2012 Nikias Bassen
# Copyright (c) 2025 Visual Ehrmanntraut <visual@chefkiss.dev>
#
# Ported to Python by DoronZ <doron88@gmail.com>. Licensed under LGPL-2.1-or-later (same as original).

import io
import logging
from typing import Optional

from construct import Bytes, ChecksumError, Int16ul, Int32ul, Int64ul, Struct

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
# Construct Structs (little-endian)
# -----------------------------------------------------------------------------

# MBN v1
MBN_V1 = Struct(
    "type" / Int32ul,
    "unk_0x04" / Int32ul,
    "unk_0x08" / Int32ul,
    "unk_0x0c" / Int32ul,
    "data_size" / Int32ul,  # total - sizeof(header)
    "sig_offset" / Int32ul,  # real offset = enc_sig_offset & 0xFFFFFF00 (FYI)
    "unk_0x18" / Int32ul,
    "unk_0x1c" / Int32ul,
    "unk_0x20" / Int32ul,
    "unk_0x24" / Int32ul,
)

# MBN v2
MBN_V2 = Struct(
    "magic1" / Bytes(8),
    "unk_0x08" / Int32ul,
    "unk_0x0c" / Int32ul,  # 0xFFFFFFFF
    "unk_0x10" / Int32ul,  # 0xFFFFFFFF
    "header_size" / Int32ul,
    "unk_0x18" / Int32ul,
    "data_size" / Int32ul,  # total - sizeof(header)
    "sig_offset" / Int32ul,
    "unk_0x24" / Int32ul,
    "unk_0x28" / Int32ul,
    "unk_0x2c" / Int32ul,
    "unk_0x30" / Int32ul,
    "unk_0x34" / Int32ul,  # 0x1
    "unk_0x38" / Int32ul,  # 0x1
    "unk_0x3c" / Int32ul,  # 0xFFFFFFFF
    "unk_0x40" / Int32ul,  # 0xFFFFFFFF
    "unk_0x44" / Int32ul,  # 0xFFFFFFFF
    "unk_0x48" / Int32ul,  # 0xFFFFFFFF
    "unk_0x4c" / Int32ul,  # 0xFFFFFFFF
)

# MBN BIN
MBN_BIN = Struct(
    "magic" / Bytes(8),
    "unk_0x08" / Int32ul,
    "version" / Int32ul,
    "total_size" / Int32ul,  # includes header
    "unk_0x14" / Int32ul,
)

# v7 trailer header used by mbn_mav25_stitch
MBN_V7 = Struct(
    "reserved" / Int32ul,
    "version" / Int32ul,
    "common_metadata_size" / Int32ul,
    "qti_metadata_size" / Int32ul,
    "oem_metadata_size" / Int32ul,
    "hash_table_size" / Int32ul,
    "qti_signature_size" / Int32ul,
    "qti_certificate_chain_size" / Int32ul,
    "oem_signature_size" / Int32ul,
    "oem_certificate_chain_size" / Int32ul,
)

# ELF (minimal fields we need)
ELF32_Ehdr = Struct(
    "e_ident" / Bytes(16),
    "e_type" / Int16ul,
    "e_machine" / Int16ul,
    "e_version" / Int32ul,
    "e_entry" / Int32ul,
    "e_phoff" / Int32ul,
    "e_shoff" / Int32ul,
    "e_flags" / Int32ul,
    "e_ehsize" / Int16ul,
    "e_phentsize" / Int16ul,
    "e_phnum" / Int16ul,
    "e_shentsize" / Int16ul,
    "e_shnum" / Int16ul,
    "e_shstrndx" / Int16ul,
)

ELF64_Ehdr = Struct(
    "e_ident" / Bytes(16),
    "e_type" / Int16ul,
    "e_machine" / Int16ul,
    "e_version" / Int32ul,
    "e_entry" / Int64ul,
    "e_phoff" / Int64ul,
    "e_shoff" / Int64ul,
    "e_flags" / Int32ul,
    "e_ehsize" / Int16ul,
    "e_phentsize" / Int16ul,
    "e_phnum" / Int16ul,
    "e_shentsize" / Int16ul,
    "e_shnum" / Int16ul,
    "e_shstrndx" / Int16ul,
)

ELF32_Phdr = Struct(
    "p_type" / Int32ul,
    "p_offset" / Int32ul,
    "p_vaddr" / Int32ul,
    "p_paddr" / Int32ul,
    "p_filesz" / Int32ul,
    "p_memsz" / Int32ul,
    "p_flags" / Int32ul,
    "p_align" / Int32ul,
)

ELF64_Phdr = Struct(
    "p_type" / Int32ul,
    "p_flags" / Int32ul,
    "p_offset" / Int64ul,
    "p_vaddr" / Int64ul,
    "p_paddr" / Int64ul,
    "p_filesz" / Int64ul,
    "p_memsz" / Int64ul,
    "p_align" / Int64ul,
)


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


def _read_elf_headers(data: bytes):
    if len(data) < EI_NIDENT:
        return None, None
    e_ident = data[:EI_NIDENT]
    if not _is_valid_elf_ident(e_ident):
        return None, None
    if e_ident[EI_CLASS] == ELFCLASS64:
        if len(data) < ELF64_Ehdr.sizeof():
            return None, None
        hdr = ELF64_Ehdr.parse(data[: ELF64_Ehdr.sizeof()])
        return "ELF64", hdr
    elif e_ident[EI_CLASS] == ELFCLASS32:
        if len(data) < ELF32_Ehdr.sizeof():
            return None, None
        hdr = ELF32_Ehdr.parse(data[: ELF32_Ehdr.sizeof()])
        return "ELF32", hdr
    return None, None


def _read_program_headers(data: bytes, kind: str, hdr) -> list:
    phdrs = []
    if hdr.e_phnum == 0:
        logger.error("%s: ELF has no program sections", "_read_program_headers")
        return phdrs

    table_size = hdr.e_phnum * (ELF64_Phdr.sizeof() if kind == "ELF64" else ELF32_Phdr.sizeof())
    if hdr.e_phoff + table_size > len(data):
        logger.error("%s: Program header table is out of bounds", "_read_program_headers")
        return []

    table = data[hdr.e_phoff : hdr.e_phoff + table_size]
    bio = io.BytesIO(table)
    for _ in range(hdr.e_phnum):
        ph = ELF64_Phdr.parse_stream(bio) if kind == "ELF64" else ELF32_Phdr.parse_stream(bio)
        phdrs.append(ph)
    return phdrs


def _elf_last_segment_end(data: bytes) -> Optional[int]:
    kind, hdr = _read_elf_headers(data)
    if not hdr:
        return None
    phdrs = _read_program_headers(data, kind, hdr)
    if not phdrs:
        return None
    # last by highest p_offset
    last = max(phdrs, key=lambda p: int(p.p_offset))
    return int(last.p_offset + last.p_filesz)


def _mbn_v7_header_sizes_valid(h, sect_size: int) -> bool:
    total = (
        MBN_V7.sizeof()
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


def _mbn_v7_header_sizes_expected(h) -> bool:
    return (
        (h.qti_metadata_size in (0, 0xE0))
        and (h.oem_metadata_size in (0, 0xE0))
        and (h.oem_signature_size in (0, 0x68))
        and (h.oem_certificate_chain_size in (0, 0xD20))
    )


def _mbn_v7_log(h, func: str, prefix: str) -> None:
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
    if data is None:
        logger.error("%s: data is NULL", "mbn_stitch")
        return None
    if not data:
        logger.error("%s: data size is 0", "mbn_stitch")
        return None
    if blob is None:
        logger.error("%s: blob is NULL", "mbn_stitch")
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
            if data_size < MBN_V2.sizeof():
                logger.error("%s: truncated MBN v2 header", "mbn_stitch")
                return None
            h = MBN_V2.parse(data[: MBN_V2.sizeof()])
            parsed_size = h.data_size + MBN_V2.sizeof()
            logger.debug(
                "%s: encountered MBN v2 image, parsed_size = 0x%x",
                "mbn_stitch",
                parsed_size,
            )

        # MBN v1
        elif data_size > MBN_V1_MAGIC_SIZE and data[:MBN_V1_MAGIC_SIZE] == MBN_V1_MAGIC:
            if data_size < MBN_V1.sizeof():
                logger.error("%s: truncated MBN v1 header", "mbn_stitch")
                return None
            h = MBN_V1.parse(data[: MBN_V1.sizeof()])
            parsed_size = h.data_size + MBN_V1.sizeof()
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
            if data_size < MBN_BIN.sizeof():
                logger.error("%s: truncated MBN BIN header", "mbn_stitch")
                return None
            h = MBN_BIN.parse(data[: MBN_BIN.sizeof()])
            parsed_size = h.total_size
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

    except ChecksumError:
        logger.exception("mbn_stitch: construct checksum error")
        return None
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
    if data is None:
        logger.error("%s: data is NULL", "mbn_mav25_stitch")
        return None
    if not data:
        logger.error("%s: data size is 0", "mbn_mav25_stitch")
        return None
    if blob is None:
        logger.error("%s: blob is NULL", "mbn_mav25_stitch")
        return None
    if not blob:
        logger.error("%s: blob size is 0", "mbn_mav25_stitch")
        return None

    data_size, blob_size = len(data), len(blob)

    kind, ehdr = _read_elf_headers(data)
    if not ehdr:
        logger.error("%s: data is not a valid ELF", "mbn_mav25_stitch")
        return None

    if blob_size < MBN_V7.sizeof():
        logger.error("%s: header is bigger than blob", "mbn_mav25_stitch")
        return None

    src = MBN_V7.parse(blob[: MBN_V7.sizeof()])
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
    phdrs = _read_program_headers(data, kind, ehdr)
    if not phdrs:
        return None
    last_ph = phdrs[-1]
    sect_off, sect_size = int(last_ph.p_offset), int(last_ph.p_filesz)

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
    if sect_size < MBN_V7.sizeof():
        logger.error(
            "%s: dest header is bigger than the section (0x%x)",
            "mbn_mav25_stitch",
            sect_size,
        )
        return None

    dest = MBN_V7.parse(data[sect_off : sect_off + MBN_V7.sizeof()])
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
    new_metadata_size = MBN_V7.sizeof() + src.common_metadata_size + src.qti_metadata_size + src.oem_metadata_size
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
