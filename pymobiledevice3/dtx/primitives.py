"""DTX primitive value types and dictionary codec.

This module provides the low-level wire representation for DTX *auxiliary
arguments*.  Every call-site value is encoded as one of six primitive types:

- :class:`PrimitiveNull`   (wire type 10) - positional NULL marker
- :class:`PrimitiveString` (wire type 1)  - length-prefixed UTF-8
- :class:`PrimitiveBuffer` (wire type 2)  - length-prefixed raw bytes or NSKeyedArchive
- :class:`PrimitiveInt32`  (wire type 3)  - 32-bit signed integer
- :class:`PrimitiveInt64`  (wire type 6)  - 64-bit signed integer
- :class:`PrimitiveDouble` (wire type 9)  - IEEE-754 double

Each type inherits from both :class:`_PrimitiveBase` and a Python builtin so it
can be used transparently in application code while still carrying wire-encoding
intent.  Short aliases (``PNull``, ``PBuf``, ``PInt32``, ``PInt64``, ``PDouble``,
``PStr``) are provided for convenience.

The :class:`PrimitiveDictionary` type serialises and deserialises a list of
``(key, value)`` pairs in the DTX aux dictionary wire format.  The module-level
:func:`read_primitive`/:func:`write_primitive` (and :func:`parse_primitive`/
:func:`build_primitive`) helpers convert between primitive instances and their
on-wire byte representation.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Any, ClassVar

from bytestruct import (
    F64_LE,
    I32_LE,
    I64_LE,
    U32_LE,
    BinaryBuildError,
    BinaryParseError,
    BinaryStruct,
    ByteReader,
    BytesLike,
    u32,
    u64,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PRIMITIVE_DICTIONARY_HEADER_SIZE: int = 16
"""Byte length of the PrimitiveDictionary wire header (two u64 fields)."""

logger = logging.getLogger(__name__)
# Registry: wire type code → _PrimitiveBase subclass.
_PRIMITIVE_REGISTRY: dict[int, type[_PrimitiveBase]] = {}
# Base magic mask. Upper bits carry optional flags observed as 0x100, 0x200 …
_PRIMITIVE_TYPE_MASK = 0xFF

_TAG_AND_U32 = struct.Struct("<II")
_TAG_AND_I32 = struct.Struct("<Ii")
_TAG_AND_I64 = struct.Struct("<Iq")
_TAG_AND_F64 = struct.Struct("<Id")


@dataclass
class _DictionaryHeader(BinaryStruct, byte_order="<"):
    """The PrimitiveDictionary header fields following its type tag."""

    unknown_flags: u32
    body_length: u64  # byte count of the entries that follow


def _pack(fmt: struct.Struct, *values: Any) -> bytes:
    try:
        return fmt.pack(*values)
    except struct.error as e:
        raise BinaryBuildError(f"cannot encode {values!r}: {e}") from e


def _read_length_prefixed(reader: ByteReader) -> bytes:
    """Read a u32 length and then up to that many bytes; a short body is returned as-is (not an error)."""
    length = reader.unpack_one(U32_LE)
    return reader.read(min(length, reader.remaining))


class _PrimitiveBase:
    """Mixin that gives a Python value class its DTX wire type code and codec.

    Subclasses inherit from both :class:`_PrimitiveBase` and a Python builtin
    (``int``, ``float``, ``str``, or ``bytes``, ``list``, ``dict``) so they
    can be used transparently wherever that builtin is expected while
    still carrying encoding intent.
    """

    _type_code: ClassVar[int]

    @classmethod
    def _read(cls, reader: ByteReader) -> Any:
        """Parse this value's bytes (type tag already consumed) from *reader* and return a new instance.

        Return type is ``Any`` rather than ``_PrimitiveBase`` because
        :class:`PrimitiveDictionary` decodes to a plain ``dict`` while every
        other subclass returns a concrete ``_PrimitiveBase`` value.
        """
        raise NotImplementedError

    def _write(self, out: bytearray) -> None:
        """Append the encoded primitive (type tag included) to *out*."""
        raise NotImplementedError


def read_primitive(reader: ByteReader) -> Any:
    """Parse a single DTX primitive (u32 type tag followed by value bytes) from *reader*."""
    tag_offset = reader.absolute
    raw_type_code = reader.unpack_one(U32_LE)
    cls = _PRIMITIVE_REGISTRY.get(raw_type_code & _PRIMITIVE_TYPE_MASK)
    if cls is None:
        raise BinaryParseError(f"unknown primitive type code {raw_type_code:#x}", offset=tag_offset)
    return cls._read(reader)


def write_primitive(obj: object, out: bytearray) -> None:
    """Append the wire encoding of the primitive *obj* (type tag included) to *out*."""
    if not isinstance(obj, _PrimitiveBase):
        raise BinaryBuildError(f"expected a DTX primitive, got {type(obj).__name__}")
    obj._write(out)


def parse_primitive(data: BytesLike) -> Any:
    """Parse a single DTX primitive from the start of *data* (trailing bytes are ignored)."""
    return read_primitive(ByteReader(data))


def build_primitive(obj: object) -> bytes:
    """Return the wire encoding of the primitive *obj*."""
    out = bytearray()
    write_primitive(obj, out)
    return bytes(out)


class PrimitiveNull(_PrimitiveBase):
    """NULL marker (wire type 10). No value bytes follow the type tag.

    Used as an index/positional-slot marker — DTX aux dictionaries use NULL
    as the key for every positional argument (see :func:`_args_to_aux_bytes`).
    """

    _type_code = 10

    @classmethod
    def _read(cls, reader: ByteReader) -> PrimitiveNull:
        return PNULL  # return the singleton instance for convenience

    def _write(self, out: bytearray) -> None:
        out += U32_LE.pack(self._type_code)  # type tag only, no value bytes

    def __eq__(self, value: object):
        return type(self) is type(value)  # all instances are equal, since there is no value data

    def __hash__(self):
        return id(PNULL)


class PrimitiveString(_PrimitiveBase, str):
    """Length-prefixed UTF-8 string primitive (wire type 1).

    Without this marker, plain Python strings are NSKeyedArchive-encoded as a
    BUFFER (the default).  Use :data:`PStr` as a shorter alias.
    """

    _type_code = 1

    @classmethod
    def _read(cls, reader: ByteReader) -> PrimitiveString:
        return cls(_read_length_prefixed(reader).decode("utf-8", errors="replace"))

    def _write(self, out: bytearray) -> None:
        raw = str(self).encode("utf-8")
        out += _pack(_TAG_AND_U32, self._type_code, len(raw))
        out += raw


class PrimitiveInt32(_PrimitiveBase, int):
    """32-bit integer primitive (wire type 3).

    Wrap a call-site value—or annotate a :func:`~pymobiledevice3.dtx.service.dtx_method`
    stub parameter—to send it as INT32 rather than as an NSKeyedArchive buffer.
    Use :data:`PInt32` as a shorter alias.
    """

    _type_code = 3

    @classmethod
    def _read(cls, reader: ByteReader) -> PrimitiveInt32:
        return cls(reader.unpack_one(I32_LE))

    def _write(self, out: bytearray) -> None:
        out += _pack(_TAG_AND_I32, self._type_code, int(self))


class PrimitiveInt64(_PrimitiveBase, int):
    """64-bit integer primitive (wire type 6).  Use :data:`PInt64` as a shorter alias."""

    _type_code = 6

    @classmethod
    def _read(cls, reader: ByteReader) -> PrimitiveInt64:
        return cls(reader.unpack_one(I64_LE))

    def _write(self, out: bytearray) -> None:
        out += _pack(_TAG_AND_I64, self._type_code, int(self))


class PrimitiveBuffer(_PrimitiveBase, bytes):
    """Raw bytes buffer (wire type 2)."""

    _type_code = 2

    @classmethod
    def _read(cls, reader: ByteReader) -> PrimitiveBuffer:
        return cls(_read_length_prefixed(reader))

    def _write(self, out: bytearray) -> None:
        out += _pack(_TAG_AND_U32, self._type_code, len(self))
        out += self


class PrimitiveDouble(_PrimitiveBase, float):
    """IEEE-754 double primitive (wire type 9).  Use :data:`PDouble`."""

    _type_code = 9

    @classmethod
    def _read(cls, reader: ByteReader) -> PrimitiveDouble:
        return cls(reader.unpack_one(F64_LE))

    def _write(self, out: bytearray) -> None:
        out += _pack(_TAG_AND_F64, self._type_code, float(self))


class PrimitiveDictionary(_PrimitiveBase, dict[Any, list[Any]]):
    """A primitive dictionaary (wire type 0xF0). Use :data:`PDict` as a shorter alias.

    Wire layout::
        u32  type_anf_flags    0xF0 | optional flags in upper bits (0x100, 0x200 …)
        u32  unknown_flags     0x0
        u64  body_length       byte count of everything that follows
        [key_primitive, value_primitive] x N entries
    """

    _type_code = 0xF0
    _HEADER_SIZE: ClassVar[int] = 16
    _DEFAULT_MAGIC: ClassVar[int] = 0x1F0  # 0x100 | 0xF0 — seen most often

    @classmethod
    def _read(cls, reader: ByteReader) -> dict[Any, list[Any]]:
        header = _DictionaryHeader.read(reader)
        begin = reader.offset
        result: dict[Any, list[Any]] = {}
        while reader.offset - begin < header.body_length:
            key = read_primitive(reader)
            value = read_primitive(reader)
            result.setdefault(key, []).append(value)
        if header.unknown_flags != 0:
            logger.warning(f"PrimitiveDictionary: non-zero unknown flags {header.unknown_flags:#x}: {result!r}")
        return result

    def _write(self, out: bytearray) -> None:
        start = len(out)
        out += bytes(self._HEADER_SIZE)  # reserve space for header
        for key, values in self.items():
            for value in values:
                write_primitive(key, out)
                write_primitive(value, out)
        body_len = len(out) - start - self._HEADER_SIZE
        # most observed magic value with type code and flags combined; unknown flags always 0 in observed samples
        out[start : start + self._HEADER_SIZE] = (
            U32_LE.pack(self._DEFAULT_MAGIC) + _DictionaryHeader(0, body_len).build()
        )


# Convenience short aliases
PNull = PrimitiveNull
PBuf = PrimitiveBuffer
PInt32 = PrimitiveInt32
PInt64 = PrimitiveInt64
PDouble = PrimitiveDouble
PStr = PrimitiveString
PDict = PrimitiveDictionary


_all_primitive_types: list[type[_PrimitiveBase]] = [
    PrimitiveNull,
    PrimitiveString,
    PrimitiveBuffer,
    PrimitiveInt32,
    PrimitiveInt64,
    PrimitiveDouble,
    PrimitiveDictionary,
]
_PRIMITIVE_REGISTRY.update({cls._type_code: cls for cls in _all_primitive_types})
PNULL = PrimitiveNull()  # singleton instance for convenience
PRIMITIVE_TYPES = tuple(_PRIMITIVE_REGISTRY.values())
