"""DTX primitive value types and dictionary codec.

This module provides the low-level wire representation for DTX *auxiliary
arguments*.  Every call-site value is encoded as one of six primitive types:

- :class:`PrimitiveNull`   (wire type 10) - positional NULL marker
- :class:`PrimitiveString` (wire type 1)  - length-prefixed UTF-8
- :class:`PrimitiveBuffer` (wire type 2)  - length-prefixed raw bytes or NSKeyedArchive
- :class:`PrimitiveInt32`  (wire type 3)  - 32-bit unsigned integer
- :class:`PrimitiveInt64`  (wire type 6)  - 64-bit unsigned integer
- :class:`PrimitiveDouble` (wire type 9)  - IEEE-754 double

Each type inherits from both :class:`_PrimitiveBase` and a Python builtin so it
can be used transparently in application code while still carrying wire-encoding
intent.  Short aliases (``PNull``, ``PBuf``, ``PInt32``, ``PInt64``, ``PDouble``,
``PStr``) are provided for convenience.

The :class:`PrimitiveDictionary` Construct serialises and deserialises a list of
``(key, value)`` pairs in the DTX aux dictionary wire format.  The module-level
:func:`_args_to_aux_bytes` and :func:`parse_aux` helpers convert between Python
argument lists and the on-wire byte representation used by
:class:`~pymobiledevice3.dtx.channel.DTXChannel`.
"""

from __future__ import annotations

import io
import logging
from typing import Any, ClassVar

from construct import (
    Bytes,
    Construct,
    ConstructError,
    Container,
    ExplicitError,
    Float64l,
    Int32sl,
    Int32ul,
    Int64sl,
    Int64ul,
    SizeofError,
    stream_seek,
    stream_tell,
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


class _PrimitiveBase:
    """Mixin that gives a Python value class its DTX wire type code and codec.

    Subclasses inherit from both :class:`_PrimitiveBase` and a Python builtin
    (``int``, ``float``, ``str``, or ``bytes``, ``list``, ``dict``) so they
    can be used transparently wherever that builtin is expected while
    still carrying encoding intent.
    """

    _type_code: ClassVar[int]

    @classmethod
    def _read(cls, stream, context, path) -> _PrimitiveBase:
        """Parse this value's bytes from *stream* and return a new instance."""
        raise NotImplementedError

    def _write(self, stream, context, path) -> None:
        """Write the encoded value bytes to *stream* (type tag NOT included)."""
        raise NotImplementedError


class PrimitiveValue(Construct):
    """Construct for a single DTX primitive: u32 type tag followed by value bytes."""

    def _parse(self, stream, context, path) -> Any:
        context = context or {}
        raw_type_code = Int32ul._parse(stream, context, path)
        context["type_code_and_flags"] = raw_type_code
        type_code = raw_type_code & _PRIMITIVE_TYPE_MASK

        cls = _PRIMITIVE_REGISTRY.get(type_code)
        if cls is None:
            raise ConstructError(f"unknown primitive type code {raw_type_code:#x}", path)
        return cls._read(stream, context, path)

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, _PrimitiveBase):
            raise ConstructError(
                f"Expected a _PrimitiveBase instance for PrimitiveValue, got {type(obj).__name__}", path
            )
        return obj._write(stream, context, path)

    def _sizeof(self, context, path):
        raise SizeofError("variable-length primitive")


_primitive_value_con = PrimitiveValue()


class PrimitiveNull(_PrimitiveBase):
    """NULL marker (wire type 10). No value bytes follow the type tag.

    Used as an index/positional-slot marker — DTX aux dictionaries use NULL
    as the key for every positional argument (see :func:`_args_to_aux_bytes`).
    """

    _type_code = 10

    @classmethod
    def _read(cls, stream, context, path) -> None:  # type: ignore[override]
        return PNULL  # return the singleton instance for convenience

    def _write(self, stream, context, path) -> None:
        Int32ul._build(self._type_code, stream, context, path)  # type tag only, no value bytes

    def __eq__(self, value):
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
    def _read(cls, stream, context, path) -> PrimitiveString:
        length = Int32ul._parse(stream, context, path)
        return cls(stream.read(length).decode("utf-8", errors="replace"))

    def _write(self, stream, context, path) -> None:
        Int32ul._build(self._type_code, stream, context, path)
        raw = str(self).encode("utf-8")
        length = len(raw)
        Int32ul._build(length, stream, context, path)
        Bytes(length)._build(raw, stream, context, path)


class PrimitiveInt32(_PrimitiveBase, int):
    """32-bit integer primitive (wire type 3).

    Wrap a call-site value—or annotate a :func:`~pymobiledevice3.dtx.service.dtx_method`
    stub parameter—to send it as INT32 rather than as an NSKeyedArchive buffer.
    Use :data:`PInt32` as a shorter alias.
    """

    _type_code = 3

    @classmethod
    def _read(cls, stream, context, path) -> PrimitiveInt32:
        return cls(Int32sl._parse(stream, context, path))

    def _write(self, stream, context, path) -> None:
        Int32ul._build(self._type_code, stream, context, path)
        Int32sl._build(int(self), stream, context, path)


class PrimitiveInt64(_PrimitiveBase, int):
    """64-bit integer primitive (wire type 6).  Use :data:`PInt64` as a shorter alias."""

    _type_code = 6

    @classmethod
    def _read(cls, stream, context, path) -> PrimitiveInt64:
        return cls(Int64sl._parse(stream, context, path))

    def _write(self, stream, context, path) -> None:
        Int32ul._build(self._type_code, stream, context, path)
        Int64sl._build(int(self), stream, context, path)


class PrimitiveBuffer(_PrimitiveBase, bytes):
    """Raw bytes buffer (wire type 2)."""

    _type_code = 2

    @classmethod
    def _read(cls, stream, context, path) -> PrimitiveBuffer:
        length = Int32ul._parse(stream, context, path)
        return cls(stream.read(length))

    def _write(self, stream, context, path) -> None:
        Int32ul._build(self._type_code, stream, context, path)
        length = len(self)
        Int32ul._build(length, stream, context, path)
        Bytes(length)._build(bytes(self), stream, context, path)


class PrimitiveDouble(_PrimitiveBase, float):
    """IEEE-754 double primitive (wire type 9).  Use :data:`PDouble`."""

    _type_code = 9

    @classmethod
    def _read(cls, stream, context, path) -> PrimitiveDouble:
        return cls(Float64l._parse(stream, context, path))

    def _write(self, stream, context, path) -> None:
        Int32ul._build(self._type_code, stream, context, path)
        Float64l._build(float(self), stream, context, path)


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
    def _read(cls, stream, context, path) -> dict[Any, list[Any]]:
        unknown_flags = Int32ul._parse(stream, context, path)
        body_len = Int64ul._parse(stream, context, path)
        begin = stream_tell(stream, path)
        result: dict[Any, list[Any]] = {}
        subcontext = Container()
        subcontext._ = context
        i = 0
        while stream_tell(stream, path) - begin < body_len:
            key = _primitive_value_con._parse(stream, subcontext, f"{path}[{i}].key")
            value = _primitive_value_con._parse(stream, subcontext, f"{path}[{i}].value")
            result.setdefault(key, []).append(value)
            i += 1
        if unknown_flags != 0:
            logger.warning(f"PrimitiveDictionary: non-zero unknown flags {unknown_flags:#x} at {path}: {result!r}")
        return result

    def _write(self, stream, context, path):
        if any(not isinstance(values, list) for values in self.values()):
            raise ExplicitError(
                f"Expected a dict[Any, list[Any]] for PrimitiveDictionary, got dict[Any, {type(next(iter(self.values()))).__name__}]: {self!r}",
                path,
            )

        start = stream_tell(stream, path)
        stream_seek(stream, self._HEADER_SIZE, io.SEEK_CUR, path)  # reserve space for header
        begin = stream_tell(stream, path)
        i = 0
        for key, values in self.items():
            for value in values:
                _primitive_value_con._build(key, stream, context, f"{path}[{i}].key")
                _primitive_value_con._build(value, stream, context, f"{path}[{i}].value")
                i += 1
        end = stream_tell(stream, path)
        body_len = end - begin
        stream_seek(stream, start, io.SEEK_SET, path)
        Int32ul._build(
            self._DEFAULT_MAGIC, stream, context, path
        )  # most observed magic value with type code and flags combined
        Int32ul._build(0, stream, context, path)  # unknown flags, always 0 in observed samples
        Int64ul._build(body_len, stream, context, path)
        stream_seek(stream, end, io.SEEK_SET, path)


# Convenience short aliases
PNull = PrimitiveNull
PBuf = PrimitiveBuffer
PInt32 = PrimitiveInt32
PInt64 = PrimitiveInt64
PDouble = PrimitiveDouble
PStr = PrimitiveString
PDict = PrimitiveDictionary


_PRIMITIVE_REGISTRY.update({
    cls._type_code: cls
    for cls in [
        PrimitiveNull,
        PrimitiveString,
        PrimitiveBuffer,
        PrimitiveInt32,
        PrimitiveInt64,
        PrimitiveDouble,
        PrimitiveDictionary,
    ]
})
PNULL = PrimitiveNull()  # singleton instance for convenience
PRIMITIVE_TYPES = tuple(_PRIMITIVE_REGISTRY.values())
