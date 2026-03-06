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
from collections.abc import Sequence
from typing import Any, ClassVar

from bpylist2 import archiver
from construct import (
    Construct,
    ConstructError,
    Float64l,
    Int32ul,
    Int64ul,
    SizeofError,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PRIMITIVE_DICTIONARY_HEADER_SIZE: int = 16
"""Byte length of the PrimitiveDictionary wire header (two u64 fields)."""

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Primitive value types  (wire codec + Python type in one class)
# ---------------------------------------------------------------------------


class _PrimitiveBase:
    """Mixin that gives a Python value class its DTX wire type code and codec.

    Subclasses inherit from both :class:`_PrimitiveBase` and a Python builtin
    (``int``, ``float``, ``str``, or ``bytes``) so they can be used transparently
    wherever that builtin is expected while still carrying encoding intent.
    """

    _type_code: ClassVar[int]

    @classmethod
    def _read(cls, stream: io.RawIOBase, context: Any, path: str) -> _PrimitiveBase:
        """Parse this value's bytes from *stream* and return a new instance."""
        raise NotImplementedError

    def _write(self, stream: io.RawIOBase, context: Any, path: str) -> None:
        """Write the encoded value bytes to *stream* (type tag NOT included)."""
        raise NotImplementedError


class PrimitiveNull(_PrimitiveBase):
    """NULL marker (wire type 10). No value bytes follow the type tag.

    Used as an index/positional-slot marker — DTX aux dictionaries use NULL
    as the key for every positional argument (see :func:`_args_to_aux_bytes`).
    """

    _type_code = 10

    @classmethod
    def _read(cls, stream: io.RawIOBase, context: Any, path: str) -> None:  # type: ignore[override]
        return None  # no value bytes follow the type tag

    def _write(self, stream: io.RawIOBase, context: Any, path: str) -> None:
        pass  # no value bytes to write


class PrimitiveString(_PrimitiveBase, str):
    """Length-prefixed UTF-8 string primitive (wire type 1).

    Without this marker, plain Python strings are NSKeyedArchive-encoded as a
    BUFFER (the default).  Use :data:`PStr` as a shorter alias.
    """

    _type_code = 1

    @classmethod
    def _read(cls, stream: io.RawIOBase, context: Any, path: str) -> PrimitiveString:
        length = Int32ul._parse(stream, context, path)
        return cls(stream.read(length).decode("utf-8", errors="replace"))

    def _write(self, stream: io.RawIOBase, context: Any, path: str) -> None:
        raw = str(self).encode("utf-8")
        Int32ul._build(len(raw), stream, context, path)
        stream.write(raw)


class PrimitiveInt32(_PrimitiveBase, int):
    """32-bit unsigned integer primitive (wire type 3).

    Wrap a call-site value—or annotate a :func:`~pymobiledevice3.dtx.service.dtx_method`
    stub parameter—to send it as INT32 rather than as an NSKeyedArchive buffer.
    Use :data:`PInt32` as a shorter alias.
    """

    _type_code = 3

    @classmethod
    def _read(cls, stream: io.RawIOBase, context: Any, path: str) -> PrimitiveInt32:
        return cls(Int32ul._parse(stream, context, path))

    def _write(self, stream: io.RawIOBase, context: Any, path: str) -> None:
        Int32ul._build(int(self), stream, context, path)


class PrimitiveInt64(_PrimitiveBase, int):
    """64-bit unsigned integer primitive (wire type 6).  Use :data:`PInt64`."""

    _type_code = 6

    @classmethod
    def _read(cls, stream: io.RawIOBase, context: Any, path: str) -> PrimitiveInt64:
        return cls(Int64ul._parse(stream, context, path))

    def _write(self, stream: io.RawIOBase, context: Any, path: str) -> None:
        Int64ul._build(int(self), stream, context, path)


class PrimitiveBuffer(_PrimitiveBase, bytes):
    """Raw bytes buffer (wire type 2).

    Unlike plain Python objects (which are NSKeyedArchive-encoded before being
    sent as BUFFER type 2), :class:`PrimitiveBuffer` sends the raw bytes
    verbatim (length-prefixed), without archiving.

    On the parse path, wire type 2 is first attempted as NSKeyedArchive; only
    on decode failure are the raw bytes returned as a :class:`PrimitiveBuffer`.
    Use :data:`PBuf` as a shorter alias.
    """

    _type_code = 2

    @classmethod
    def _read(cls, stream: io.RawIOBase, context: Any, path: str) -> Any:
        length = Int32ul._parse(stream, context, path)
        if length == 0:
            return cls(b"")
        raw = stream.read(length)
        if raw.startswith(b"bplist"):
            try:
                return archiver.unarchive(raw)
            except Exception as e:
                logger.error("Failed to decode NSKeyedArchive in PrimitiveBuffer: error=%s, buf[:100]=%s", e, raw[:100])

        return cls(raw)

    def _write(self, stream: io.RawIOBase, context: Any, path: str) -> None:
        Int32ul._build(len(self), stream, context, path)
        stream.write(bytes(self))


class PrimitiveDouble(_PrimitiveBase, float):
    """IEEE-754 double primitive (wire type 9).  Use :data:`PDouble`."""

    _type_code = 9

    @classmethod
    def _read(cls, stream: io.RawIOBase, context: Any, path: str) -> PrimitiveDouble:
        return cls(Float64l._parse(stream, context, path))

    def _write(self, stream: io.RawIOBase, context: Any, path: str) -> None:
        Float64l._build(float(self), stream, context, path)


# Convenience short aliases
PNull = PrimitiveNull
PBuf = PrimitiveBuffer
PInt32 = PrimitiveInt32
PInt64 = PrimitiveInt64
PDouble = PrimitiveDouble
PStr = PrimitiveString

# Registry: wire type code → _PrimitiveBase subclass.
# All six primitive types are represented; the _build path uses this for dispatch.
_PRIMITIVE_REGISTRY: dict[int, type[_PrimitiveBase]] = {
    cls._type_code: cls
    for cls in (PrimitiveNull, PrimitiveBuffer, PrimitiveString, PrimitiveInt32, PrimitiveInt64, PrimitiveDouble)
}


# ---------------------------------------------------------------------------
# Construct helpers for the primitive dictionary
# ---------------------------------------------------------------------------


class _PrimitiveValueCon(Construct):
    """Construct for a single DTX primitive: u32 type tag followed by value bytes.

    Parse → :class:`PrimitiveInt32` | :class:`PrimitiveInt64` |
             :class:`PrimitiveDouble` | :class:`PrimitiveString` |
             :class:`PrimitiveBuffer` (raw bytes on NSKeyedArchive decode failure) |
             decoded Python object (NSKeyedArchive BUFFER, type 2) |
             ``None`` (NULL, type 10)

    Build ← :class:`_PrimitiveBase` instance (type inferred from class) |
             ``None`` → NULL (convenience; same wire result as ``PrimitiveNull()``) |
             any other Python object → NSKeyedArchive-encoded BUFFER (type 2)
    """

    def _parse(self, stream, context, path) -> Any:
        type_code = Int32ul._parse(stream, context, path)
        cls = _PRIMITIVE_REGISTRY.get(type_code)
        if cls is None:
            raise ConstructError(f"unknown primitive type code {type_code:#x}", path)
        return cls._read(stream, context, path)

    def _build(self, obj, stream, context, path):
        if isinstance(obj, _PrimitiveBase):
            Int32ul._build(type(obj)._type_code, stream, context, path)
            obj._write(stream, context, path)
        elif obj is None:
            # Convenience: plain None → NULL (same wire result as PrimitiveNull())
            Int32ul._build(PrimitiveNull._type_code, stream, context, path)
        else:
            # Any other Python value → NSKeyedArchive-encoded BUFFER (type 2)
            enc = archiver.archive(obj)
            Int32ul._build(PrimitiveBuffer._type_code, stream, context, path)
            Int32ul._build(len(enc), stream, context, path)
            stream.write(enc)
        return obj

    def _sizeof(self, context, path):
        raise SizeofError("variable-length primitive")


class PrimitiveDictionary(Construct):
    """Construct for the full DTX primitive dictionary wire format.

    Wire layout::

        u64  magic_and_flags   0xf0 | optional flag bits (e.g. 0x100, 0x200)
        u64  body_length       byte count of everything that follows
        [key_primitive, value_primitive] x N entries

    Keys are decoded/encoded with :class:`_PrimitiveValueCon` — they can be any
    primitive value (or ``None`` for an index/positional marker).

    Parse → list of ``(key, value)`` tuples

    Build ← list of ``(key, value)`` tuples (same as parsed form).
    """

    # Base magic nibble. Upper bits carry optional flags observed as 0x100, 0x200 …
    _MAGIC_BASE: ClassVar[int] = 0xF0
    _DEFAULT_MAGIC: ClassVar[int] = 0x1F0  # 0x100 | 0xF0 — seen most often

    _item: ClassVar[_PrimitiveValueCon] = _PrimitiveValueCon()

    def _parse(self, stream, context, path) -> list[tuple[Any, Any]]:
        magic = Int64ul._parse(stream, context, path)
        if (magic & 0xFF) != self._MAGIC_BASE:
            raise ConstructError(f"PrimitiveDictionary: unexpected magic {magic:#x}", path)
        body_len = Int64ul._parse(stream, context, path)
        body = io.BytesIO(stream.read(body_len))
        entries = []
        while body.tell() < body_len:
            key = self._item._parse(body, context, path)
            value = self._item._parse(body, context, path)
            entries.append((key, value))

        return entries

    def _build(self, obj, stream, context, path):
        buf = io.BytesIO()
        for key, value in obj:
            self._item._build(key, buf, context, path)
            self._item._build(value, buf, context, path)
        body = buf.getvalue()
        Int64ul._build(self._DEFAULT_MAGIC, stream, context, path)
        Int64ul._build(len(body), stream, context, path)
        stream.write(body)
        return obj

    def _sizeof(self, context, path):
        raise SizeofError("variable-length primitive dictionary")


# Module-level singleton used by _args_to_aux_bytes and parse_aux.
_primitive_dict = PrimitiveDictionary()


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def _args_to_aux_bytes(args: Sequence[Any]) -> bytes:
    """Serialise a positional argument list to a DTX primitive-dictionary bytestring.

    Returns an empty ``bytes`` when *args* is empty.  Each element is encoded
    by :class:`_PrimitiveValueCon`: :class:`_PrimitiveBase` instances use their
    own wire type; everything else is NSKeyedArchive-encoded as BUFFER (type 2).
    """
    if not args:
        return b""
    buf = io.BytesIO()
    _primitive_dict._build([(None, a) for a in args], buf, {}, "")
    return buf.getvalue()


def parse_aux(data: memoryview | bytes) -> list:
    """Parse a DTX primitive dictionary and return its values as a plain list.

    Each element is one of :class:`PrimitiveInt32`, :class:`PrimitiveInt64`,
    :class:`PrimitiveDouble`, :class:`PrimitiveString`, a decoded NSKeyedArchive
    object (BUFFER), or ``None`` (NULL).  The 16-byte dictionary header is consumed
    by :class:`PrimitiveDictionary`.
    """
    if not data:
        return []
    if len(data) < PRIMITIVE_DICTIONARY_HEADER_SIZE:
        return []
    try:
        d = _primitive_dict._parse(io.BytesIO(data), {}, "")
        return [value for _, value in d]
    except Exception:
        return []
