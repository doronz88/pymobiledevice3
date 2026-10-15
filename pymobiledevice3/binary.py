"""Small stdlib helpers for parsing binary wire structures.

Fixed-size records are declared as dataclasses deriving from :class:`BinaryStruct`, with each field's wire
type given by its annotation::

    @dataclass
    class Header(BinaryStruct, byte_order="<"):
        magic: Annotated[u32, Const(0x1F3D5B79)] = field(default=0x1F3D5B79, init=False)
        size: u32
        name: Annotated[str, PaddedString(16)]
        kind: Annotated[SomeIntEnum, u16]  # parsed into the enum type

    header = Header.parse(data)  # short input -> TruncatedDataError, wrong magic -> UnexpectedConstantError
    data = header.build()  # an unencodable value or a wrong constant -> BinaryBuildError

The layout is compiled into ``struct.Struct`` objects once, when the class is defined, so a parse is one
``unpack_from`` per byte-order run. Wire fields are positional ``__init__`` parameters in wire order; a field
declared ``= field(default=..., init=False)`` is left out of ``__init__``: parse skips its bytes (padding) and
build packs its default (on a ``Const`` field, the constant). Fields without a wire type may follow the wire
fields and are ignored by parse/build. Records cannot be subclassed.

Variable-length data is read with :class:`ByteReader` and built by concatenating ``build()`` output with
:func:`encode_utf8_cstring` and :func:`pad_to`.
"""

import dataclasses
import enum
import ipaddress
import itertools
import operator
import struct
import sys
import uuid
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    NoReturn,
    Optional,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
)

from pymobiledevice3.exceptions import (
    BinaryBuildError,
    BinaryDataError,
    BinaryParseError,
    TruncatedDataError,
    UnexpectedConstantError,
)

BytesLike = Union[bytes, bytearray, memoryview]

# Little-endian scalars, for ``ByteReader.unpack_one`` and hand-built framing.
U32_LE = struct.Struct("<I")
I32_LE = struct.Struct("<i")
U64_LE = struct.Struct("<Q")
I64_LE = struct.Struct("<q")
F64_LE = struct.Struct("<d")


class ByteReader:
    """Sequential reader over an in-memory buffer; every ``read*``/``unpack*`` returns exactly what was asked for
    or raises :class:`TruncatedDataError`.

    ``base`` is the absolute offset of ``data[0]`` in the outermost buffer, so errors from nested readers
    (see :meth:`sub`) report absolute offsets.
    """

    def __init__(self, data: BytesLike, offset: int = 0, base: int = 0) -> None:
        self.data = bytes(data)
        self.base = base
        if not 0 <= offset <= len(self.data):  # offsets often come from the wire
            raise BinaryParseError(f"invalid offset {offset} in {len(self.data)} bytes", offset=base)
        self.offset = offset

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    @property
    def absolute(self) -> int:
        """The current position as an absolute offset in the outermost buffer."""
        return self.base + self.offset

    def read(self, size: int) -> bytes:
        if size < 0:  # a length computed from wire data
            raise BinaryParseError(f"invalid size {size}", offset=self.absolute)
        if size > self.remaining:
            raise TruncatedDataError(f"expected {size} bytes, found {self.remaining}", offset=self.absolute)
        result = self.data[self.offset : self.offset + size]
        self.offset += size
        return result

    def sub(self, size: int) -> "ByteReader":
        """Consume the next ``size`` bytes and return a reader over just them (keeping absolute offsets)."""
        start = self.absolute
        return ByteReader(self.read(size), base=start)

    def prefixed(self, fmt: struct.Struct) -> "ByteReader":
        """Read a length in ``fmt`` and return a reader over that many following bytes (construct's ``Prefixed``)."""
        return self.sub(self.unpack_one(fmt))

    def read_all(self) -> bytes:
        return self.read(self.remaining)

    def unpack(self, fmt: struct.Struct) -> tuple[Any, ...]:
        return fmt.unpack(self.read(fmt.size))

    def unpack_one(self, fmt: struct.Struct) -> Any:
        return fmt.unpack(self.read(fmt.size))[0]

    def read_cstring(self) -> bytes:
        """Read up to (and consume) a NUL terminator; the terminator is not returned."""
        end = self.data.find(b"\0", self.offset)
        if end == -1:
            raise TruncatedDataError("unterminated C string", offset=self.absolute)
        result = self.data[self.offset : end]
        self.offset = end + 1
        return result

    def read_utf8_cstring(self) -> str:
        start = self.absolute
        raw = self.read_cstring()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise BinaryParseError(f"invalid UTF-8 in C string: {e}", offset=start) from e


class OpenIntEnum(enum.IntEnum):
    """``IntEnum`` that maps unknown values to cached pseudo-members instead of raising, so a value from a newer
    peer (an unknown opcode, status, level, ...) still parses. Declare at least one member."""

    @classmethod
    def _missing_(cls, value: object) -> Optional["OpenIntEnum"]:
        if not isinstance(value, int):
            return None
        member = int.__new__(cls, value)
        member._name_ = str(value)
        member._value_ = value
        # Registered so the next ``cls(value)`` returns the same object.
        return cast(OpenIntEnum, cls._value2member_map_.setdefault(value, member))


def encode_utf8_cstring(value: str) -> bytes:
    """Encode ``value`` as a NUL-terminated UTF-8 string; an embedded NUL (the peer would stop there) is rejected."""
    if "\0" in value:
        raise BinaryBuildError(f"embedded NUL in {value!r}")
    try:
        return value.encode("utf-8") + b"\0"
    except UnicodeEncodeError as e:
        raise BinaryBuildError(f"cannot encode {value!r}: {e}") from e


def pad_to(data: bytes, alignment: int) -> bytes:
    """Append NUL bytes so ``len(data)`` is a multiple of ``alignment``."""
    return data + b"\0" * (-len(data) % alignment)


class Format:
    """Field annotation metadata: a single-value ``struct`` code, optionally pinned to a byte order.

    Subclasses override ``decode`` (unpacked value -> field value, raising :class:`BinaryParseError`) and/or
    ``encode`` (the reverse, raising :class:`BinaryBuildError`); only overridden ones are called.
    """

    def __init__(self, code: str, byte_order: Optional[str] = None) -> None:
        self.code = code
        self.byte_order = byte_order

    def decode(self, value: Any) -> Any:
        return value

    def encode(self, value: Any) -> Any:
        return value


class Bytes(Format):
    """A fixed-size raw byte field; building it from a value of any other length is an error."""

    def __init__(self, size: int) -> None:
        super().__init__(f"{size}s")
        self.size = size

    def encode(self, value: Any) -> Any:
        if len(value) != self.size:
            raise BinaryBuildError(f"expected {self.size} bytes, got {len(value)}")
        return value


class PaddedString(Format):
    """A fixed-size field holding a NUL-terminated UTF-8 string followed by arbitrary bytes (parse only).

    ``errors`` is the UTF-8 decoding error handler (e.g. ``"replace"`` for names cut mid-character).
    """

    def __init__(self, size: int, errors: str = "strict") -> None:
        super().__init__(f"{size}s")
        self.size = size
        self.errors = errors

    def decode(self, value: Any) -> str:
        end = value.find(b"\0")
        if end == -1:
            raise BinaryParseError(f"C string not terminated within its {self.size}-byte field")
        try:
            return value[:end].decode("utf-8", self.errors)
        except UnicodeDecodeError as e:
            raise BinaryParseError(f"invalid UTF-8 in C string field: {e}") from e


class Uuid(Format):
    """A 16-byte UUID field, parsed into a :class:`uuid.UUID` (parse only)."""

    def __init__(self) -> None:
        super().__init__("16s")

    def decode(self, value: Any) -> uuid.UUID:
        return uuid.UUID(bytes=value)


class IPAddress(Format):
    """A packed IPv4 (4-byte) or IPv6 (16-byte) address field, parsed into an :mod:`ipaddress` object."""

    def __init__(self, version: int) -> None:
        self.address_type = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        super().__init__("4s" if version == 4 else "16s")

    def decode(self, value: Any) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        return self.address_type(value)

    def encode(self, value: Any) -> bytes:
        return value.packed


class Array(Format):
    """A fixed-length array of a plain number type, parsed into a list (parse only):
    ``Annotated[list[int], Array(u64, 6)]``. Elements are little-endian unless their alias pins a byte order."""

    def __init__(self, element: Any, count: int) -> None:
        fmt: Format = get_args(element)[1]
        self.count = count
        self.struct = struct.Struct(f"{fmt.byte_order or '<'}{count}{fmt.code}")
        super().__init__(f"{self.struct.size}s")

    def decode(self, value: Any) -> list[Any]:
        return list(self.struct.unpack(value))


class Const:
    """Field annotation metadata: the field must always hold ``value``.

    A wrong value raises :class:`UnexpectedConstantError` on parse and :class:`BinaryBuildError` on build. Only for
    fields whose value is not converted (numbers, ``Bytes``, int enums): parse compares the raw unpacked value.
    """

    def __init__(self, value: Any) -> None:
        self.value = value


# Field types: ``Annotated[<what type checkers see>, <wire format>]``. The byte order comes from the record unless
# the alias pins one.
u8 = Annotated[int, Format("B")]
u16 = Annotated[int, Format("H")]
u32 = Annotated[int, Format("I")]
u64 = Annotated[int, Format("Q")]
i16 = Annotated[int, Format("h")]
i32 = Annotated[int, Format("i")]
i64 = Annotated[int, Format("q")]
u32le = Annotated[int, Format("I", "<")]
u32be = Annotated[int, Format("I", ">")]
uuid_t = Annotated[uuid.UUID, Uuid()]
ipv4 = Annotated[ipaddress.IPv4Address, IPAddress(4)]
ipv6 = Annotated[ipaddress.IPv6Address, IPAddress(6)]

T = TypeVar("T", bound="BinaryStruct")


class _EnumFormat(Format):
    """Converts a parsed integer to the field's int-valued enum (``Annotated[SomeEnum, u32]``)."""

    def __init__(self, base: Format, enum_type: type[enum.Enum]) -> None:
        super().__init__(base.code, base.byte_order)
        self.enum_type = enum_type

    def decode(self, value: Any) -> Any:
        try:
            return self.enum_type(value)
        except ValueError as e:
            raise BinaryParseError(str(e)) from e


_NO_CONST = object()  # sentinel: None (or 0) can be a legitimate constant


@dataclasses.dataclass(frozen=True)
class _Field:
    index: int  # position among the wire fields
    name: str
    fmt: Format
    struct: struct.Struct  # this field alone: its size, and for locating errors
    offset: int
    const: Any
    init: bool  # an ``__init__`` parameter


@dataclasses.dataclass(frozen=True)
class _Run:
    """Consecutive fields sharing one byte order, (un)packed by a single ``struct.Struct``."""

    struct: struct.Struct
    offset: int
    first: int  # index of the run's first field
    count: int


def _wire_format(hint: Any) -> tuple[Optional[Format], Any]:
    """The wire format and constant of a field annotation (``None`` if it has no wire type).

    ``Annotated[u32, Const(1)]`` is flattened by Python; ``Annotated[SomeEnum, u16]`` nests the alias.
    """
    if get_origin(hint) is not Annotated:
        return None, _NO_CONST
    base, *metadata = get_args(hint)
    for item in list(metadata):
        if get_origin(item) is Annotated:
            metadata.extend(get_args(item)[1:])
    fmt = next((m for m in reversed(metadata) if isinstance(m, Format)), None)
    if fmt is not None and isinstance(base, type) and issubclass(base, enum.Enum):
        fmt = _EnumFormat(fmt, base)
    const = next((m.value for m in metadata if isinstance(m, Const)), _NO_CONST)
    return fmt, const


def _layout(cls: type, byte_order: str) -> list[_Field]:
    # 3.10+ ``__annotations__`` is per class (lazily computed on 3.14); 3.9's falls back to a base class's.
    names = cls.__annotations__ if sys.version_info >= (3, 10) else cls.__dict__.get("__annotations__", {})
    hints = get_type_hints(cls, include_extras=True)  # keeps the Annotated metadata
    fields: list[_Field] = []
    offset = 0
    for name in names:
        fmt, const = _wire_format(hints[name])
        if fmt is None:  # a trailing field without a wire type
            continue
        field_struct = struct.Struct((fmt.byte_order or byte_order) + fmt.code)
        spec = cls.__dict__.get(name)
        init = not isinstance(spec, dataclasses.Field) or spec.init
        fields.append(_Field(len(fields), name, fmt, field_struct, offset, const, init))
        offset += field_struct.size
    return fields


def _runs(fields: list[_Field]) -> list[_Run]:
    """Group consecutive same-byte-order fields into one ``struct.Struct`` each (usually one per record)."""
    runs: list[_Run] = []
    for order, group in itertools.groupby(fields, key=lambda f: f.struct.format[0]):
        members = list(group)
        fmt = struct.Struct(order + "".join(f.struct.format[1:] for f in members))
        runs.append(_Run(fmt, members[0].offset, members[0].index, len(members)))
    return runs


def _overrides(fmt: Format, method: str) -> bool:
    return getattr(type(fmt), method) is not getattr(Format, method)


def _tuple_getter(names: list[str]) -> Callable[[Any], tuple[Any, ...]]:
    """``operator.attrgetter`` that always returns a tuple (with one name it returns the bare value)."""
    if len(names) == 1:
        single = operator.attrgetter(names[0])
        return lambda obj: (single(obj),)
    return operator.attrgetter(*names)


def _show(value: Any) -> str:
    """Integers (magics, versions) read best in hex."""
    return hex(value) if isinstance(value, int) and not isinstance(value, bool) else repr(value)


class BinaryStruct:
    """Base for dataclasses describing a fixed-size binary record; see the module docstring."""

    # Computed once per record class by ``__init_subclass__``.
    SIZE: ClassVar[int]
    _fields: ClassVar[tuple[_Field, ...]]  # in wire order
    _runs: ClassVar[tuple[_Run, ...]]
    _consts: ClassVar[tuple[_Field, ...]]
    _const_getter: ClassVar[Callable[[Any], Any]]  # instance -> its constant fields' values
    _const_values: ClassVar[Any]  # what ``_const_getter`` must return
    _decoders: ClassVar[tuple[_Field, ...]]
    _encoders: ClassVar[tuple[_Field, ...]]  # non-constant fields whose format converts values before packing
    _getter: ClassVar[Callable[[Any], tuple[Any, ...]]]  # instance -> its wire field values
    _init_indices: ClassVar[Optional[list[int]]]  # the wire fields passed to ``__init__``, if not all of them
    _plain: ClassVar[bool]  # parse is a single unpack straight into ``__init__``

    def __init_subclass__(cls, byte_order: str = "<", **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.__bases__ != (BinaryStruct,):
            raise TypeError(f"{cls.__name__}: records cannot be subclassed or mixed with other bases")
        fields = _layout(cls, byte_order)
        cls._fields = tuple(fields)
        cls._runs = tuple(_runs(fields))
        cls._consts = tuple(f for f in fields if f.const is not _NO_CONST)
        cls._decoders = tuple(f for f in fields if _overrides(f.fmt, "decode"))
        # A constant was checked before packing, so it never needs encoding.
        cls._encoders = tuple(f for f in fields if _overrides(f.fmt, "encode") and f.const is _NO_CONST)
        cls.SIZE = sum(f.struct.size for f in fields)
        cls._getter = _tuple_getter([f.name for f in fields])  # pyright: ignore[reportAttributeAccessIssue]
        cls._init_indices = None if all(f.init for f in fields) else [f.index for f in fields if f.init]
        cls._plain = len(cls._runs) == 1 and not cls._consts and not cls._decoders and cls._init_indices is None
        if cls._consts:
            # ``attrgetter`` returns the bare value for one name and a tuple for several; compare likewise.
            cls._const_getter = operator.attrgetter(*(f.name for f in cls._consts))
            consts = [f.const for f in cls._consts]
            cls._const_values = consts[0] if len(consts) == 1 else tuple(consts)

    @classmethod
    def parse(cls: type[T], data: BytesLike) -> T:
        """Parse the record from the start of ``data``; trailing bytes are ignored."""
        return cls._parse(data, 0, 0)

    @classmethod
    def read(cls: type[T], reader: ByteReader) -> T:
        """Parse the record at the reader's offset and advance past it."""
        record = cls._parse(reader.data, reader.offset, reader.base)
        reader.offset += cls.SIZE
        return record

    @classmethod
    def _parse(cls: type[T], data: BytesLike, start: int, base: int) -> T:
        """Parse at ``data[start:]``; ``base + start`` is that position's absolute offset (for errors)."""
        if len(data) - start < cls.SIZE:
            cls._raise_short(data, start, base)
        if cls._plain:
            return cls(*cls._runs[0].struct.unpack_from(data, start))
        values: list[Any] = []
        for run in cls._runs:
            values.extend(run.struct.unpack_from(data, start + run.offset))
        # Constants first, so a wrong magic is reported as such.
        for field in cls._consts:
            if values[field.index] != field.const:
                raise cls._const_error(field, values[field.index], base + start)
        for field in cls._decoders:
            try:
                values[field.index] = field.fmt.decode(values[field.index])
            except BinaryParseError as e:
                raise e.located(record=cls.__name__, field=field.name, offset=base + start + field.offset) from e
        if cls._init_indices is not None:
            return cls(*[values[i] for i in cls._init_indices])
        return cls(*values)

    @classmethod
    def _raise_short(cls, data: BytesLike, start: int, base: int) -> NoReturn:
        """A wrong constant that is already readable wins (``b"HTTP/1.1..."`` is not a short XPC frame, it is not
        an XPC frame at all); otherwise the error names the first field that does not fit."""
        available = len(data) - start
        for field in cls._consts:
            if field.offset + field.struct.size <= available:
                actual = field.struct.unpack_from(data, start + field.offset)[0]
                if actual != field.const:
                    raise cls._const_error(field, actual, base + start)
        field = next(f for f in cls._fields if f.offset + f.struct.size > available)
        raise TruncatedDataError(
            f"expected {field.struct.size} bytes, found {max(available - field.offset, 0)}",
            record=cls.__name__,
            field=field.name,
            offset=base + start + field.offset,
        )

    @classmethod
    def _const_error(cls, field: _Field, actual: Any, record_offset: int) -> UnexpectedConstantError:
        return UnexpectedConstantError(
            f"expected {_show(field.const)}, got {_show(actual)}",
            record=cls.__name__,
            field=field.name,
            offset=record_offset + field.offset,
        )

    def build(self) -> bytes:
        cls = type(self)
        if cls._consts and cls._const_getter(self) != cls._const_values:
            field = next(f for f in cls._consts if getattr(self, f.name) != f.const)
            raise BinaryBuildError(
                f"expected {_show(field.const)}, got {_show(getattr(self, field.name))}",
                record=cls.__name__,
                field=field.name,
            )
        values = cls._getter(self)
        if cls._encoders:
            values = list(values)
            for field in cls._encoders:
                try:
                    values[field.index] = field.fmt.encode(values[field.index])
                except BinaryDataError as e:
                    raise e.located(record=cls.__name__, field=field.name) from e
        try:
            if len(cls._runs) == 1:
                return cls._runs[0].struct.pack(*values)
            return b"".join([run.struct.pack(*values[run.first : run.first + run.count]) for run in cls._runs])
        except (struct.error, OverflowError) as e:
            raise BinaryBuildError(f"cannot encode: {e}", record=cls.__name__) from e


__all__ = [
    "F64_LE",
    "I32_LE",
    "I64_LE",
    "U32_LE",
    "U64_LE",
    "Array",
    "BinaryStruct",
    "ByteReader",
    "Bytes",
    "BytesLike",
    "Const",
    "OpenIntEnum",
    "PaddedString",
    "encode_utf8_cstring",
    "i16",
    "i32",
    "i64",
    "ipv4",
    "ipv6",
    "pad_to",
    "u8",
    "u16",
    "u32",
    "u32be",
    "u32le",
    "u64",
    "uuid_t",
]
