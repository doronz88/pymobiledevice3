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

Variable-length values are described by codecs, which compose like construct's::

    STRING = Aligned(4, Prefixed(U32_LE, CSTRING))  # u32 length, NUL-terminated UTF-8, padded to 4 bytes
    OBJECT = Switch(U32_LE, {1: STRING, 2: U64_LE})  # parses to (tag, value)

A codec is anything with ``read(reader)`` and ``build(value)``: the :class:`Codec` combinators, the scalars
(``U32_LE``, ...), ``Bytes(n)``, and record classes themselves. A record field annotated with a codec
(``name: Annotated[str, CSTRING]``) makes the record variable-length; such fields follow the fixed-size ones.
Formats with no declarative shape are read by hand with :class:`ByteReader`.
"""

import dataclasses
import enum
import ipaddress
import itertools
import operator
import struct
import sys
import uuid
from collections.abc import Mapping
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Generic,
    NoReturn,
    Optional,
    Protocol,
    TypeVar,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
)

from typing_extensions import Self

from pymobiledevice3.exceptions import (
    BinaryBuildError,
    BinaryDataError,
    BinaryParseError,
    TruncatedDataError,
    UnexpectedConstantError,
)

BytesLike = Union[bytes, bytearray, memoryview]


class ByteReader:
    """Sequential reader over the window ``data[offset:end]`` of an in-memory buffer; every ``read*``/``unpack*``
    returns exactly what was asked for or raises :class:`TruncatedDataError`.

    Readers made by :meth:`sub` share ``data`` (nothing is copied) and have a narrower ``end``. ``base`` is the
    absolute offset of ``data[0]`` in the outermost buffer, so errors report absolute offsets.
    """

    __slots__ = ("base", "data", "end", "offset")

    def __init__(self, data: BytesLike, offset: int = 0, base: int = 0) -> None:
        self.data = data if type(data) is bytes else bytes(data)
        self.base = base
        self.end = len(self.data)
        if not 0 <= offset <= self.end:  # offsets often come from the wire
            raise BinaryParseError(f"invalid offset {offset} in {self.end} bytes", offset=base)
        self.offset = offset

    @property
    def remaining(self) -> int:
        return self.end - self.offset

    @property
    def absolute(self) -> int:
        """The current position as an absolute offset in the outermost buffer."""
        return self.base + self.offset

    def _invalid_size(self, size: int) -> BinaryParseError:
        if size < 0:  # a length computed from wire data
            return BinaryParseError(f"invalid size {size}", offset=self.absolute)
        return TruncatedDataError(f"expected {size} bytes, found {self.remaining}", offset=self.absolute)

    def read(self, size: int) -> bytes:
        offset = self.offset
        if not 0 <= size <= self.end - offset:
            raise self._invalid_size(size)
        self.offset = offset + size
        return self.data[offset : offset + size]

    def skip(self, size: int) -> None:
        if not 0 <= size <= self.end - self.offset:
            raise self._invalid_size(size)
        self.offset += size

    def sub(self, size: int) -> "ByteReader":
        """Consume the next ``size`` bytes and return a reader confined to them."""
        start = self.offset
        self.skip(size)
        reader = ByteReader.__new__(ByteReader)
        reader.data, reader.base, reader.offset, reader.end = self.data, self.base, start, start + size
        return reader

    def read_all(self) -> bytes:
        return self.read(self.end - self.offset)

    def unpack(self, fmt: struct.Struct) -> tuple[Any, ...]:
        offset = self.offset
        if fmt.size > self.end - offset:
            raise self._invalid_size(fmt.size)
        self.offset = offset + fmt.size
        return fmt.unpack_from(self.data, offset)

    def unpack_one(self, fmt: struct.Struct) -> Any:
        offset = self.offset
        if fmt.size > self.end - offset:
            raise self._invalid_size(fmt.size)
        self.offset = offset + fmt.size
        return fmt.unpack_from(self.data, offset)[0]

    def read_cstring(self) -> bytes:
        """Read up to (and consume) a NUL terminator; the terminator is not returned."""
        end = self.data.find(b"\0", self.offset, self.end)
        if end == -1:
            raise TruncatedDataError("unterminated C string", offset=self.absolute)
        result = self.data[self.offset : end]
        self.offset = end + 1
        return result


T = TypeVar("T")


class Codec(Protocol[T]):
    """Parses one wire value from a :class:`ByteReader` (``read``) and encodes one (``build``).

    Anything with these two methods is a codec: the combinators below, the scalars (``U32_LE``, ...), ``Bytes(n)``,
    and :class:`BinaryStruct` record classes. Errors raised inside a nested value record the enclosing cases,
    elements and fields in :attr:`BinaryDataError.path`.
    """

    # Attributes rather than methods, so that a record class (whose ``build`` is an instance method, called as
    # ``Record.build(record)``) is a codec too.
    @property
    def read(self) -> Callable[[ByteReader], T]: ...

    @property
    def build(self) -> Callable[[T], bytes]: ...


class CodecBase(Generic[T]):
    """Base of the combinators: a codec with a ``parse`` shortcut."""

    def read(self, reader: ByteReader) -> T:
        raise NotImplementedError

    def build(self, value: T) -> bytes:
        raise NotImplementedError

    def parse(self, data: BytesLike) -> T:
        """Parse the value from the start of ``data``; trailing bytes are ignored."""
        return self.read(ByteReader(data))


class Scalar(struct.Struct):
    """A ``struct.Struct`` holding a single value, usable as a codec and with ``ByteReader.unpack_one``."""

    def read(self, reader: ByteReader) -> Any:
        return reader.unpack_one(self)

    def parse(self, data: BytesLike) -> Any:
        return self.read(ByteReader(data))

    def build(self, value: Any) -> bytes:
        try:
            return self.pack(value)
        except (struct.error, OverflowError) as e:
            raise BinaryBuildError(f"cannot encode {value!r}: {e}") from e


U8 = Scalar("B")
U16_BE = Scalar(">H")
U32_LE = Scalar("<I")
I32_LE = Scalar("<i")
U64_LE = Scalar("<Q")
I64_LE = Scalar("<q")
F64_LE = Scalar("<d")


class Pass(CodecBase[None]):
    """No bytes; parses to ``None``."""

    def read(self, reader: ByteReader) -> None:
        return None

    def build(self, value: None) -> bytes:
        return b""


class GreedyBytes(CodecBase[bytes]):
    """Every remaining byte (of the enclosing :class:`Prefixed`, or of the buffer)."""

    def read(self, reader: ByteReader) -> bytes:
        return reader.read_all()

    def build(self, value: BytesLike) -> bytes:
        return bytes(value)


class CString(CodecBase[str]):
    """A NUL-terminated UTF-8 string. Building one with an embedded NUL (the peer would stop there) is an error.

    ``errors`` is the UTF-8 decoding error handler (e.g. ``"replace"`` for names cut mid-character).
    """

    def __init__(self, errors: str = "strict") -> None:
        self.errors = errors

    def read(self, reader: ByteReader) -> str:
        start = reader.absolute
        raw = reader.read_cstring()
        try:
            return raw.decode("utf-8", self.errors)
        except UnicodeDecodeError as e:
            raise BinaryParseError(f"invalid UTF-8 in C string: {e}", offset=start) from e

    def build(self, value: str) -> bytes:
        if "\0" in value:
            raise BinaryBuildError(f"embedded NUL in {value!r}")
        try:
            return value.encode("utf-8") + b"\0"
        except UnicodeEncodeError as e:
            raise BinaryBuildError(f"cannot encode {value!r}: {e}") from e


PASS = Pass()
GREEDY_BYTES = GreedyBytes()
CSTRING = CString()


class Prefixed(CodecBase[T]):
    """``inner``, confined to the byte count that ``length`` precedes it with."""

    def __init__(self, length: Scalar, inner: Codec[T]) -> None:
        self.length = length
        self.inner = inner

    def read(self, reader: ByteReader) -> T:
        size = reader.unpack_one(self.length)
        end = reader.end
        stop = reader.offset + size
        if not reader.offset <= stop <= end:
            raise reader._invalid_size(size)
        reader.end = stop  # cheaper than a sub-reader
        try:
            return self.inner.read(reader)
        finally:
            reader.end = end
            reader.offset = stop

    def build(self, value: T) -> bytes:
        body = self.inner.build(value)
        try:
            return self.length.pack(len(body)) + body
        except struct.error as e:
            raise BinaryBuildError(f"cannot encode a length of {len(body)}: {e}") from e


class Aligned(CodecBase[T]):
    """``inner``, followed by NUL padding to a multiple of ``modulus`` bytes counted from where it starts."""

    def __init__(self, modulus: int, inner: Codec[T]) -> None:
        self.modulus = modulus
        self.inner = inner
        self._padding = [bytes(size) for size in range(modulus)]

    def read(self, reader: ByteReader) -> T:
        start = reader.offset
        value = self.inner.read(reader)
        reader.skip(-(reader.offset - start) % self.modulus)
        return value

    def build(self, value: T) -> bytes:
        data = self.inner.build(value)
        return data + self._padding[-len(data) % self.modulus]


class PrefixedArray(CodecBase[list[T]]):
    """An element count in ``count``, followed by that many ``element``s."""

    def __init__(self, count: Scalar, element: Codec[T]) -> None:
        self.count = count
        self.element = element

    def read(self, reader: ByteReader) -> list[T]:
        count = reader.unpack_one(self.count)
        read = self.element.read
        result: list[T] = []
        try:
            for _ in range(count):
                result.append(read(reader))
        except BinaryDataError as e:
            e.within(f"[{len(result)}]")
            raise
        return result

    def build(self, value: list[T]) -> bytes:
        build = self.element.build
        parts = [self.count.build(len(value))]
        for index, element in enumerate(value):
            try:
                parts.append(build(element))
            except BinaryDataError as e:
                e.within(f"[{index}]")
                raise
        return b"".join(parts)


class Tuple(CodecBase[tuple[Any, ...]]):
    """Consecutive values of different codecs, parsed into a tuple."""

    def __init__(self, *codecs: Codec[Any]) -> None:
        self.codecs = codecs

    def read(self, reader: ByteReader) -> tuple[Any, ...]:
        return tuple([codec.read(reader) for codec in self.codecs])

    def build(self, value: tuple[Any, ...]) -> bytes:
        codecs = self.codecs
        if len(value) != len(codecs):
            raise BinaryBuildError(f"expected {len(codecs)} values, got {len(value)}")
        if len(codecs) == 2:  # the common (key, value) pair, without a join
            return codecs[0].build(value[0]) + codecs[1].build(value[1])
        return b"".join([codec.build(item) for codec, item in zip(codecs, value)])


class Switch(CodecBase[tuple[Any, Any]]):
    """A ``tag``, followed by a value in the codec it selects from ``cases``; parses to ``(tag, value)``.

    A tag without a case uses ``default``, or is an error when there is none.
    """

    def __init__(self, tag: Scalar, cases: Mapping[Any, Codec[Any]], *, default: Optional[Codec[Any]] = None) -> None:
        self.tag = tag
        self.cases = dict(cases)
        self.default = default
        self._names = {key: getattr(key, "name", None) or _show(key) for key in self.cases}

    def read(self, reader: ByteReader) -> tuple[Any, Any]:
        start = reader.absolute
        tag = reader.unpack_one(self.tag)
        case = self.cases.get(tag, self.default)
        if case is None:
            raise BinaryParseError(f"unknown tag {_show(tag)}", offset=start)
        try:
            return tag, case.read(reader)
        except BinaryDataError as e:
            e.within(self._names.get(tag) or _show(tag))
            raise

    def build(self, value: tuple[Any, Any]) -> bytes:
        tag, item = value
        case = self.cases.get(tag, self.default)
        if case is None:
            raise BinaryBuildError(f"unknown tag {_show(tag)}")
        head = self.tag.build(tag)
        try:
            return head + case.build(item)
        except BinaryDataError as e:
            e.within(self._names.get(tag) or _show(tag))
            raise


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

    # As a codec, outside of fixed-size records.
    def read(self, reader: ByteReader) -> bytes:
        return reader.read(self.size)

    def build(self, value: BytesLike) -> bytes:
        return bytes(self.encode(value))


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
    index: int  # position among the fixed-size fields
    name: str
    fmt: Format
    struct: struct.Struct  # this field alone: its size, and for locating errors
    offset: int
    const: Any
    init: bool  # an ``__init__`` parameter


@dataclasses.dataclass(frozen=True)
class _CodecField:
    """A variable-length field, read and written by its codec after the fixed-size fields."""

    name: str
    codec: Codec[Any]


@dataclasses.dataclass(frozen=True)
class _Run:
    """Consecutive fields sharing one byte order, (un)packed by a single ``struct.Struct``."""

    struct: struct.Struct
    offset: int
    first: int  # index of the run's first field
    count: int


def _is_codec(item: Any) -> bool:
    return hasattr(item, "read") and hasattr(item, "build")


def _wire_format(hint: Any) -> tuple[Optional[Format], Any, Optional[Codec[Any]]]:
    """The fixed-size format, constant and codec of a field annotation (all absent for a field without a wire type).

    ``Annotated[u32, Const(1)]`` is flattened by Python; ``Annotated[SomeEnum, u16]`` nests the alias.
    """
    if get_origin(hint) is not Annotated:
        return None, _NO_CONST, None
    base, *metadata = get_args(hint)
    for item in list(metadata):
        if get_origin(item) is Annotated:
            metadata.extend(get_args(item)[1:])
    fmt = next((m for m in reversed(metadata) if isinstance(m, Format)), None)
    if fmt is not None and isinstance(base, type) and issubclass(base, enum.Enum):
        fmt = _EnumFormat(fmt, base)
    const = next((m.value for m in metadata if isinstance(m, Const)), _NO_CONST)
    codec = None if fmt is not None else next((m for m in metadata if _is_codec(m)), None)
    return fmt, const, codec


def _layout(cls: type, byte_order: str) -> tuple[list[_Field], list[_CodecField]]:
    # 3.10+ ``__annotations__`` is per class (lazily computed on 3.14); 3.9's falls back to a base class's.
    names = cls.__annotations__ if sys.version_info >= (3, 10) else cls.__dict__.get("__annotations__", {})
    hints = get_type_hints(cls, include_extras=True)  # keeps the Annotated metadata
    fields: list[_Field] = []
    codec_fields: list[_CodecField] = []
    offset = 0
    for name in names:
        fmt, const, codec = _wire_format(hints[name])
        if codec is not None:
            codec_fields.append(_CodecField(name, codec))
            continue
        if fmt is None:  # a trailing field without a wire type
            continue
        if codec_fields:
            raise TypeError(f"{cls.__name__}.{name}: fixed-size fields must precede the codec fields")
        field_struct = struct.Struct((fmt.byte_order or byte_order) + fmt.code)
        spec = cls.__dict__.get(name)
        init = not isinstance(spec, dataclasses.Field) or spec.init
        fields.append(_Field(len(fields), name, fmt, field_struct, offset, const, init))
        offset += field_struct.size
    return fields, codec_fields


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
    if not names:
        return lambda obj: ()
    if len(names) == 1:
        single = operator.attrgetter(names[0])
        return lambda obj: (single(obj),)
    return operator.attrgetter(*names)


def _show(value: Any) -> str:
    """Integers (magics, versions, tags) read best in hex."""
    return hex(value) if isinstance(value, int) and not isinstance(value, bool) else repr(value)


class BinaryStruct:
    """Base for dataclasses describing a binary record; see the module docstring.

    Record classes are codecs themselves (``read``/``build``), so they nest inside other records and combinators.
    """

    # Computed once per record class by ``__init_subclass__``.
    SIZE: ClassVar[int]  # of the fixed-size fields (all of a record without codec fields)
    _fields: ClassVar[tuple[_Field, ...]]  # in wire order
    _codec_fields: ClassVar[tuple[_CodecField, ...]]
    _runs: ClassVar[tuple[_Run, ...]]
    _consts: ClassVar[tuple[_Field, ...]]
    _const_getter: ClassVar[Callable[[Any], Any]]  # instance -> its constant fields' values
    _const_values: ClassVar[Any]  # what ``_const_getter`` must return
    _decoders: ClassVar[tuple[_Field, ...]]
    _encoders: ClassVar[tuple[_Field, ...]]  # non-constant fields whose format converts values before packing
    _getter: ClassVar[Callable[[Any], tuple[Any, ...]]]  # instance -> its fixed-size field values
    _init_indices: ClassVar[Optional[list[int]]]  # the fixed-size fields passed to ``__init__``, if not all of them
    _plain: ClassVar[bool]  # parse is a single unpack straight into ``__init__``
    _plain_build: ClassVar[bool]  # build is a single pack of the field values

    def __init_subclass__(cls, byte_order: str = "<", **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.__bases__ != (BinaryStruct,):
            raise TypeError(f"{cls.__name__}: records cannot be subclassed or mixed with other bases")
        fields, codec_fields = _layout(cls, byte_order)
        cls._fields = tuple(fields)
        cls._codec_fields = tuple(codec_fields)
        cls._runs = tuple(_runs(fields))
        cls._consts = tuple(f for f in fields if f.const is not _NO_CONST)
        cls._decoders = tuple(f for f in fields if _overrides(f.fmt, "decode"))
        # A constant was checked before packing, so it never needs encoding.
        cls._encoders = tuple(f for f in fields if _overrides(f.fmt, "encode") and f.const is _NO_CONST)
        cls.SIZE = sum(f.struct.size for f in fields)
        cls._getter = _tuple_getter([f.name for f in fields])  # pyright: ignore[reportAttributeAccessIssue]
        cls._init_indices = None if all(f.init for f in fields) else [f.index for f in fields if f.init]
        cls._plain = (
            len(cls._runs) == 1
            and not cls._consts
            and not cls._decoders
            and cls._init_indices is None
            and not cls._codec_fields
        )
        cls._plain_build = len(cls._runs) == 1 and not cls._consts and not cls._encoders
        if cls._consts:
            # ``attrgetter`` returns the bare value for one name and a tuple for several; compare likewise.
            cls._const_getter = operator.attrgetter(*(f.name for f in cls._consts))
            consts = [f.const for f in cls._consts]
            cls._const_values = consts[0] if len(consts) == 1 else tuple(consts)

    @classmethod
    def parse(cls, data: BytesLike) -> Self:
        """Parse the record from the start of ``data``; trailing bytes are ignored."""
        if cls._codec_fields:
            return cls.read(ByteReader(data))
        return cls._parse(data, 0, len(data), 0)

    @classmethod
    def read(cls, reader: ByteReader) -> Self:
        """Parse the record at the reader's offset and advance past it."""
        start = reader.offset
        if not cls._codec_fields:
            record = cls._parse(reader.data, start, reader.end, reader.base)
            reader.offset = start + cls.SIZE
            return record
        values = cls._unpack(reader.data, start, reader.end, reader.base)
        reader.offset = start + cls.SIZE
        for field in cls._codec_fields:
            try:
                values.append(field.codec.read(reader))
            except BinaryDataError as e:
                e.within(f"{cls.__name__}.{field.name}")
                raise
        return cls(*values)

    @classmethod
    def _parse(cls, data: BytesLike, start: int, end: int, base: int) -> Self:
        """Parse at ``data[start:end]``; ``base + start`` is that position's absolute offset (for errors)."""
        if cls._plain:
            if end - start < cls.SIZE:
                cls._raise_short(data, start, end, base)
            return cls(*cls._runs[0].struct.unpack_from(data, start))
        return cls(*cls._unpack(data, start, end, base))

    @classmethod
    def _unpack(cls, data: BytesLike, start: int, end: int, base: int) -> list[Any]:
        """The ``__init__`` arguments of the fixed-size fields at ``data[start:end]``."""
        if end - start < cls.SIZE:
            cls._raise_short(data, start, end, base)
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
            return [values[i] for i in cls._init_indices]
        return values

    @classmethod
    def _raise_short(cls, data: BytesLike, start: int, end: int, base: int) -> NoReturn:
        """A wrong constant that is already readable wins (``b"HTTP/1.1..."`` is not a short XPC frame, it is not
        an XPC frame at all); otherwise the error names the first field that does not fit."""
        available = end - start
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
        """Encode the record (as a codec, ``Record.build(record)``)."""
        if not self._codec_fields:
            return self._build_fixed()
        parts = [self._build_fixed()]
        for field in self._codec_fields:
            try:
                parts.append(field.codec.build(getattr(self, field.name)))
            except BinaryDataError as e:
                e.within(f"{type(self).__name__}.{field.name}")
                raise
        return b"".join(parts)

    def _build_fixed(self) -> bytes:
        cls = type(self)
        if cls._plain_build:
            try:
                return cls._runs[0].struct.pack(*cls._getter(self))
            except (struct.error, OverflowError) as e:
                raise BinaryBuildError(f"cannot encode: {e}", record=cls.__name__) from e
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
    "CSTRING",
    "F64_LE",
    "GREEDY_BYTES",
    "I32_LE",
    "I64_LE",
    "PASS",
    "U8",
    "U16_BE",
    "U32_LE",
    "U64_LE",
    "Aligned",
    "Array",
    "BinaryStruct",
    "ByteReader",
    "Bytes",
    "BytesLike",
    "CString",
    "Codec",
    "CodecBase",
    "Const",
    "GreedyBytes",
    "OpenIntEnum",
    "PaddedString",
    "Pass",
    "Prefixed",
    "PrefixedArray",
    "Scalar",
    "Switch",
    "Tuple",
    "i16",
    "i32",
    "i64",
    "ipv4",
    "ipv6",
    "u8",
    "u16",
    "u32",
    "u32be",
    "u32le",
    "u64",
    "uuid_t",
]
