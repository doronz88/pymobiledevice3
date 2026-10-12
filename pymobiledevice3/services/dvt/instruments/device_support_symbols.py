"""
Symbol lookup against an Xcode ``DeviceSupport`` ``Symbols`` tree.

The tree holds the device's dyld shared cache split back into one Mach-O per image (see
``pymobiledevice3 developer fetch-symbols download``). Every image keeps the unslid address it has
inside the cache, so an address is resolved by finding the image whose ``__TEXT`` contains it and
then the nearest preceding entry of that image's symbol table.
"""

import bisect
import hashlib
import json
import logging
import os
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Optional

from ipsw_parser.dsc import get_device_support_path

from pymobiledevice3.common import get_home_folder
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider

logger = logging.getLogger(__name__)

INDEX_VERSION = 1
INDEX_DIRNAME = "device_support_index"

MH_MAGIC_64 = 0xFEEDFACF
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_FUNCTION_STARTS = 0x26
LC_FILESET_ENTRY = 0x80000035

N_STAB = 0xE0
N_TYPE = 0x0E
N_SECT = 0x0E

MACH_HEADER_64 = struct.Struct("<8I")
LOAD_COMMAND = struct.Struct("<2I")
SEGMENT_COMMAND_64 = struct.Struct("<16s4Q")
SYMTAB_COMMAND = struct.Struct("<4I")
LINKEDIT_DATA_COMMAND = struct.Struct("<2I")
FILESET_ENTRY_COMMAND = struct.Struct("<2QI")
NLIST_64 = struct.Struct("<IBBHQ")

# Longest symbol name read from the string table; Swift manglings go well past the usual C lengths
MAX_SYMBOL_LENGTH = 4096


@dataclass(frozen=True)
class SymbolImage:
    """A Mach-O of the symbols tree. `path` is its on-device path."""

    path: str
    uuid: str
    vmaddr: int
    vmsize: int

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass
class MachO:
    """The load commands of a Mach-O which symbolication needs."""

    uuid: Optional[str] = None
    # `__TEXT`
    vmaddr: Optional[int] = None
    vmsize: int = 0
    text_exec_vmaddr: Optional[int] = None
    symoff: int = 0
    nsyms: int = 0
    stroff: int = 0
    function_starts_offset: int = 0
    function_starts_size: int = 0
    # Name and file offset of the Mach-O files a fileset (a kernelcache) holds
    fileset_entries: list[tuple[str, int]] = field(default_factory=list[tuple[str, int]])


def parse_macho(fd: BinaryIO, offset: int = 0) -> Optional[MachO]:
    """
    Parse the load commands of a thin 64-bit little-endian Mach-O, or `None` for anything else.

    :param offset: Where the Mach-O starts in the file, for one held by a fileset.
    """
    fd.seek(offset)
    header = fd.read(MACH_HEADER_64.size)
    if len(header) < MACH_HEADER_64.size:
        return None
    magic, _cputype, _cpusubtype, _filetype, ncmds, sizeofcmds, _flags, _reserved = MACH_HEADER_64.unpack(header)
    if magic != MH_MAGIC_64:
        return None
    commands = fd.read(sizeofcmds)
    macho = MachO()
    offset = 0
    for _ in range(ncmds):
        if offset + LOAD_COMMAND.size > len(commands):
            return None
        cmd, cmdsize = LOAD_COMMAND.unpack_from(commands, offset)
        if cmdsize < LOAD_COMMAND.size:
            return None
        body = offset + LOAD_COMMAND.size
        if cmd == LC_SEGMENT_64:
            segname, vmaddr, vmsize, _fileoff, _filesize = SEGMENT_COMMAND_64.unpack_from(commands, body)
            if segname.rstrip(b"\x00") == b"__TEXT":
                macho.vmaddr = vmaddr
                macho.vmsize = vmsize
            elif segname.rstrip(b"\x00") == b"__TEXT_EXEC":
                macho.text_exec_vmaddr = vmaddr
        elif cmd == LC_UUID:
            macho.uuid = str(uuid.UUID(bytes=commands[body : body + 16]))
        elif cmd == LC_SYMTAB:
            macho.symoff, macho.nsyms, macho.stroff, _strsize = SYMTAB_COMMAND.unpack_from(commands, body)
        elif cmd == LC_FUNCTION_STARTS:
            macho.function_starts_offset, macho.function_starts_size = LINKEDIT_DATA_COMMAND.unpack_from(commands, body)
        elif cmd == LC_FILESET_ENTRY:
            _vmaddr, fileoff, entry_id_offset = FILESET_ENTRY_COMMAND.unpack_from(commands, body)
            entry_id = commands[offset + entry_id_offset : offset + cmdsize].split(b"\x00", 1)[0]
            macho.fileset_entries.append((entry_id.decode(errors="replace"), fileoff))
        offset += cmdsize
    return macho


def read_symbols(fd: BinaryIO, macho: MachO, start: int, end: int) -> list[tuple[int, int]]:
    """Get the address and string table offset of every symbol of `macho` within [start, end), sorted."""
    fd.seek(macho.symoff)
    data = fd.read(macho.nsyms * NLIST_64.size)
    data = data[: len(data) - len(data) % NLIST_64.size]
    return sorted(
        (n_value, n_strx)
        for n_strx, n_type, _n_sect, _n_desc, n_value in NLIST_64.iter_unpack(data)
        if not n_type & N_STAB and n_type & N_TYPE == N_SECT and start <= n_value < end
    )


def read_symbol_name(fd: BinaryIO, offset: int) -> str:
    """Read the symbol name at the given file offset of a string table."""
    fd.seek(offset)
    name = fd.read(MAX_SYMBOL_LENGTH).split(b"\x00", 1)[0].decode(errors="replace")
    # C symbols carry a leading underscore in the symbol table
    return name[1:] if name.startswith("_") else name


def parse_function_starts(data: bytes, base: int) -> list[int]:
    """Decode `LC_FUNCTION_STARTS`: ULEB128 deltas between consecutive functions, starting at `__TEXT`."""
    starts: list[int] = []
    address = base
    delta = 0
    shift = 0
    for byte in data:
        delta |= (byte & 0x7F) << shift
        if byte & 0x80:
            shift += 7
            continue
        if delta == 0:
            break
        address += delta
        starts.append(address)
        delta = 0
        shift = 0
    return starts


@dataclass
class _SymbolTable:
    addresses: list[int] = field(default_factory=list[int])
    string_offsets: list[int] = field(default_factory=list[int])
    stroff: int = 0
    function_starts: list[int] = field(default_factory=list[int])


def _scan(root: Path) -> list[SymbolImage]:
    images: list[SymbolImage] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in filenames:
            file = Path(dirpath) / filename
            try:
                with open(file, "rb") as fd:
                    macho = parse_macho(fd)
            except (OSError, struct.error):
                continue
            if macho is None or macho.uuid is None or macho.vmaddr is None:
                continue
            images.append(
                SymbolImage(
                    path="/" + file.relative_to(root).as_posix(),
                    uuid=macho.uuid,
                    vmaddr=macho.vmaddr,
                    vmsize=macho.vmsize,
                )
            )
    return images


def fingerprint(root: Path) -> list[int]:
    """
    Get a value which changes whenever a file is added to or removed from the tree.

    That is what touches the modification time of a directory, so no file has to be looked at.
    """
    count = 0
    latest = 0
    for dirpath, _dirnames, _filenames in os.walk(root):
        count += 1
        latest = max(latest, os.stat(dirpath).st_mtime_ns)
    return [count, latest]


class DeviceSupportSymbols:
    """Resolves addresses to symbols using the Mach-O files below `root`."""

    def __init__(self, root: Path, images: list[SymbolImage]) -> None:
        self.root = root
        self.images = sorted(images, key=lambda image: image.vmaddr)
        self._starts = [image.vmaddr for image in self.images]
        self._by_uuid = {image.uuid: image for image in self.images}
        self._symtabs: dict[str, _SymbolTable] = {}
        self._names: dict[tuple[str, int], str] = {}

    @classmethod
    def load(cls, root: Path, index_dir: Optional[Path] = None) -> "DeviceSupportSymbols":
        """
        Index the images below `root`.

        Reading the headers of a whole tree takes a while, so the index is kept in `index_dir`
        (the pymobiledevice3 home folder by default) and reused for as long as no file is added to
        or removed from the tree.
        """
        root = root.resolve()
        if index_dir is None:
            index_dir = get_home_folder() / INDEX_DIRNAME
        index_file = index_dir / f"{hashlib.sha256(str(root).encode()).hexdigest()[:16]}.json"
        tree_fingerprint = fingerprint(root)
        try:
            index = json.loads(index_file.read_text())
            if (
                index["version"] == INDEX_VERSION
                and index["root"] == str(root)
                and index["fingerprint"] == tree_fingerprint
            ):
                return cls(root, [SymbolImage(*image) for image in index["images"]])
        except (OSError, ValueError, KeyError, TypeError):
            pass

        logger.info(f"Indexing symbols of {root}")
        images = _scan(root)
        try:
            index_dir.mkdir(parents=True, exist_ok=True)
            index_file.write_text(
                json.dumps({
                    "version": INDEX_VERSION,
                    "root": str(root),
                    "fingerprint": tree_fingerprint,
                    "images": [[image.path, image.uuid, image.vmaddr, image.vmsize] for image in images],
                })
            )
        except OSError as e:
            logger.debug(f"Could not store the symbols index at {index_file}: {e}")
        return cls(root, images)

    @property
    def has_shared_cache_images(self) -> bool:
        """Whether the tree holds images split out of the shared cache, which is where they get an address."""
        return any(image.vmaddr for image in self.images)

    def image_by_uuid(self, image_uuid: str) -> Optional[SymbolImage]:
        return self._by_uuid.get(image_uuid.lower())

    def image_by_address(self, address: int) -> Optional[SymbolImage]:
        """Get the image whose `__TEXT` contains the given unslid address."""
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return None
        image = self.images[index]
        return image if address < image.vmaddr + image.vmsize else None

    def _symtab(self, image: SymbolImage) -> _SymbolTable:
        symtab = self._symtabs.get(image.path)
        if symtab is not None:
            return symtab
        symtab = _SymbolTable()
        try:
            with open(self.root / image.path.lstrip("/"), "rb") as fd:
                macho = parse_macho(fd)
                if macho is not None and macho.nsyms:
                    symbols = read_symbols(fd, macho, image.vmaddr, image.vmaddr + image.vmsize)
                    symtab.addresses = [address for address, _ in symbols]
                    symtab.string_offsets = [strx for _, strx in symbols]
                    symtab.stroff = macho.stroff
                if macho is not None and macho.function_starts_size:
                    fd.seek(macho.function_starts_offset)
                    symtab.function_starts = parse_function_starts(fd.read(macho.function_starts_size), image.vmaddr)
        except (OSError, struct.error) as e:
            logger.debug(f"Could not read the symbols of {image.path}: {e}")
        self._symtabs[image.path] = symtab
        return symtab

    def _symbol_name(self, image: SymbolImage, offset: int) -> str:
        key = (image.path, offset)
        name = self._names.get(key)
        if name is None:
            with open(self.root / image.path.lstrip("/"), "rb") as fd:
                name = read_symbol_name(fd, offset)
            self._names[key] = name
        return name

    def symbolicate(self, image: SymbolImage, address: int) -> Optional[tuple[str, int]]:
        """
        Get the symbol preceding the given unslid address of `image`.

        :returns: The symbol name and the offset of `address` from it, or `None` when the symbol
            table does not name the function the address is in.
        """
        symtab = self._symtab(image)
        index = bisect.bisect_right(symtab.addresses, address) - 1
        if index < 0:
            return None
        symbol_address = symtab.addresses[index]
        function = bisect.bisect_right(symtab.function_starts, address) - 1
        if function >= 0 and symtab.function_starts[function] > symbol_address:
            # The address belongs to a function the symbol table does not name
            return None
        try:
            name = self._symbol_name(image, symtab.stroff + symtab.string_offsets[index])
        except OSError:
            return None
        if not name:
            return None
        return name, address - symbol_address


def find_device_support_symbols(service_provider: LockdownServiceProvider) -> Optional[Path]:
    """Get the Xcode DeviceSupport `Symbols` directory of the given device, if it exists."""
    if service_provider.product_type is None:
        return None
    symbols = (
        get_device_support_path(
            service_provider.product_type,
            service_provider.product_version,
            service_provider.product_build_version or "",
        )
        / "Symbols"
    )
    return symbols if symbols.is_dir() else None
