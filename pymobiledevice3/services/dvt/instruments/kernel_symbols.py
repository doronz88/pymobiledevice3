"""
Symbol lookup against a kernelcache.

A kernelcache is a fileset holding the kernel and its extensions, each with its own UUID: the one a
stackshot reports for a kernel image. Released kernelcaches are stripped, so their symbols come from
``ipsw kernel symbolicate`` and its signatures (https://github.com/blacktop/symbolicator).
"""

import bisect
import hashlib
import json
import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional

from ipsw_parser.process import run

from pymobiledevice3.common import get_home_folder
from pymobiledevice3.services.dvt.instruments.device_support_symbols import (
    MH_MAGIC_64,
    fingerprint,
    parse_function_starts,
    parse_macho,
    read_symbol_name,
    read_symbols,
)

logger = logging.getLogger(__name__)

INDEX_VERSION = 1
INDEX_DIRNAME = "kernel_symbols"
# Name given to the only image of a kernel which is not a fileset
KERNEL_IMAGE_NAME = "kernel"


@dataclass(frozen=True)
class KernelImage:
    """The kernel or one of its extensions. `text_exec` is the unslid address of its `__TEXT_EXEC`."""

    name: str
    uuid: str
    text_exec: int


def _decompress(kernelcache: Path, directory: Path) -> Path:
    """Get the Mach-O of a kernelcache, which firmwares ship compressed inside an IM4P."""
    with open(kernelcache, "rb") as fd:
        magic = fd.read(4)
    if len(magic) == 4 and struct.unpack("<I", magic)[0] == MH_MAGIC_64:
        return kernelcache
    run("ipsw", "kernel", "dec", kernelcache, "--output", directory)
    decompressed = [file for file in directory.rglob("*") if file.is_file()]
    if len(decompressed) != 1:
        raise OSError(f"`ipsw kernel dec` did not decompress {kernelcache}")
    return decompressed[0]


def _signature_symbols(kernelcache: Path, signatures: Path, directory: Path) -> dict[int, str]:
    output = directory / "symbols"
    run("ipsw", "kernel", "symbolicate", "--signatures", signatures, "--json", "--output", output, kernelcache)
    symbols: dict[int, str] = {}
    for file in output.rglob("*.json"):
        symbols.update({int(address): str(name) for address, name in json.loads(file.read_text()).items()})
    return symbols


class KernelSymbols:
    """Resolves unslid kernel addresses to symbols."""

    def __init__(self, images: list[KernelImage], symbols: dict[int, str], function_starts: list[int]) -> None:
        self.images = images
        self._by_uuid = {image.uuid: image for image in images}
        self._addresses = sorted(symbols)
        self._names = [symbols[address] for address in self._addresses]
        self._function_starts = sorted(function_starts)

    @classmethod
    def load(
        cls, kernelcache: Path, signatures: Optional[Path] = None, index_dir: Optional[Path] = None
    ) -> "KernelSymbols":
        """
        Read the images and symbols of a kernelcache.

        :param kernelcache: A kernelcache, compressed (as found in an IPSW) or not.
        :param signatures: Directory of ``ipsw`` symbolication signatures to get the symbols of a
            stripped kernelcache with.
        :param index_dir: Where to keep the result, which takes a while to produce. It is reused
            for as long as the kernelcache and the signatures stay the same. The pymobiledevice3
            home folder by default.
        :raises OSError: If ``ipsw``, which decompresses and symbolicates, is missing or fails.
        """
        kernelcache = kernelcache.resolve()
        stat = kernelcache.stat()
        key: list[object] = [str(kernelcache), stat.st_size, stat.st_mtime_ns]
        if signatures is not None:
            signatures = signatures.resolve()
            key += [str(signatures), fingerprint(signatures)]
        if index_dir is None:
            index_dir = get_home_folder() / INDEX_DIRNAME
        index_file = index_dir / f"{hashlib.sha256(json.dumps(key).encode()).hexdigest()[:16]}.json"
        try:
            index = json.loads(index_file.read_text())
            if index["version"] == INDEX_VERSION and index["key"] == key:
                return cls(
                    [KernelImage(*image) for image in index["images"]],
                    {int(address): name for address, name in index["symbols"]},
                    index["function_starts"],
                )
        except (OSError, ValueError, KeyError, TypeError):
            pass

        logger.info(f"Reading the kernel symbols of {kernelcache}")
        images: list[KernelImage] = []
        symbols: dict[int, str] = {}
        function_starts: list[int] = []
        with TemporaryDirectory() as temp_dir:
            macho_file = _decompress(kernelcache, Path(temp_dir) / "kernelcache")
            if signatures is not None:
                symbols.update(_signature_symbols(macho_file, signatures, Path(temp_dir)))
            with open(macho_file, "rb") as fd:
                fileset = parse_macho(fd)
                if fileset is None:
                    raise OSError(f"{kernelcache} is not a kernelcache")
                for name, offset in fileset.fileset_entries or [(KERNEL_IMAGE_NAME, 0)]:
                    macho = parse_macho(fd, offset)
                    if macho is None or macho.uuid is None or macho.vmaddr is None:
                        continue
                    text_exec = macho.text_exec_vmaddr if macho.text_exec_vmaddr is not None else macho.vmaddr
                    images.append(KernelImage(name=name, uuid=macho.uuid, text_exec=text_exec))
                    if macho.function_starts_size:
                        fd.seek(macho.function_starts_offset)
                        function_starts += parse_function_starts(fd.read(macho.function_starts_size), macho.vmaddr)
                    # The symbol table says more than a signature guessing the same address
                    for address, string_offset in read_symbols(fd, macho, 0, 1 << 64):
                        symbols[address] = read_symbol_name(fd, macho.stroff + string_offset)

        try:
            index_dir.mkdir(parents=True, exist_ok=True)
            index_file.write_text(
                json.dumps({
                    "version": INDEX_VERSION,
                    "key": key,
                    "images": [[image.name, image.uuid, image.text_exec] for image in images],
                    "symbols": sorted(symbols.items()),
                    "function_starts": function_starts,
                })
            )
        except OSError as e:
            logger.debug(f"Could not store the kernel symbols at {index_file}: {e}")
        return cls(images, symbols, function_starts)

    @property
    def has_symbols(self) -> bool:
        return bool(self._addresses)

    def image_by_uuid(self, image_uuid: str) -> Optional[KernelImage]:
        return self._by_uuid.get(image_uuid.lower())

    def symbolicate(self, address: int) -> Optional[tuple[str, int]]:
        """
        Get the symbol preceding the given unslid address.

        :returns: The symbol name and the offset of `address` from it, or `None` when no symbol
            names the function the address is in.
        """
        index = bisect.bisect_right(self._addresses, address) - 1
        if index < 0:
            return None
        symbol_address = self._addresses[index]
        function = bisect.bisect_right(self._function_starts, address) - 1
        if function >= 0 and self._function_starts[function] > symbol_address:
            return None
        return self._names[index], address - symbol_address
