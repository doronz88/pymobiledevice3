import os
import plistlib
import stat
import struct
import uuid
import zipfile
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Callable, Optional, cast

from pymobiledevice3.exceptions import AppInstallError, PyMobileDevice3Exception
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.lockdown_service import LockdownService

#: Staging directory, relative to the device's Media directory.
STAGING_DIRECTORY = "PublicStaging"

_CHUNK_SIZE = 1024 * 1024
_LOCAL_FILE_HEADER = struct.Struct("<IHHHHHIIIHH")
_LOCAL_FILE_SIGNATURE = 0x04034B50
#: The stream ends where a zip's central directory would begin; the directory itself is never sent.
_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
_ZIP_METADATA_PATH = "META-INF/com.apple.ZipMetadata.plist"
_STANDARD_DIRECTORY_MODE = stat.S_IFDIR | 0o755
_STANDARD_FILE_MODE = stat.S_IFREG | 0o644
#: StreamingZip's own extra field, carrying the mode of an entry that differs from the standard one.
_MODE_EXTRA_ID = b"SZ"
_MAX_ENTRY_SIZE = 0xFFFFFFFF
_HAS_PERMISSION_BITS = os.name != "nt"


class StreamingZipConduitError(PyMobileDevice3Exception):
    """The device refused or failed a streaming zip conduit transfer."""

    def __init__(self, error: str) -> None:
        super().__init__(f"streaming zip conduit failed: {error}")
        #: The device's error code, e.g. ``DestinationExists``, ``NoSpace`` or ``ExtractionFailed``.
        self.error = error


class _Entry:
    """One record of the stream: a directory, a regular file or a symlink."""

    def __init__(self, name: str, mode: int, size: int, crc: int, chunks: Callable[[], Iterator[bytes]]) -> None:
        self.name = name
        self.mode = mode
        self.size = size
        self.crc = crc
        self.chunks = chunks

    def header(self) -> bytes:
        name = self.name.encode()
        standard = _STANDARD_DIRECTORY_MODE if stat.S_ISDIR(self.mode) else _STANDARD_FILE_MODE
        extra = b"" if self.mode == standard else _MODE_EXTRA_ID + struct.pack("<HH", 2, self.mode & 0xFFFF)
        return (
            _LOCAL_FILE_HEADER.pack(
                _LOCAL_FILE_SIGNATURE, 20, 0, zipfile.ZIP_STORED, 0, 0x21, self.crc, self.size, self.size,
                len(name), len(extra),
            )
            + name
            + extra
        )  # fmt: skip


def _bytes_entry(name: str, mode: int, data: bytes) -> _Entry:
    return _Entry(name, mode, len(data), zlib.crc32(data), lambda: iter((data,)))


def _directory_entry(name: str, mode: int = _STANDARD_DIRECTORY_MODE) -> _Entry:
    return _Entry(name if name.endswith("/") else name + "/", mode, 0, 0, lambda: iter(()))


def _file_crc(path: Path) -> int:
    crc = 0
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            crc = zlib.crc32(chunk, crc)
    return crc


def _file_chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            yield chunk


def _local_mode(path: Path) -> int:
    """The mode to give ``path`` on the device."""
    mode = path.lstat().st_mode
    if not _HAS_PERMISSION_BITS and not stat.S_ISLNK(mode):
        # Windows keeps no permission bits. Send directories as standard ones and files as
        # executable, so that the app's binaries can still run.
        return _STANDARD_DIRECTORY_MODE if stat.S_ISDIR(mode) else stat.S_IFREG | 0o755
    return mode


def _app_directory_entries(app: Path) -> list[_Entry]:
    """Entries for an unpackaged ``.app``, laid out under ``Payload/`` as in an ``.ipa``."""
    root = f"Payload/{app.name}"
    entries = [_directory_entry("Payload"), _directory_entry(root)]
    for directory, directory_names, file_names in os.walk(app):
        directory_names.sort()
        relative = Path(directory).relative_to(app)
        prefix = root if relative == Path(".") else f"{root}/{relative.as_posix()}"
        # A symlink to a directory is listed among the directories, but must be sent as a link.
        links = [name for name in directory_names if (Path(directory) / name).is_symlink()]
        for name in sorted(directory_names):
            if name not in links:
                entries.append(_directory_entry(f"{prefix}/{name}", _local_mode(Path(directory) / name)))
        for name in sorted([*file_names, *links]):
            path = Path(directory) / name
            mode = _local_mode(path)
            if stat.S_ISLNK(mode):
                entries.append(_bytes_entry(f"{prefix}/{name}", mode, os.readlink(path).encode()))
            elif stat.S_ISREG(mode):
                size = path.stat().st_size
                entries.append(_Entry(f"{prefix}/{name}", mode, size, _file_crc(path), lambda p=path: _file_chunks(p)))
    return entries


def _ipa_chunks(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> Iterator[bytes]:
    with archive.open(info) as f:
        while chunk := f.read(_CHUNK_SIZE):
            yield chunk


def _ipa_entries(archive: zipfile.ZipFile) -> list[_Entry]:
    entries: list[_Entry] = []
    for info in archive.infolist():
        mode = info.external_attr >> 16
        if info.is_dir():
            entries.append(_directory_entry(info.filename, mode if stat.S_ISDIR(mode) else _STANDARD_DIRECTORY_MODE))
        elif stat.S_ISLNK(mode):
            entries.append(_bytes_entry(info.filename, mode, archive.read(info)))
        else:
            if not stat.S_ISREG(mode):
                mode = _STANDARD_FILE_MODE  # archives made without unix attributes
            entries.append(
                _Entry(info.filename, mode, info.file_size, info.CRC, lambda i=info: _ipa_chunks(archive, i))
            )
    return entries


def _with_metadata(entries: list[_Entry]) -> list[_Entry]:
    """Prepend the metadata record that marks the stream as extractable while it arrives."""
    entries = [entry for entry in entries if entry.name not in ("META-INF/", _ZIP_METADATA_PATH)]
    for entry in entries:
        if entry.size > _MAX_ENTRY_SIZE:
            raise ValueError(f"{entry.name} is larger than 4 GiB, which the streaming format cannot carry")
    metadata = plistlib.dumps({
        "RecordCount": len(entries) + 2,
        "StandardDirectoryPerms": _STANDARD_DIRECTORY_MODE,
        "StandardFilePerms": _STANDARD_FILE_MODE,
        "TotalUncompressedBytes": sum(entry.size for entry in entries),
        "Version": 2,
    })
    return [_directory_entry("META-INF"), _bytes_entry(_ZIP_METADATA_PATH, _STANDARD_FILE_MODE, metadata), *entries]


class StreamingZipConduitService(LockdownService):
    """
    Stream an app to the device and install it, the way Xcode does.

    The device extracts the archive while it arrives, instead of receiving an ``.ipa`` over AFC and
    unpacking it afterwards as `InstallationProxyService` does, so nothing is written twice. The
    stream is a zip without compression and without a central directory, opened by a metadata
    record.

    Each instance performs a single transfer. This is a lockdown service; the RSD/tunnel variant is
    chosen automatically for `RemoteServiceDiscoveryService` providers.
    """

    SERVICE_NAME = "com.apple.streaming_zip_conduit"
    RSD_SERVICE_NAME = "com.apple.streaming_zip_conduit.shim.remote"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        """
        :param lockdown: service provider used to start the service and reach the device.
        """
        if isinstance(lockdown, RemoteServiceDiscoveryService):
            super().__init__(lockdown, self.RSD_SERVICE_NAME)
        else:
            super().__init__(lockdown, self.SERVICE_NAME)

    async def install(
        self,
        package_path: Path,
        developer: bool = False,
        options: Optional[dict[str, Any]] = None,
        handler: Optional[Callable[[int], Any]] = None,
    ) -> None:
        """
        Stream a local app to the device and install it.

        :param package_path: an ``.ipa`` file or an unpackaged ``.app`` directory.
        :param developer: install as a developer package (``PackageType`` ``Developer``) rather than
            a customer one.
        :param options: extra installation options, merged over the defaults.
        :param handler: progress callback, invoked with the completion percentage.
        :raises AppInstallError: if the device fails to install the app.
        :raises StreamingZipConduitError: if the device refuses or fails the transfer.
        """
        install_options: dict[str, Any] = {"PackageType": "Developer" if developer else "Customer"}
        install_options.update(options or {})
        setup: dict[str, Any] = {
            "InstallOptionsDictionary": install_options,
            "InstallTransferredDirectory": True,
            "MediaSubdir": f"{STAGING_DIRECTORY}/pymobiledevice3-{uuid.uuid4()}.ipa",
            "UserInitiatedTransfer": False,
        }
        if package_path.is_dir():
            await self._transfer(setup, _app_directory_entries(package_path), handler)
        else:
            with zipfile.ZipFile(package_path) as archive:
                await self._transfer(setup, _ipa_entries(archive), handler)

    async def _transfer(
        self, setup: dict[str, Any], entries: list[_Entry], handler: Optional[Callable[[int], Any]]
    ) -> None:
        await self.service.send_plist(setup)
        for entry in _with_metadata(entries):
            await self.service.sendall(entry.header())
            for chunk in entry.chunks():
                await self.service.sendall(chunk)
        await self.service.sendall(_CENTRAL_DIRECTORY_SIGNATURE)

        while True:
            response = await self.service.recv_plist()
            if "Error" in response:
                raise StreamingZipConduitError(str(response["Error"]))
            if response.get("Status") == "DataComplete":
                return
            progress = cast(dict[str, Any], response.get("InstallProgressDict") or {})
            if "Error" in progress:
                raise AppInstallError(f"{progress['Error']}: {progress.get('ErrorDescription')}")
            if handler is not None and "PercentComplete" in progress:
                handler(progress["PercentComplete"])
