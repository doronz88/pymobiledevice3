import asyncio
from collections.abc import AsyncGenerator, Iterable
from typing import Optional

from packaging.version import InvalidVersion, Version

from pymobiledevice3.exceptions import ConnectionTerminatedError, FileRelayError
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService

DEFAULT_CHUNK_SIZE = 1024 * 1024
DEFAULT_SOURCE = "UserDatabases"
FILE_RELAY_RESTRICTED_VERSION = Version("8.0")
SERVICE_NAME = "com.apple.mobile.file_relay"

KNOWN_SOURCES = (
    "Accounts",
    "AddressBook",
    "AppleSupport",
    "Baseband",
    "CoreLocation",
    "CrashReporter",
    "HFSMeta",
    "Keyboard",
    "Lockdown",
    "MobileAsset",
    "MobileBackup",
    "MobileCal",
    "MobileDelete",
    "MobileInstallation",
    "MobileNotes",
    "NANDDebugInfo",
    "Network",
    "Photos",
    "SystemConfiguration",
    "Ubiquity",
    "UserDatabases",
    "VARFS",
    "VPN",
    "Voicemail",
    "WiFi",
    "WirelessAutomation",
    "tmp",
)


def is_file_relay_likely_supported(product_version: str) -> bool:
    try:
        return Version(product_version) < FILE_RELAY_RESTRICTED_VERSION
    except InvalidVersion:
        return True


def file_relay_unsupported_message(product_version: str) -> str:
    return (
        "file_relay is a legacy service. "
        f"The device reports iOS {product_version}; on iOS {FILE_RELAY_RESTRICTED_VERSION} and newer, "
        "Apple restricts or removes com.apple.mobile.file_relay, so this command is unlikely to be useful. "
        "Use --allow-unsupported to try anyway."
    )


class FileRelayService(LockdownService):
    SERVICE_NAME = SERVICE_NAME

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        super().__init__(lockdown, self.SERVICE_NAME)

    async def stop_session(self) -> None:
        self.logger.info("Disconnecting...")
        await self.close()

    async def request_sources(
        self,
        sources: Optional[Iterable[str]] = None,
        *,
        timeout: Optional[float] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> bytes:
        archive = bytearray()
        async for chunk in self.iter_sources(sources, timeout=timeout, chunk_size=chunk_size):
            archive.extend(chunk)
        return bytes(archive)

    async def iter_sources(
        self,
        sources: Optional[Iterable[str]] = None,
        *,
        timeout: Optional[float] = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> AsyncGenerator[bytes, None]:
        normalized_sources = self._normalize_sources(sources)
        await self._request_sources(normalized_sources, timeout=timeout)

        chunk = await self._read_next_archive_chunk(chunk_size)
        while chunk:
            yield chunk
            chunk = await self._read_next_archive_chunk(chunk_size)

    async def _read_next_archive_chunk(self, chunk_size: int) -> bytes:
        try:
            return await self.service.recv_any(chunk_size)
        except ConnectionTerminatedError:
            return b""

    async def _request_sources(self, sources: list[str], *, timeout: Optional[float] = None) -> None:
        await self.service.send_plist({"Sources": sources})

        response = await self._receive_response(timeout=timeout)
        if not isinstance(response, dict):
            raise FileRelayError(f"file relay returned an unexpected response: {response!r}")

        error = response.get("Error")
        if error:
            raise FileRelayError(f"file relay request failed: {error}", response=response)

        status = response.get("Status")
        if status != "Acknowledged":
            raise FileRelayError(f"file relay request was not acknowledged: {response!r}", response=response)

    async def _receive_response(self, *, timeout: Optional[float] = None) -> dict:
        if timeout is None:
            return await self.service.recv_plist()
        try:
            return await asyncio.wait_for(self.service.recv_plist(), timeout=timeout)
        except asyncio.TimeoutError as e:
            raise FileRelayError("timed out waiting for file relay acknowledgement") from e

    @staticmethod
    def _normalize_sources(sources: Optional[Iterable[str]]) -> list[str]:
        if sources is None:
            return [DEFAULT_SOURCE]

        normalized_sources = [source for source in sources if source]
        if not normalized_sources:
            raise ValueError("at least one file relay source is required")
        return normalized_sources
