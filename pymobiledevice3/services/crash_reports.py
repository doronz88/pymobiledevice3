import asyncio
import logging
import posixpath
import re
import time
from collections.abc import AsyncGenerator
from json import JSONDecodeError
from typing import Callable, ClassVar, Optional

from pycrashreport.crash_report import CrashReportBase, get_crash_report_from_buf
from xonsh.built_ins import XSH
from xonsh.cli_utils import Annotated, Arg

from pymobiledevice3.exceptions import (
    AfcException,
    AfcFileNotFoundError,
    NotificationTimeoutError,
    SysdiagnoseTimeoutError,
)
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService, AfcShell, path_completer
from pymobiledevice3.services.notification_proxy import NotificationProxyService
from pymobiledevice3.services.os_trace import OsTraceService

SYSDIAGNOSE_PROCESS_NAMES = ("sysdiagnose", "sysdiagnosed")
SYSDIAGNOSE_DIR = "DiagnosticLogs/sysdiagnose"
SYSDIAGNOSE_IN_PROGRESS_MAX_TTL_SECS = 600

# on iOS17, we need to wait for a moment before trying to fetch the sysdiagnose archive
IOS17_SYSDIAGNOSE_DELAY = 3


class CrashReportsManager:
    COPY_MOBILE_NAME = "com.apple.crashreportcopymobile"
    RSD_COPY_MOBILE_NAME = "com.apple.crashreportcopymobile.shim.remote"

    CRASH_MOVER_NAME = "com.apple.crashreportmover"
    RSD_CRASH_MOVER_NAME = "com.apple.crashreportmover.shim.remote"

    APPSTORED_PATH = "/com.apple.appstored"
    IN_PROGRESS_SYSDIAGNOSE_EXTENSIONS: ClassVar = [".tmp", ".tar.gz"]

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown

        if isinstance(lockdown, LockdownClient):
            self.copy_mobile_service_name = self.COPY_MOBILE_NAME
            self.crash_mover_service_name = self.CRASH_MOVER_NAME
        else:
            self.copy_mobile_service_name = self.RSD_COPY_MOBILE_NAME
            self.crash_mover_service_name = self.RSD_CRASH_MOVER_NAME

        self.afc = AfcService(lockdown, service_name=self.copy_mobile_service_name)

    def __enter__(self):
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aenter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        raise RuntimeError("Use async context manager: `async with ...`")

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    async def aclose(self) -> None:
        await self.afc.aclose()

    async def clear(self, path: str = "/") -> None:
        """
        Clear crash reports under a path.
        """
        undeleted_items = []
        for filename in await self.ls(path, depth=1):
            undeleted_items.extend(await self.afc.rm(filename, force=True))

        for item in undeleted_items:
            # special case of file that sometimes created automatically right after delete,
            # and then we can't delete the folder because it's not empty
            if item != self.APPSTORED_PATH:
                raise AfcException(
                    f"failed to clear crash reports under {path!r}, undeleted items: {undeleted_items}", None
                )

    async def ls(self, path: str = "/", depth: int = 1) -> list[str]:
        """
        List file and folder in the crash report's directory.
        :param path: Path to list, relative to the crash report's directory.
        :param depth: Listing depth, -1 to list infinite.
        :return: List of files listed.
        """
        result = []
        async for item in self.afc.dirlist(path, depth):
            result.append(item)
        return result[1:]  # skip the root path '/'

    async def parse(self, path: str = "/") -> CrashReportBase:
        """
        Parse a crash report file and return the parsed crash report object.

        :param path: Path to a crash report file.
        :return: Parsed crash report object.
        """
        return get_crash_report_from_buf((await self.afc.get_file_contents(path)).decode(), filename=path)

    async def parse_latest(
        self,
        path: str = "/",
        match: Optional[list[str]] = None,
        match_insensitive: Optional[list[str]] = None,
        count: int = 1,
    ) -> list[CrashReportBase]:
        """
        Parse latest top-level crash report(s) under a path, optionally filtered by basename regex patterns.

        Scans the top level of the given path, filters regular files by basename,
        and returns matches sorted by last modification time (newest first).

        :param path: Path whose top-level entries should be considered. Defaults to '/'
        :param match: Case-sensitive regex patterns over report basename.
        :param match_insensitive: Case-insensitive regex patterns over report basename.
        :param count: Maximum number of latest matching reports to parse.
        :return: Parsed crash report objects ordered from newest to oldest.
                 Result length is between 1 and count.
        :raises ValueError: If count < 1 or if no reports match the filters.

        All provided patterns must match.
        """

        def get_match_arguments_description():
            return ", ".join(
                f"{name}={value!r}"
                for name, value in (("match", match_patterns), ("match_insensitive", match_insensitive_patterns))
                if value
            )

        if count < 1:
            raise ValueError("count must be >= 1")

        match_patterns = match or []
        match_insensitive_patterns = match_insensitive or []

        patterns = [re.compile(pattern) for pattern in match_patterns]
        patterns.extend(re.compile(pattern, re.IGNORECASE) for pattern in match_insensitive_patterns)

        matching_entries_by_mtime = sorted(
            [
                (stat["st_mtime"].timestamp(), entry)
                async for entry in self.afc.dirlist(path, depth=1)
                if entry != path
                and (stat := await self.afc.stat(entry)).get("st_ifmt") == "S_IFREG"
                and (not patterns or all(pattern.search(posixpath.basename(entry)) for pattern in patterns))
            ],
            reverse=True,
        )

        if len(matching_entries_by_mtime) == 0:
            match_arguments_description = get_match_arguments_description()
            raise ValueError(
                f"No reports found ({match_arguments_description})"
                if match_arguments_description
                else "No reports found"
            )

        return [await self.parse(report_path) for _, report_path in matching_entries_by_mtime[:count]]

    async def pull(
        self, out: str, entry: str = "/", erase: bool = False, match: Optional[str] = None, progress_bar: bool = True
    ) -> None:
        """
        Pull crash reports from the device.
        :param out: Directory to pull crash reports to.
        :param entry: File or Folder to pull.
        :param erase: Whether to erase the original file from the CrashReports directory.
        :param match: Regex to match against file and directory names to pull.
        :param progress_bar: Whether to show a progress bar when pulling large files.
        """

        async def _callback(src: str, dst: str) -> None:
            self.logger.info(f"{src} --> {dst}")
            if erase:
                await self.afc.rm_single(src, force=True)

        match = None if match is None else re.compile(match)
        await self.afc.pull(entry, out, match, callback=_callback, progress_bar=progress_bar, ignore_errors=True)

    async def flush(self) -> None:
        """Trigger com.apple.crashreportmover to flush all products into CrashReports directory"""
        ack = b"ping\x00"
        service = await self.lockdown.start_lockdown_service(self.crash_mover_service_name)
        assert ack == await service.recvall(len(ack))

    async def watch(self, name: Optional[str] = None, raw: bool = False) -> AsyncGenerator[str, None]:
        """
        Monitor creation of new crash reports for a given process name.

        Return value can either be the raw crash string, or parsed result containing a more human-friendly
        representation for the crash.
        """
        async for syslog_entry in OsTraceService(lockdown=self.lockdown).syslog():
            if (
                (posixpath.basename(syslog_entry.filename) != "osanalyticshelper")
                or (posixpath.basename(syslog_entry.image_name) != "OSAnalytics")
                or not syslog_entry.message.startswith("Saved type ")
            ):
                # skip non-ips creation syslog lines
                continue

            filename = posixpath.basename(syslog_entry.message.split()[-1])
            self.logger.debug(f"crash report: {filename}")

            if posixpath.splitext(filename)[-1] not in (".ips", ".panic"):
                continue

            while True:
                try:
                    crash_report_raw = (await self.afc.get_file_contents(filename)).decode()
                    crash_report = get_crash_report_from_buf(crash_report_raw, filename=filename)
                    break
                except (AfcFileNotFoundError, JSONDecodeError):
                    # Sometimes we have to wait for the file to be readable
                    pass

            if name is None or crash_report.name == name:
                if raw:
                    yield crash_report_raw
                else:
                    yield crash_report

    async def get_new_sysdiagnose(
        self,
        out: str,
        erase: bool = True,
        *,
        timeout: Optional[float] = None,
        callback: Optional[Callable[[float], None]] = None,
    ) -> None:
        """
        Monitor the creation of a newly created sysdiagnose archive and pull it
        :param out: filename
        :param erase: remove after pulling
        :keyword timeout: Maximum time in seconds to wait for the completion of sysdiagnose archive
            If None (default), waits indefinitely
        :keyword callback: optional callback function (form: func(float)) that accepts the elapsed time so far
        """
        start_time = time.monotonic()
        end_time = None
        if timeout is not None:
            end_time = start_time + timeout
        sysdiagnose_filename = await self._get_new_sysdiagnose_filename(end_time)

        if callback is not None:
            callback(time.monotonic() - start_time)

        self.logger.info("sysdiagnose tarball creation has been started")
        await self._wait_for_sysdiagnose_to_finish(timeout)

        if callback is not None:
            callback(time.monotonic() - start_time)

        await self.pull(out, entry=sysdiagnose_filename, erase=erase)

        if callback is not None:
            callback(time.monotonic() - start_time)

    async def _wait_for_sysdiagnose_to_finish(self, end_time: Optional[float] = None) -> None:
        async with NotificationProxyService(self.lockdown, timeout=end_time) as service:
            stop_notification = "com.apple.sysdiagnose.sysdiagnoseStopped"
            await service.notify_register_dispatch(stop_notification)
            try:
                async for event in service.receive_notification():
                    if event["Name"] != stop_notification:
                        continue
                    self.logger.debug(f"Received {event}")
                    await asyncio.sleep(IOS17_SYSDIAGNOSE_DELAY)
                    break
            except NotificationTimeoutError as e:
                raise SysdiagnoseTimeoutError("Timeout waiting for sysdiagnose completion") from e

    async def _get_new_sysdiagnose_filename(self, end_time: Optional[float] = None) -> str:
        sysdiagnose_filename = None
        excluded_temp_files = []

        while sysdiagnose_filename is None:
            try:
                for filename in await self.afc.listdir(SYSDIAGNOSE_DIR):
                    # search for an IN_PROGRESS archive
                    if filename not in excluded_temp_files and "IN_PROGRESS_" in filename:
                        for ext in self.IN_PROGRESS_SYSDIAGNOSE_EXTENSIONS:
                            if filename.endswith(ext):
                                delta = (
                                    await self.lockdown.get_date()
                                    - (await self.afc.stat(posixpath.join(SYSDIAGNOSE_DIR, filename)))["st_mtime"]
                                )
                                # Ignores IN_PROGRESS sysdiagnose files older than the defined time to live
                                if delta.total_seconds() < SYSDIAGNOSE_IN_PROGRESS_MAX_TTL_SECS:
                                    self.logger.debug(f"Detected in progress sysdiagnose {filename}")
                                    sysdiagnose_filename = filename.rsplit(ext)[0]
                                    sysdiagnose_filename = sysdiagnose_filename.replace("IN_PROGRESS_", "")
                                    sysdiagnose_filename = f"{sysdiagnose_filename}.tar.gz"
                                    return posixpath.join(SYSDIAGNOSE_DIR, sysdiagnose_filename)
                                else:
                                    self.logger.warning(f"Old sysdiagnose temp file ignored {filename}")
                                    excluded_temp_files.append(filename)
            except AfcException:
                pass

            if self._check_timeout(end_time):
                raise SysdiagnoseTimeoutError("Timeout finding in-progress sysdiagnose filename")
            await asyncio.sleep(0.1)

    def _check_timeout(self, end_time: Optional[float] = None) -> bool:
        return end_time is not None and time.monotonic() > end_time


class CrashReportsShell(AfcShell):
    @classmethod
    def create(cls, service_provider: LockdownServiceProvider, **kwargs):
        manager = CrashReportsManager(service_provider)
        XSH.ctx["_manager"] = manager
        super(CrashReportsShell, CrashReportsShell).create(service_provider, service=manager.afc)

    def _setup_shell_commands(self):
        super()._setup_shell_commands()
        self._register_arg_parse_alias("parse", self._do_parse)
        self._register_arg_parse_alias("parse-latest", self._do_parse_latest)
        self._register_arg_parse_alias("clear", self._do_clear)

    def _do_parse(self, filename: Annotated[str, Arg(completer=path_completer)]) -> None:
        """
        Parse and print a crash report by filename.

        :param filename: Path to the crash report file
        """
        print(XSH.ctx["_shell"]._async_runner.run(XSH.ctx["_manager"].parse(filename)))

    def _do_parse_latest(
        self,
        path: Annotated[str, Arg(completer=path_completer)] = "/",
        match: Annotated[Optional[list[str]], Arg("--match", "-m", action="append")] = None,
        match_insensitive: Annotated[
            Optional[list[str]],
            Arg("--match-insensitive", "-mi", action="append"),
        ] = None,
        count: Annotated[int, Arg("--count", "-n")] = 1,
    ) -> None:
        """Parse latest top-level crash report(s) under a path, ordered by newest first"""
        latest_reports = XSH.ctx["_shell"]._async_runner.run(
            XSH.ctx["_manager"].parse_latest(
                path=path,
                match=match or [],
                match_insensitive=match_insensitive or [],
                count=count,
            )
        )
        for report in latest_reports:
            print(report)

    def _do_clear(self, path: Annotated[str, Arg(completer=path_completer)] = "/") -> None:
        """Clear crash reports from the device under a path."""
        XSH.ctx["_shell"]._async_runner.run(XSH.ctx["_manager"].clear(path))
