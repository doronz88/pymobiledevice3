import logging
import posixpath
from typing import Any

import pytest

from pymobiledevice3.exceptions import AfcDeleteError, AfcException, AfcFileNotFoundError
from pymobiledevice3.services.afc import AfcError, AfcOpcode, AfcService
from pymobiledevice3.services.crash_reports import CrashReportsManager

STALE_SYSDIAGNOSE = (
    "/DiagnosticLogs/sysdiagnose/IN_PROGRESS_sysdiagnose_2026.08.10_23-55-37+0200_iPhone-OS_iPhone_24A5408d.tmp"
)


class _FakeDevice:
    """A crash reports directory: ``dirs`` and ``files`` by path; entries under ``protected`` refuse removal."""

    def __init__(self, dirs: set[str], files: set[str], protected: tuple[str, ...] = ()) -> None:
        self.dirs = {"/", *dirs}
        self.files = files
        self.protected = protected
        # paths something else removes right before we get to them
        self.vanishing: set[str] = set()

    def _children(self, path: str) -> list[str]:
        return sorted(
            posixpath.basename(entry)
            for entry in self.dirs | self.files
            if entry != "/" and posixpath.dirname(entry) == path
        )

    def _forget(self, path: str) -> None:
        self.dirs.discard(path)
        self.files.discard(path)

    def attach(self, afc: AfcService, monkeypatch: pytest.MonkeyPatch) -> None:
        async def isdir(path: str) -> bool:
            if path in self.vanishing:
                self.vanishing.discard(path)
                self._forget(path)
            if path not in self.dirs and path not in self.files:
                raise AfcFileNotFoundError(f"No such file on the device: {path}", AfcError.READ_ERROR, path)
            return path in self.dirs

        async def exists(path: str) -> bool:
            return path in self.dirs or path in self.files

        async def listdir(path: str) -> list[str]:
            return self._children(path)

        async def do_operation(opcode: AfcOpcode, data: bytes = b"", filename: Any = None) -> bytes:
            path = data.rstrip(b"\0").decode()
            if opcode == AfcOpcode.REMOVE_PATH_AND_CONTENTS:
                raise AfcException("tree removal failed", AfcError.PERM_DENIED, path)
            assert opcode == AfcOpcode.REMOVE_PATH
            if path not in self.dirs and path not in self.files:
                raise AfcException("removal failed", AfcError.OBJECT_NOT_FOUND, path)
            if self.protected and path.startswith(self.protected):
                raise AfcException("removal failed", AfcError.PERM_DENIED, path)
            if self._children(path):
                raise AfcException("removal failed", AfcError.DIR_NOT_EMPTY, path)
            self._forget(path)
            return b""

        monkeypatch.setattr(afc, "isdir", isdir)
        monkeypatch.setattr(afc, "exists", exists)
        monkeypatch.setattr(afc, "listdir", listdir)
        monkeypatch.setattr(afc, "_do_operation", do_operation)


def _manager(device: _FakeDevice, monkeypatch: pytest.MonkeyPatch) -> CrashReportsManager:
    manager = CrashReportsManager.__new__(CrashReportsManager)
    manager.logger = logging.getLogger("test_crash_clear")
    manager.afc = AfcService.__new__(AfcService)
    device.attach(manager.afc, monkeypatch)

    async def ls(path: str = "/", depth: int = 1) -> list[str]:
        return [posixpath.join(path, entry) for entry in device._children(path)]

    monkeypatch.setattr(manager, "ls", ls)
    return manager


def _reporter_device() -> _FakeDevice:
    """What #2146 shows: crash reports next to an interrupted sysdiagnose the device keeps."""
    return _FakeDevice(
        dirs={
            "/DiagnosticLogs",
            "/DiagnosticLogs/sysdiagnose",
            STALE_SYSDIAGNOSE,
            f"{STALE_SYSDIAGNOSE}/WiFi_sysdiagnose_temp.0SIh9r",
            f"{STALE_SYSDIAGNOSE}/WiFi_sysdiagnose_temp.0SIh9r/WiFi",
        },
        files={"/JetsamEvent-2026-10-29.ips", "/DiagnosticLogs/sysdiagnose/sysdiagnose_2026.10.01.tar.gz"},
        protected=(STALE_SYSDIAGNOSE,),
    )


@pytest.mark.asyncio
async def test_clear_keeps_a_protected_sysdiagnose_with_a_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    device = _reporter_device()

    with caplog.at_level(logging.WARNING):
        await _manager(device, monkeypatch).clear()

    # everything else is gone; the sysdiagnose is named once, not as every path in it
    assert device.files == set()
    assert "/DiagnosticLogs/sysdiagnose" in device.dirs
    assert [record.getMessage().count(posixpath.basename(STALE_SYSDIAGNOSE)) for record in caplog.records] == [1]


@pytest.mark.asyncio
async def test_clear_reports_other_failures_with_their_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    device = _FakeDevice(dirs={"/Retired"}, files={"/Retired/a.ips"}, protected=("/Retired/a.ips",))

    with pytest.raises(AfcDeleteError, match=r"/Retired/a\.ips \(PERM_DENIED\)") as excinfo:
        await _manager(device, monkeypatch).clear()

    # the directory holding it is not reported on its own
    assert excinfo.value.failures == {"/Retired/a.ips": AfcError.PERM_DENIED}


@pytest.mark.asyncio
async def test_clear_counts_what_vanishes_meanwhile_as_deleted(monkeypatch: pytest.MonkeyPatch) -> None:
    device = _FakeDevice(dirs={"/Retired"}, files={"/Retired/a.ips", "/b.ips"})
    device.vanishing = {"/Retired/a.ips"}

    await _manager(device, monkeypatch).clear()

    assert device.files == set()
    assert device.dirs == {"/"}


@pytest.mark.asyncio
async def test_rm_of_a_missing_path_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    afc = AfcService.__new__(AfcService)
    _FakeDevice(dirs=set(), files=set()).attach(afc, monkeypatch)

    with pytest.raises(AfcException) as excinfo:
        await afc.rm("/missing")
    assert excinfo.value.status == AfcError.OBJECT_NOT_FOUND
    assert await afc.rm("/missing", force=True) == ["/missing"]
