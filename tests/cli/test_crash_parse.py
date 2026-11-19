import json
from pathlib import Path
from typing import Optional, cast

import pytest
import typer
from apple_symbols import KernelSymbols
from pycrashreport.crash_report import CrashReportBase, get_crash_report_from_buf

from pymobiledevice3.cli import crash as crash_module
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.crash_reports import CrashReportsManager, CrashReportsShell

pytestmark = [pytest.mark.cli]

_FAKE_SERVICE_PROVIDER = cast(LockdownServiceProvider, object())
_HEADER = '{"bug_type": "%s", "timestamp": "2026-11-16 17:35:06.00 +0200"}\n'
_PANIC = _HEADER % "210" + "panic(cpu 1 caller 0xfffffe0008123456): something broke"
_CRASH = _HEADER % "999" + "whatever"


def _fake_manager(reports: list[CrashReportBase]):
    class _Manager:
        def __init__(self, service_provider: object) -> None:
            pass

        async def __aenter__(self) -> "_Manager":
            return self

        async def __aexit__(self, *exc: object) -> bool:
            return False

        async def parse(self, path: str = "/") -> CrashReportBase:
            return reports[0]

        async def parse_latest(self, **kwargs: object) -> list[CrashReportBase]:
            return reports

    return _Manager


@pytest.fixture
def kernel_symbols(monkeypatch: pytest.MonkeyPatch) -> KernelSymbols:
    symbols = KernelSymbols([], {}, [])

    def load(cls: object, kernelcache: Path, signatures: Optional[Path] = None) -> KernelSymbols:
        assert (kernelcache, signatures) == (Path("kc"), Path("signatures"))
        return symbols

    monkeypatch.setattr(crash_module.KernelSymbols, "load", classmethod(load))
    return symbols


def test_crash_parse_gives_the_kernel_symbols_to_a_panic(
    monkeypatch: pytest.MonkeyPatch, kernel_symbols: KernelSymbols
) -> None:
    panic = get_crash_report_from_buf(_PANIC, filename="/panic-full.ips")
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([panic]))

    crash_module.crash_parse(
        _FAKE_SERVICE_PROVIDER, "/panic-full.ips", kernelcache=Path("kc"), kernel_signatures=Path("signatures")
    )

    assert cast(object, getattr(panic, "kernel_symbols", None)) is kernel_symbols


def test_crash_parse_latest_gives_the_kernel_symbols_to_panics_only(
    monkeypatch: pytest.MonkeyPatch, kernel_symbols: KernelSymbols
) -> None:
    panic = get_crash_report_from_buf(_PANIC, filename="/panic-full.ips")
    crash = get_crash_report_from_buf(_CRASH, filename="/other.ips")
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([crash, panic]))

    crash_module.crash_parse_latest(
        _FAKE_SERVICE_PROVIDER, count=2, kernelcache=Path("kc"), kernel_signatures=Path("signatures")
    )

    assert cast(object, getattr(panic, "kernel_symbols", None)) is kernel_symbols
    assert not hasattr(crash, "kernel_symbols")


def test_crash_parse_rejects_signatures_without_a_kernelcache() -> None:
    with pytest.raises(typer.BadParameter, match="--kernel-signatures requires --kernelcache"):
        crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/panic-full.ips", kernel_signatures=Path("signatures"))


def test_crash_parse_reports_an_unreadable_kernelcache(monkeypatch: pytest.MonkeyPatch) -> None:
    def load(cls: object, kernelcache: Path, signatures: Optional[Path] = None) -> KernelSymbols:
        raise FileNotFoundError("ipsw")

    monkeypatch.setattr(crash_module.KernelSymbols, "load", classmethod(load))
    with pytest.raises(typer.BadParameter, match="Reading the kernel symbols of kc failed"):
        crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/panic-full.ips", kernelcache=Path("kc"))


_PANIC_WITH_PROCESSES = _HEADER % "210" + json.dumps({
    "product": "iPhone17,3",
    "build": "iPhone OS 26.4 (23E246)",
    "panicString": "panic(cpu 1 caller 0xfffffe0008123456): something broke\nPanicked thread: 0xfffffe1e45334bf0, "
    "backtrace: 0xfffffe8fed6fb3d0, tid: 500\n",
    "binaryImages": [["11111111-2222-3333-4444-555555555555", 0x104000000, "P"]],
    "processByPid": {
        "0": {"procname": "kernel_task", "threadById": {"1": {"userFrames": [[0, 0x10]]}}},
        "77": {"procname": "food", "threadById": {"500": {"name": "worker", "userFrames": [[0, 0x40]]}}},
    },
})


class _ShellManager:
    """What the shell needs of a `CrashReportsManager`, serving reports out of memory."""

    afc = cast(AfcService, None)

    def __init__(self, reports: dict[str, str]) -> None:
        self._reports = reports

    async def parse(self, path: str = "/") -> CrashReportBase:
        return get_crash_report_from_buf(self._reports[path], filename=path)


def test_crash_parse_lists_the_threads_of_the_processes_asked_for(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    panic = get_crash_report_from_buf(_PANIC_WITH_PROCESSES, filename="/panic-full.ips")
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([panic]))

    crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/panic-full.ips")
    assert "Process:" not in capsys.readouterr().out

    crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/panic-full.ips", process=["food", "77"])
    out = capsys.readouterr().out
    assert out.count("Process: food (pid 77, 1 threads)") == 1
    assert "Thread: tid 500 worker (panicked)" in out
    assert "Process: kernel_task" not in out

    crash_module.crash_parse_latest(_FAKE_SERVICE_PROVIDER, all_processes=True)
    out = capsys.readouterr().out
    assert "Process: kernel_task (pid 0, 1 threads)" in out
    assert "Process: food (pid 77, 1 threads)" in out


def test_crash_parse_rejects_processes_a_report_does_not_hold(monkeypatch: pytest.MonkeyPatch) -> None:
    panic = get_crash_report_from_buf(_PANIC_WITH_PROCESSES, filename="/panic-full.ips")
    crash = get_crash_report_from_buf(_CRASH, filename="/other.ips")

    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([panic]))
    with pytest.raises(typer.BadParameter, match="The report holds no process nosuchd"):
        crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/panic-full.ips", process=["nosuchd"])

    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([crash]))
    with pytest.raises(typer.BadParameter, match="apply to panic reports only"):
        crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/other.ips", all_processes=True)


@pytest.mark.asyncio
async def test_crash_shell_parse_takes_the_same_options(
    kernel_symbols: KernelSymbols, capsys: pytest.CaptureFixture[str]
) -> None:
    shell = CrashReportsShell(cast(CrashReportsManager, _ShellManager({"panic-full.ips": _PANIC_WITH_PROCESSES})))

    assert await shell.run_line("parse panic-full.ips") == 0
    out = capsys.readouterr().out
    assert "something broke" in out
    assert "Process:" not in out

    assert await shell.run_line("parse panic-full.ips -p food --kernelcache kc --kernel-signatures signatures") == 0
    out = capsys.readouterr().out
    assert "Process: food (pid 77, 1 threads)" in out
    assert "Process: kernel_task" not in out

    assert await shell.run_line("parse panic-full.ips --all") == 0
    assert "Process: kernel_task (pid 0, 1 threads)" in capsys.readouterr().out

    assert await shell.run_line("parse panic-full.ips --process nosuchd") != 0
