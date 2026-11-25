import json
from pathlib import Path
from typing import Optional, cast

import pytest
import typer
from apple_symbols import KernelSymbols
from pycrashreport.crash_report import CrashReportBase, get_crash_report_from_buf
from pycrashreport.symbols import SymbolServerError

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


def test_crash_parse_gives_the_symbol_server_to_the_report(monkeypatch: pytest.MonkeyPatch) -> None:
    panic = get_crash_report_from_buf(_PANIC, filename="/panic-full.ips")
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([panic]))

    crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/panic-full.ips")
    assert panic.symbol_server is None

    crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/panic-full.ips", symbol_server="http://server.invalid:3993")
    assert panic.symbol_server == "http://server.invalid:3993"

    crash_module.crash_parse_latest(_FAKE_SERVICE_PROVIDER, symbol_server="http://other.invalid:3993")
    assert panic.symbol_server == "http://other.invalid:3993"


def test_crash_parse_reports_a_symbol_server_which_cannot_be_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    def print_crash_report(*args: object) -> None:
        raise SymbolServerError("The server cannot be reached")

    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([get_crash_report_from_buf(_PANIC)]))
    monkeypatch.setattr(crash_module, "print_crash_report", print_crash_report)
    with pytest.raises(typer.BadParameter, match="The server cannot be reached"):
        crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/panic-full.ips", symbol_server="http://server.invalid:3993")


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


_STACKSHOT = _HEADER % "288" + json.dumps({
    "product": "iPhone19,4",
    "build": "iPhone OS 27.2.1 (24B91034)",
    "reason": "stackshot via sysdiagnose",
    "binaryImages": [["11111111-2222-3333-4444-555555555555", 0x104000000, "P"]],
    "processByPid": {
        "0": {
            "procname": "kernel_task",
            "threadById": {"1": {"name": "idle #0", "state": ["TH_RUN", "TH_IDLE"]}},
        },
        "77": {
            "procname": "food",
            "waitInfo": ["thread 500: pthread condvar 0x1"],
            "threadById": {"500": {"state": ["TH_WAIT"], "userFrames": [[0, 0x40]]}},
        },
    },
})


def test_crash_parse_lists_the_threads_of_a_stackshot(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stackshot = get_crash_report_from_buf(_STACKSHOT, filename="/stacks.ips")
    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([stackshot]))

    crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/stacks.ips")
    out = capsys.readouterr().out
    assert "Reason: stackshot via sysdiagnose" in out
    assert "Process:" not in out

    crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/stacks.ips", process=["food"])
    out = capsys.readouterr().out
    assert "Process: food (pid 77, 1 threads)" in out
    assert "Thread: tid 500 [TH_WAIT]" in out
    assert "Waiting: pthread condvar 0x1" in out
    assert "Process: kernel_task" not in out

    # only the threads which were on a CPU
    crash_module.crash_parse_latest(_FAKE_SERVICE_PROVIDER, running=True)
    out = capsys.readouterr().out
    assert "Thread: tid 1 idle #0 [TH_RUN, TH_IDLE]" in out
    assert "Process: food" not in out


@pytest.mark.asyncio
async def test_crash_shell_parse_lists_the_threads_of_a_stackshot(capsys: pytest.CaptureFixture[str]) -> None:
    shell = CrashReportsShell(cast(CrashReportsManager, _ShellManager({"stacks.ips": _STACKSHOT})))

    assert await shell.run_line("parse stacks.ips -r -p food") == 0
    out = capsys.readouterr().out
    assert "Process: kernel_task (pid 0, 1 threads)" in out
    assert "Process: food (pid 77, 1 threads)" in out


_SPINDUMP = (
    _HEADER % "145"
    + """Command:          food
PID:              77

Event:            disk writes

Heaviest stack for the target process:
  5  ??? (food + 64) [0x104000040]


Powerstats for:   food [77]
Num samples:      5 (100%)
  5  ??? (food + 64) [0x104000040]
    3  <Kernel mode>

  Binary Images:
           0x104000000 -                ???  food <11111111-2222-3333-4444-555555555555>  /usr/libexec/food
"""
)
_USER_CRASH = _HEADER % "309" + json.dumps({
    "procName": "food",
    "pid": 77,
    "exception": {"type": "EXC_CRASH", "signal": "SIGABRT", "codes": "0x0, 0x0"},
    "termination": {
        "namespace": "SIGNAL",
        "code": 6,
        "indicator": "Abort trap: 6",
        "byProc": "backboardd",
        "byPid": 73,
    },
    "faultingThread": 0,
    "usedImages": [{"base": 0x104000000, "path": "/usr/libexec/food", "uuid": "11111111-2222-3333-4444-555555555555"}],
    "threads": [
        {"id": 500, "triggered": True, "threadState": {}, "frames": [{"imageIndex": 0, "imageOffset": 64}]},
        {"id": 501, "name": "worker", "threadState": {}, "frames": [{"imageIndex": 0, "imageOffset": 128}]},
    ],
})


def test_crash_parse_lists_the_call_trees_of_a_spindump_and_the_threads_of_a_crash(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    spindump = get_crash_report_from_buf(_SPINDUMP, filename="/food.diskwrites_resource.ips")
    crash = get_crash_report_from_buf(_USER_CRASH, filename="/food.ips")

    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([spindump]))
    crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/food.diskwrites_resource.ips", process=["food"])
    out = capsys.readouterr().out
    assert "Event: disk writes" in out
    assert "Process: food (pid 77, samples: 5 (100%))" in out
    assert "<Kernel mode>" in out
    with pytest.raises(typer.BadParameter, match="--running applies to panic and stackshot reports only"):
        crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/food.diskwrites_resource.ips", running=True)

    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([crash]))
    crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/food.ips", all_processes=True)
    out = capsys.readouterr().out
    assert "Termination: SIGNAL, Abort trap: 6, by backboardd (pid 73)" in out
    assert "Thread: 0, tid 500 (crashed)" in out
    assert "Thread: 1, tid 501, worker" in out


def test_crash_parse_rejects_processes_a_report_does_not_hold(monkeypatch: pytest.MonkeyPatch) -> None:
    panic = get_crash_report_from_buf(_PANIC_WITH_PROCESSES, filename="/panic-full.ips")
    crash = get_crash_report_from_buf(_CRASH, filename="/other.ips")

    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([panic]))
    with pytest.raises(typer.BadParameter, match="The report holds no process nosuchd"):
        crash_module.crash_parse(_FAKE_SERVICE_PROVIDER, "/panic-full.ips", process=["nosuchd"])

    monkeypatch.setattr(crash_module, "CrashReportsManager", _fake_manager([crash]))
    with pytest.raises(typer.BadParameter, match="apply to crash, panic, stackshot and spindump reports only"):
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
