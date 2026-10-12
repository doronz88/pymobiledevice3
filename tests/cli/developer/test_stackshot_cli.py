import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import typer

from pymobiledevice3.cli.developer.dvt import core_profile_session
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.dvt.instruments.kernel_symbols import KernelSymbols
from pymobiledevice3.services.dvt.instruments.stackshot import StackshotFrame, StackshotProcess, StackshotThread

pytestmark = [pytest.mark.cli]

SERVICE_PROVIDER = cast(
    LockdownServiceProvider,
    SimpleNamespace(product_type="iPhone15,2", product_version="16.0", product_build_version="20A362"),
)
STACKSHOT = {
    "shared_cache_dyld_load_info": {
        "imageLoadAddress": 0,
        "imageUUID": "82daa8c7-ae0f-3010-a3b0-acea8bbb0af9",
        "imageSlidBaseAddress": 0x180000000,
    },
    "task_snapshots": {
        1: {
            "task_snapshot": {"ts_pid": 1, "ts_p_comm": "launchd"},
            "thread_snapshots": {7: {"user_stack_frames": [{"lr": 0x180000010}]}},
        },
        42: {
            "task_snapshot": {"ts_pid": 42, "ts_p_comm": "SpringBoard"},
            "thread_snapshots": {8: {"user_stack_frames": [{"lr": 0x180000020}]}},
        },
    },
}


class _AsyncContext:
    async def __aenter__(self) -> Any:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None


@pytest.fixture(autouse=True)
def fake_device(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class FakeCoreProfileSessionTap(_AsyncContext):
        def __init__(self, dvt: object, config: object) -> None:
            pass

        async def get_stackshot(self) -> Any:
            return STACKSHOT

    monkeypatch.setattr(core_profile_session, "DvtProvider", lambda _service_provider: _AsyncContext())
    monkeypatch.setattr(core_profile_session, "CoreProfileSessionTap", FakeCoreProfileSessionTap)
    # No device support exists for the fake device
    monkeypatch.setattr(core_profile_session, "find_device_support_symbols", lambda _service_provider: None)


def test_format_stackshot() -> None:
    process = StackshotProcess(
        pid=42,
        name="SpringBoard",
        task_size=5 * 1024 * 1024,
        max_resident_size=1536,
        suspend_count=1,
        threads=[
            StackshotThread(
                thread_id=514,
                name="worker",
                dispatch_queue="com.apple.main-thread",
                states=["waiting"],
                qos="user-interactive",
                sched_priority=47,
                user_usec=1500000,
                system_usec=250000,
                wait_event=0x1234,
                continuation="kqueue_scan_continue",
                frames=[
                    StackshotFrame(address=0xFFFFFE0007004020, kernel=True, image="kernel-uuid", image_offset=0x20),
                    StackshotFrame(
                        address=0x180010208,
                        image="libfoo.dylib",
                        image_offset=0x208,
                        symbol="bar",
                        symbol_offset=0x1A8,
                    ),
                    StackshotFrame(address=0x100004A38, image="app-uuid", image_offset=0x4A38),
                    StackshotFrame(address=0x1234),
                ],
            ),
            StackshotThread(thread_id=515),
        ],
    )

    assert core_profile_session.format_stackshot([process]).splitlines() == [
        "SpringBoard [42]  size 5.0 MB  max rss 1.5 KB  suspended x1  2 threads",
        "  Thread 514  worker  com.apple.main-thread  waiting  user-interactive  pri 47"
        "  cpu 1.500s user, 0.250s sys  wait 0x1234  continuation kqueue_scan_continue",
        "      0  kernel-uuid   0x20  (kernel)",
        "      1  libfoo.dylib  bar + 0x1a8",
        "      2  app-uuid      0x4a38",
        "      3  0x1234",
        "  Thread 515",
    ]


def test_stackshot_prints_call_stacks_by_default(capsys: pytest.CaptureFixture[str], caplog: Any) -> None:
    core_profile_session.stackshot(service_provider=SERVICE_PROVIDER)

    assert capsys.readouterr().out.splitlines() == [
        "launchd [1]  1 threads",
        "  Thread 7",
        "      0  dyld_shared_cache  0x10",
        "",
        "SpringBoard [42]  1 threads",
        "  Thread 8",
        "      0  dyld_shared_cache  0x20",
        "",
    ]
    assert "fetch-symbols download" in caplog.text


@pytest.mark.parametrize("process", ["42", "SpringBoard"])
def test_stackshot_filters_by_process(capsys: pytest.CaptureFixture[str], process: str) -> None:
    core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, process=process)

    assert capsys.readouterr().out.splitlines()[0] == "SpringBoard [42]  1 threads"


def test_stackshot_json_prints_the_raw_stackshot(capsys: pytest.CaptureFixture[str], caplog: Any) -> None:
    core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, json_output=True)

    assert json.loads(capsys.readouterr().out) == json.loads(json.dumps(STACKSHOT))
    assert "fetch-symbols" not in caplog.text


def test_stackshot_out_writes_the_raw_stackshot(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    out = tmp_path / "stackshot.json"

    core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, out=out)

    assert json.loads(out.read_text()) == json.loads(json.dumps(STACKSHOT))
    assert capsys.readouterr().out == ""


def test_stackshot_kernel_signatures_require_a_kernelcache(tmp_path: Path) -> None:
    with pytest.raises(typer.BadParameter):
        core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, kernel_signatures=tmp_path)


def test_stackshot_warns_about_a_kernelcache_the_device_does_not_run(
    capsys: pytest.CaptureFixture[str], caplog: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    kernelcache = tmp_path / "kernelcache"
    monkeypatch.setattr(
        core_profile_session.KernelSymbols,
        "load",
        classmethod(lambda cls, kernelcache, signatures=None: KernelSymbols([], {}, [])),
    )

    core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, kernelcache=kernelcache)

    assert "is not the kernelcache the device runs" in caplog.text
    assert capsys.readouterr().out.startswith("launchd [1]")


def test_stackshot_exits_nonzero_when_the_kernelcache_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def load(cls: object, kernelcache: Path, signatures: object = None) -> KernelSymbols:
        raise FileNotFoundError("ipsw")

    monkeypatch.setattr(core_profile_session.KernelSymbols, "load", classmethod(load))

    with pytest.raises(typer.Exit) as exc_info:
        core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, kernelcache=tmp_path / "kernelcache")

    assert exc_info.value.exit_code == 1
