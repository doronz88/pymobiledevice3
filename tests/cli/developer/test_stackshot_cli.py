import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional, cast

import pytest
import typer
from apple_symbols import DeviceSupportSymbols, KernelImage, KernelSymbols, SymbolImage
from pycrashreport.symbols import SymbolServerError

from pymobiledevice3.cli.developer.dvt import core_profile_session
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
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
    monkeypatch.setattr(core_profile_session, "find_device_support_symbols", lambda *_args: None)


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


class _ServerSymbols:
    """Symbols of a symbol server, which names one function of one image of the shared cache."""

    has_shared_cache_images = True
    shared_cache_base = 0x180000000

    def __init__(self) -> None:
        self.images = [SymbolImage("/usr/lib/libfoo.dylib", "11111111-2222-3333-4444-555555555555", 0x180000000, 0x18)]

    def image_by_uuid(self, image_uuid: str) -> Optional[SymbolImage]:
        return next((image for image in self.images if image.uuid == image_uuid), None)

    def image_by_address(self, address: int) -> Optional[SymbolImage]:
        return next((image for image in self.images if image.vmaddr <= address < image.vmaddr + image.vmsize), None)

    def symbolicate(self, image: SymbolImage, address: int) -> Optional[tuple[str, int]]:
        return ("foo", address - image.vmaddr)


class _ServerKernelSymbols:
    """Kernel symbols of a symbol server, which names one function of the kernel."""

    has_symbols = True

    def __init__(self) -> None:
        self.images = [KernelImage("com.apple.kernel", KERNEL_UUID, 0xFFFFFFF007004000)]

    def image_by_uuid(self, image_uuid: str) -> Optional[KernelImage]:
        return next((image for image in self.images if image.uuid == image_uuid), None)

    def symbolicate(self, address: int) -> Optional[tuple[str, int]]:
        return ("panic", address - self.images[0].text_exec)


SERVER = "http://server.invalid:3993"
KERNEL_UUID = "99999999-8888-7777-6666-555555555555"


@pytest.fixture
def symbol_server(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, ...]]:
    asked: list[tuple[object, ...]] = []

    def connect(server: str) -> str:
        asked.append((server,))
        return server

    def userland_symbols(client: object, product_type: str, build_version: str) -> _ServerSymbols:
        asked.append((client, product_type, build_version))
        return _ServerSymbols()

    monkeypatch.setattr(core_profile_session.symbol_server_client, "connect", connect)

    def kernel_symbols_of_build(
        client: object, product_type: str, build_version: str, image_uuids: list[str]
    ) -> Optional[_ServerKernelSymbols]:
        asked.append((client, product_type, build_version, image_uuids))
        return _ServerKernelSymbols() if KERNEL_UUID in image_uuids else None

    monkeypatch.setattr(core_profile_session.symbol_server_client, "userland_symbols", userland_symbols)
    monkeypatch.setattr(core_profile_session.symbol_server_client, "kernel_symbols_of_build", kernel_symbols_of_build)
    return asked


def test_stackshot_symbolicates_with_a_symbol_server(
    capsys: pytest.CaptureFixture[str], caplog: Any, symbol_server: list[tuple[object, ...]]
) -> None:
    core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, symbol_server=SERVER)

    assert symbol_server == [(SERVER,), (SERVER, "iPhone15,2", "20A362"), (SERVER, "iPhone15,2", "20A362", [])]
    assert capsys.readouterr().out.splitlines() == [
        "launchd [1]  1 threads",
        "  Thread 7",
        "      0  libfoo.dylib  foo + 0x10",
        "",
        "SpringBoard [42]  1 threads",
        "  Thread 8",
        # outside what the server holds
        "      0  dyld_shared_cache  0x20",
        "",
    ]
    # the device support of this host is not missed once the server names the frames
    assert "fetch-symbols download" not in caplog.text


def test_stackshot_leaves_what_the_symbol_server_does_not_name_to_this_host(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    symbol_server: list[tuple[object, ...]],
    tmp_path: Path,
) -> None:
    host_image = SymbolImage("/usr/lib/libbar.dylib", "66666666-7777-8888-9999-aaaaaaaaaaaa", 0x180000018, 0x100)

    class HostSymbols(_ServerSymbols):
        def __init__(self) -> None:
            self.images = [host_image]

        def symbolicate(self, image: SymbolImage, address: int) -> Optional[tuple[str, int]]:
            return ("bar", address - image.vmaddr)

    monkeypatch.setattr(
        core_profile_session.DeviceSupportSymbols,
        "load",
        classmethod(lambda cls, root: cast(DeviceSupportSymbols, HostSymbols())),
    )

    core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, symbols=tmp_path, symbol_server=SERVER)

    out = capsys.readouterr().out
    assert "      0  libfoo.dylib  foo + 0x10" in out
    assert "      0  libbar.dylib  bar + 0x8" in out


def test_stackshot_exits_nonzero_when_the_symbol_server_cannot_be_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    def connect(server: str) -> object:
        raise SymbolServerError(f"Reaching {server} failed")

    monkeypatch.setattr(core_profile_session.symbol_server_client, "connect", connect)

    with pytest.raises(typer.Exit) as exc_info:
        core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, symbol_server=SERVER)

    assert exc_info.value.exit_code == 1


def test_stackshot_symbolicates_kernel_frames_with_a_symbol_server(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, symbol_server: list[tuple[object, ...]]
) -> None:
    # a stackshot tells its kernel images, by which the server finds the kernelcache of the device
    monkeypatch.setitem(
        cast(dict[int, Any], STACKSHOT["task_snapshots"]),
        0,
        {
            "task_snapshot": {"ts_pid": 0, "ts_p_comm": "kernel_task"},
            "dyld_load_info_text_exec": [{"imageLoadAddress": 0xFFFFFFF010000000, "imageUUID": KERNEL_UUID}],
            "thread_snapshots": {3: {"kernel_stack_frames": [{"lr": 0xFFFFFFF010000020}]}},
        },
    )

    core_profile_session.stackshot(service_provider=SERVICE_PROVIDER, symbol_server=SERVER, process="kernel_task")

    assert symbol_server[-1] == (SERVER, "iPhone15,2", "20A362", [KERNEL_UUID])
    assert capsys.readouterr().out.splitlines() == [
        "kernel_task [0]  1 threads",
        "  Thread 3",
        "      0  com.apple.kernel  panic + 0x20  (kernel)",
        "",
    ]
