import asyncio
from typing import Callable, ClassVar

import pytest

from pymobiledevice3.remote.core_device import screen_stream
from pymobiledevice3.remote.core_device.pasteboard_service import PasteboardContent
from pymobiledevice3.remote.core_device.screen_stream import ScreenStreamServer
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class FakeMonitor:
    instances: ClassVar[list["FakeMonitor"]] = []

    def __init__(self, _rsd: RemoteServiceDiscoveryService, on_change: Callable[[PasteboardContent], None]) -> None:
        self.on_change = on_change
        self.started = False
        self.stopped = False
        self.sent: list[str] = []
        self.sent_images: list[bytes] = []
        FakeMonitor.instances.append(self)

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def set_text(self, text: str) -> None:
        self.sent.append(text)

    async def set_image(self, data: bytes) -> None:
        self.sent_images.append(data)


@pytest.fixture
def make_server(monkeypatch: pytest.MonkeyPatch) -> Callable[[], ScreenStreamServer]:
    FakeMonitor.instances = []
    monkeypatch.setattr(screen_stream, "PasteboardMonitor", FakeMonitor)
    monkeypatch.setattr(screen_stream, "_CLIPBOARD_POLL_SECONDS", 0.05)
    monkeypatch.setattr(screen_stream, "_CLIPBOARD_IDLE_SECONDS", 0.05)

    # Built by the test itself, inside its event loop, like the CLI does: on Python 3.9 an
    # asyncio.Event belongs to the loop that was current when it was constructed.
    def _make() -> ScreenStreamServer:
        return ScreenStreamServer(RemoteServiceDiscoveryService(("127.0.0.1", 0)))

    return _make


@pytest.mark.asyncio
async def test_first_poll_starts_the_monitor_and_reports_nothing(make_server: Callable[[], ScreenStreamServer]) -> None:
    server = make_server()
    assert await server._clipboard_wait(None) == {"seq": 0, "text": None, "image": None}
    assert len(FakeMonitor.instances) == 1
    assert FakeMonitor.instances[0].started


@pytest.mark.asyncio
async def test_poll_returns_as_soon_as_the_device_copies(
    make_server: Callable[[], ScreenStreamServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    server = make_server()
    seq = (await server._clipboard_wait(None))["seq"]
    monkeypatch.setattr(screen_stream, "_CLIPBOARD_POLL_SECONDS", 5.0)
    poll = asyncio.create_task(server._clipboard_wait(seq))
    await asyncio.sleep(0.01)
    assert not poll.done()
    FakeMonitor.instances[0].on_change(PasteboardContent(text="copied on device"))
    assert await asyncio.wait_for(poll, 1) == {"seq": seq + 1, "text": "copied on device", "image": None}


@pytest.mark.asyncio
async def test_poll_times_out_with_no_text(make_server: Callable[[], ScreenStreamServer]) -> None:
    server = make_server()
    seq = (await server._clipboard_wait(None))["seq"]
    assert await server._clipboard_wait(seq) == {"seq": seq, "text": None, "image": None}


@pytest.mark.asyncio
async def test_copy_made_between_polls_is_not_lost(make_server: Callable[[], ScreenStreamServer]) -> None:
    server = make_server()
    seq = (await server._clipboard_wait(None))["seq"]
    FakeMonitor.instances[0].on_change(PasteboardContent(text="while the viewer was re-polling"))
    assert await server._clipboard_wait(seq) == {
        "seq": seq + 1,
        "text": "while the viewer was re-polling",
        "image": None,
    }


@pytest.mark.asyncio
async def test_image_copy_is_announced_with_type_and_size(make_server: Callable[[], ScreenStreamServer]) -> None:
    server = make_server()
    seq = (await server._clipboard_wait(None))["seq"]
    FakeMonitor.instances[0].on_change(PasteboardContent(image=b"\xff\xd8jpeg", image_uti="public.jpeg"))
    assert await server._clipboard_wait(seq) == {
        "seq": seq + 1,
        "text": None,
        "image": {"type": "image/jpeg", "size": 6},
    }


@pytest.mark.asyncio
async def test_host_content_goes_through_the_running_monitor(make_server: Callable[[], ScreenStreamServer]) -> None:
    server = make_server()
    await server._clipboard_wait(None)
    await server._clipboard_set(text="from host")
    await server._clipboard_set(image=b"\x89PNG")
    assert FakeMonitor.instances[0].sent == ["from host"]
    assert FakeMonitor.instances[0].sent_images == [b"\x89PNG"]


@pytest.mark.asyncio
async def test_monitor_stops_once_no_viewer_polls(make_server: Callable[[], ScreenStreamServer]) -> None:
    server = make_server()
    await server._clipboard_wait(None)
    monitor = FakeMonitor.instances[0]
    await asyncio.sleep(0.15)
    assert monitor.stopped
    assert server._clipboard_monitor is None
    # A returning viewer gets a fresh monitor.
    await server._clipboard_wait(None)
    assert len(FakeMonitor.instances) == 2
