import asyncio
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.remote.core_device.pasteboard_service import (
    AUTONOTIFY_COMMAND,
    PUSH_COMMAND,
    SET_COMMAND,
    PasteboardMonitor,
    text_item,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

PASTEBOARD_SERVICE = "com.apple.coredevice.pasteboardservice"


def _push(text: str) -> dict[str, Any]:
    return {"command": PUSH_COMMAND, "pasteboard": {"items": [text_item(text)]}}


class FakeConnection:
    """Mimics dtpasteboardd: an AUTONOTIFY subscriber gets a PUSH for every change, including its own SET."""

    def __init__(self) -> None:
        self.sent: list[tuple[dict[str, Any], bool]] = []
        self.inbox: asyncio.Queue[Optional[dict[str, Any]]] = asyncio.Queue()
        self.closed = False

    async def connect(self) -> None:
        pass

    async def send_request(self, data: dict[str, Any], wanting_reply: bool = False) -> None:
        self.sent.append((data, wanting_reply))
        if data["command"] == SET_COMMAND:
            self.inbox.put_nowait({"command": PUSH_COMMAND, "pasteboard": {"items": data["items"]}})

    async def receive_response(self) -> dict[str, Any]:
        message = await self.inbox.get()
        if message is None:
            raise ConnectionResetError("daemon went away")
        return message

    async def close(self) -> None:
        self.closed = True


def _make_rsd() -> RemoteServiceDiscoveryService:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {
        "Properties": {"OSVersion": "26.0"},
        "Services": {PASTEBOARD_SERVICE: {"Port": "1024"}},
    }
    return rsd


class Harness:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.connections: list[FakeConnection] = []
        self.received: list[str] = []
        self.changed = asyncio.Event()

        def _start_remote_service(_rsd: RemoteServiceDiscoveryService, _name: str) -> RemoteXPCConnection:
            connection = FakeConnection()
            self.connections.append(connection)
            return cast(RemoteXPCConnection, connection)

        monkeypatch.setattr(RemoteServiceDiscoveryService, "start_remote_service", _start_remote_service)
        self.monitor = PasteboardMonitor(_make_rsd(), self._on_text, reconnect_delay=0.01)

    def _on_text(self, text: str) -> None:
        self.received.append(text)
        self.changed.set()

    async def wait_for_text(self) -> None:
        await asyncio.wait_for(self.changed.wait(), 2)
        self.changed.clear()

    async def wait_for_connections(self, count: int) -> None:
        async def _poll() -> None:
            while len(self.connections) < count or not self.connections[count - 1].sent:
                await asyncio.sleep(0.005)

        await asyncio.wait_for(_poll(), 2)


@pytest.mark.asyncio
async def test_subscribes_without_asking_for_a_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.monitor.start()
    try:
        await harness.wait_for_connections(1)
        message, wanting_reply = harness.connections[0].sent[0]
        assert message == {"command": AUTONOTIFY_COMMAND, "pasteboardName": "general", "enable": True}
        # A second reply-wanting request on one connection aborts dtpasteboardd.
        assert wanting_reply is False
    finally:
        await harness.monitor.stop()
    assert harness.connections[0].closed


@pytest.mark.asyncio
async def test_device_copy_reaches_the_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.monitor.start()
    try:
        await harness.wait_for_connections(1)
        harness.connections[0].inbox.put_nowait(_push("copied on device"))
        await harness.wait_for_text()
        assert harness.received == ["copied on device"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_own_set_is_not_echoed_back(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.monitor.start()
    try:
        await harness.wait_for_connections(1)
        await harness.monitor.set_text("from host")
        set_message, wanting_reply = harness.connections[0].sent[-1]
        assert set_message["command"] == SET_COMMAND
        assert wanting_reply is False
        harness.connections[0].inbox.put_nowait(_push("from device"))
        await harness.wait_for_text()
        assert harness.received == ["from device"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_stale_echo_of_a_burst_is_not_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.monitor.start()
    try:
        await harness.wait_for_connections(1)
        # The fake echoes every SET; the echo of "first" is read after "second" was already sent.
        await harness.monitor.set_text("first")
        await harness.monitor.set_text("second")
        harness.connections[0].inbox.put_nowait(_push("from device"))
        await harness.wait_for_text()
        assert harness.received == ["from device"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_non_text_push_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.monitor.start()
    try:
        await harness.wait_for_connections(1)
        harness.connections[0].inbox.put_nowait({
            "command": PUSH_COMMAND,
            "pasteboard": {"items": [{"types": ["public.png"], "data": {"public.png": {"data": b"\x89PNG"}}}]},
        })
        harness.connections[0].inbox.put_nowait(_push("text after image"))
        await harness.wait_for_text()
        assert harness.received == ["text after image"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_resubscribes_after_the_connection_drops(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.monitor.start()
    try:
        await harness.wait_for_connections(1)
        harness.connections[0].inbox.put_nowait(None)
        await harness.wait_for_connections(2)
        assert harness.connections[1].sent[0][0]["command"] == AUTONOTIFY_COMMAND
        harness.connections[1].inbox.put_nowait(_push("after reconnect"))
        await harness.wait_for_text()
        assert harness.received == ["after reconnect"]
    finally:
        await harness.monitor.stop()
