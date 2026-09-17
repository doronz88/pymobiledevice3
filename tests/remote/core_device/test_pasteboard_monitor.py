import asyncio
import plistlib
from collections.abc import AsyncGenerator
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.remote.core_device import pasteboard_service
from pymobiledevice3.remote.core_device.pasteboard_service import (
    AUTONOTIFY_COMMAND,
    PASTEBOARD_CHANGED_NOTIFICATION,
    POLICY_ALL_PROMISED,
    POLICY_ALL_RESOLVED,
    POLICY_PROMISE_SECONDARY,
    PULL_COMMAND,
    SET_COMMAND,
    PasteboardContent,
    PasteboardMonitor,
    data_item,
    read_pasteboard,
    text_item,
)
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

PASTEBOARD_SERVICE = "com.apple.coredevice.pasteboardservice"


class FakeDevice:
    """Mimics the device: a pasteboard with a change count, and the Darwin notification posted on every change."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self.change_count = 0
        self.notifications: asyncio.Queue[Optional[str]] = asyncio.Queue()
        self.name_set_replies = True
        self.full_pull_hangs = False
        # Cleared while the daemon is busy resolving a rich copy: requests wait their turn.
        self.idle = asyncio.Event()
        self.idle.set()

    def copy(self, *items: dict[str, Any]) -> None:
        """Something was copied on the device."""
        self.items = list(items)
        self.change_count += 1
        self.notifications.put_nowait(PASTEBOARD_CHANGED_NOTIFICATION)

    def snapshot(self, policy: Optional[dict[str, Any]], with_metadata: bool = True) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        for item in self.items:
            if policy == POLICY_ALL_PROMISED:
                inline = []
            elif policy == POLICY_PROMISE_SECONDARY:
                inline = item["types"][:1]
            else:
                inline = item["types"]
            items.append({
                "types": item["types"],
                "data": {uti: (item["data"][uti] if uti in inline else {}) for uti in item["types"]},
            })
        pasteboard: dict[str, Any] = {"items": items}
        if with_metadata:
            pasteboard["metadata"] = {"pasteboardName": "general", "nonce": "N", "changeCount": self.change_count}
        return {"pasteboard": pasteboard}


class FakeConnection:
    """One pasteboard-service connection; like dtpasteboardd, good for a single reply."""

    def __init__(self, device: FakeDevice) -> None:
        self.device = device
        self.sent: list[dict[str, Any]] = []
        self.closed = False

    async def connect(self) -> None:
        pass

    async def send_request(self, data: dict[str, Any], wanting_reply: bool = False) -> None:
        assert not (wanting_reply and self.sent), "a second reply-wanting request aborts dtpasteboardd"
        self.sent.append(data)

    async def receive_response(self) -> dict[str, Any]:
        data = self.sent[-1]
        await self.device.idle.wait()
        if data["command"] == SET_COMMAND:
            self.device.copy(*data["items"])
            return {"command": "SET_REPLY", **self.device.snapshot(POLICY_ALL_PROMISED, self.device.name_set_replies)}
        assert data["command"] == PULL_COMMAND
        if self.device.full_pull_hangs and data["dataPolicy"] == POLICY_ALL_RESOLVED:
            await asyncio.sleep(3600)
        return {"command": "PULL_REPLY", **self.device.snapshot(data["dataPolicy"])}

    async def send_receive_request(self, data: dict[str, Any]) -> dict[str, Any]:
        await self.send_request(data, wanting_reply=True)
        return await self.receive_response()

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
    def __init__(self, monkeypatch: pytest.MonkeyPatch, allow_full_pull: bool = False) -> None:
        self.device = FakeDevice()
        self.connections: list[FakeConnection] = []
        self.observed: list[list[str]] = []  # names observed, per notification connection
        self.received: list[str] = []
        self.images: list[tuple[str, bytes]] = []
        self.changed = asyncio.Event()
        harness = self

        def _start_remote_service(_rsd: RemoteServiceDiscoveryService, _name: str) -> RemoteXPCConnection:
            connection = FakeConnection(self.device)
            self.connections.append(connection)
            return cast(RemoteXPCConnection, connection)

        class FakeNotificationProxy:
            def __init__(self, _rsd: RemoteServiceDiscoveryService) -> None:
                self.names: list[str] = []

            async def __aenter__(self) -> "FakeNotificationProxy":
                harness.observed.append(self.names)
                return self

            async def __aexit__(self, *_exc: object) -> None:
                pass

            async def notify_register_dispatch(self, name: str) -> None:
                self.names.append(name)

            async def receive_notification(self) -> AsyncGenerator[dict[str, Any], None]:
                while True:
                    name = await harness.device.notifications.get()
                    if name is None:
                        raise ConnectionResetError("notification proxy went away")
                    yield {"Command": "RelayNotification", "Name": name}

        monkeypatch.setattr(RemoteServiceDiscoveryService, "start_remote_service", _start_remote_service)
        monkeypatch.setattr(pasteboard_service, "NotificationProxyService", FakeNotificationProxy)
        self.monitor = PasteboardMonitor(
            _make_rsd(), self._on_change, reconnect_delay=0.01, allow_full_pull=allow_full_pull
        )

    def _on_change(self, content: PasteboardContent) -> None:
        if content.text is not None:
            self.received.append(content.text)
        if content.image is not None and content.image_uti is not None:
            self.images.append((content.image_uti, content.image))
        self.changed.set()

    @property
    def pulls(self) -> list[dict[str, Any]]:
        return [m["dataPolicy"] for c in self.connections for m in c.sent if m["command"] == PULL_COMMAND]

    async def started(self) -> None:
        """Start the monitor and wait until it took its baseline look at the pasteboard."""
        await self.monitor.start()
        await self.wait_for_pulls(1)

    async def wait_for_change(self) -> None:
        await asyncio.wait_for(self.changed.wait(), 2)
        self.changed.clear()

    async def wait_for_pulls(self, count: int) -> None:
        async def _poll() -> None:
            while len(self.pulls) < count or not self.connections[-1].closed:
                await asyncio.sleep(0.005)

        await asyncio.wait_for(_poll(), 2)


# What Notes publishes for copied text: plain text first, then rich types -- one of which
# (public.rtf) the pasteboard daemon needs a minute to give up on.
def _notes_text_copy(text: str) -> dict[str, Any]:
    types = ["public.utf8-plain-text", "com.apple.notes.richtext", "com.apple.webarchive", "public.html", "public.rtf"]
    return {"types": types, "data": {uti: {"data": text.encode()} for uti in types}}


# A picture copied in Notes: a newline as plain text, the image inside the web archive.
def _notes_picture_copy() -> dict[str, Any]:
    return {
        "types": ["public.utf8-plain-text", "com.apple.webarchive"],
        "data": {
            "public.utf8-plain-text": {"data": b"\n"},
            "com.apple.webarchive": {"data": _web_archive(("image/png", b"\x89PNGnotes"))},
        },
    }


@pytest.mark.asyncio
async def test_watches_the_notification_instead_of_subscribing(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.started()
    try:
        assert harness.observed == [[PASTEBOARD_CHANGED_NOTIFICATION]]
        # An AUTONOTIFY subscriber makes the daemon resolve every representation on every change.
        assert all(m["command"] != AUTONOTIFY_COMMAND for c in harness.connections for m in c.sent)
    finally:
        await harness.monitor.stop()
    assert all(c.closed for c in harness.connections)


@pytest.mark.asyncio
async def test_device_copy_reaches_the_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.started()
    try:
        harness.device.copy(text_item("copied on device"))
        await harness.wait_for_change()
        assert harness.received == ["copied on device"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_rich_copy_is_read_without_resolving_every_representation(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    harness.device.full_pull_hangs = True
    await harness.started()
    try:
        harness.device.copy(_notes_text_copy("from notes"))
        await harness.wait_for_change()
        assert harness.received == ["from notes"]
        assert harness.pulls == [POLICY_ALL_PROMISED, POLICY_PROMISE_SECONDARY]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_content_held_at_start_is_not_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    harness.device.items = [text_item("old")]
    harness.device.change_count = 7
    await harness.started()
    try:
        harness.device.notifications.put_nowait(PASTEBOARD_CHANGED_NOTIFICATION)  # nothing new behind it
        await harness.wait_for_pulls(2)
        harness.device.copy(text_item("new"))
        await harness.wait_for_change()
        assert harness.received == ["new"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_own_set_is_not_echoed_back(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.started()
    try:
        await harness.monitor.set_text("from host")
        await harness.wait_for_pulls(2)
        assert harness.device.items == [text_item("from host")]
        # Past the echo window only the change id of the SET_REPLY tells it apart.
        harness.monitor._recent_host_content.clear()  # pyright: ignore[reportPrivateUsage]
        harness.device.notifications.put_nowait(PASTEBOARD_CHANGED_NOTIFICATION)
        harness.device.copy(text_item("from device"))
        await harness.wait_for_change()
        assert harness.received == ["from device"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_own_set_is_recognised_by_content_when_its_reply_names_no_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(monkeypatch)
    harness.device.name_set_replies = False
    await harness.started()
    try:
        await harness.monitor.set_text("first")
        await harness.monitor.set_text("second")
        await harness.wait_for_pulls(3)  # both landed and were looked at
        harness.device.copy(text_item("from device"))
        await harness.wait_for_change()
        assert harness.received == ["from device"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_set_does_not_wait_for_a_busy_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.started()
    try:
        harness.device.idle.clear()  # a minute-long resolve of a rich copy is in progress
        await asyncio.wait_for(harness.monitor.set_text("from host"), 1)
        assert harness.device.items == []
        harness.monitor._recent_host_content.clear()  # pyright: ignore[reportPrivateUsage]  # ...a minute later
        harness.device.idle.set()
        await harness.wait_for_pulls(2)
        assert harness.device.items == [text_item("from host")]
        harness.device.copy(text_item("from device"))
        await harness.wait_for_change()
        assert harness.received == ["from device"]
    finally:
        await harness.monitor.stop()
    assert all(c.closed for c in harness.connections)


@pytest.mark.asyncio
async def test_device_image_copy_reaches_the_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.started()
    try:
        harness.device.copy(data_item("public.jpeg", b"\xff\xd8jpeg"))
        await harness.wait_for_change()
        assert harness.images == [("public.jpeg", b"\xff\xd8jpeg")]
        assert harness.received == []
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_own_image_is_not_echoed_back(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.started()
    try:
        await harness.monitor.set_image(b"\x89PNGhost")
        await harness.wait_for_pulls(2)
        assert harness.device.items == [data_item("public.png", b"\x89PNGhost")]
        harness.device.copy(data_item("public.png", b"\x89PNGdevice"))
        await harness.wait_for_change()
        assert harness.images == [("public.png", b"\x89PNGdevice")]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_unshareable_copy_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.started()
    try:
        harness.device.copy(data_item("com.adobe.pdf", b"%PDF"))
        harness.device.copy(text_item("text after the pdf"))
        await harness.wait_for_change()
        assert harness.received == ["text after the pdf"]
        assert harness.images == []
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_one_change_announced_twice_is_reported_once(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.started()
    try:
        harness.device.copy(text_item("once"))
        harness.device.notifications.put_nowait(PASTEBOARD_CHANGED_NOTIFICATION)
        await harness.wait_for_pulls(3)
        assert harness.received == ["once"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_copy_made_while_the_connection_was_down_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    await harness.started()
    try:
        harness.device.items = [text_item("while away")]
        harness.device.change_count += 1
        harness.device.notifications.put_nowait(None)  # the connection drops; its notification is lost
        await harness.wait_for_change()
        assert harness.received == ["while away"]
        assert len(harness.observed) == 2
        harness.device.copy(text_item("after reconnect"))
        await harness.wait_for_change()
        assert harness.received == ["while away", "after reconnect"]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_picture_in_a_secondary_type_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    harness.device.full_pull_hangs = True
    await harness.started()
    try:
        harness.device.copy(_notes_picture_copy())
        harness.device.copy(text_item("text after the picture"))
        await harness.wait_for_change()
        assert harness.received == ["text after the picture"]
        assert harness.images == []
        assert POLICY_ALL_RESOLVED not in harness.pulls
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_picture_in_a_secondary_type_is_fetched_when_a_full_pull_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = Harness(monkeypatch, allow_full_pull=True)
    await harness.started()
    try:
        harness.device.copy(_notes_picture_copy())
        await harness.wait_for_change()
        assert harness.images == [("public.png", b"\x89PNGnotes")]
        assert harness.pulls[1:] == [POLICY_PROMISE_SECONDARY, POLICY_ALL_RESOLVED]
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_unanswered_full_pull_does_not_stop_the_monitor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pasteboard_service, "_FULL_PULL_TIMEOUT_SECONDS", 0.05)
    harness = Harness(monkeypatch, allow_full_pull=True)
    harness.device.full_pull_hangs = True
    await harness.started()
    try:
        harness.device.copy(_notes_picture_copy())
        harness.device.copy(text_item("still alive"))
        await harness.wait_for_change()
        assert harness.received == ["still alive"]
        assert len(harness.observed) == 1
    finally:
        await harness.monitor.stop()


@pytest.mark.asyncio
async def test_read_pasteboard_returns_the_primary_text_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(monkeypatch)
    harness.device.full_pull_hangs = True
    harness.device.items = [_notes_text_copy("from notes")]
    _, content = await asyncio.wait_for(read_pasteboard(_make_rsd()), 2)
    assert content.text == "from notes"
    assert harness.pulls == [POLICY_PROMISE_SECONDARY]


def _web_archive(*subresources: tuple[str, bytes]) -> bytes:
    return plistlib.dumps(
        {
            "WebMainResource": {"WebResourceData": b"<html></html>", "WebResourceMIMEType": "text/html"},
            "WebSubresources": [
                {"WebResourceData": data, "WebResourceMIMEType": mime, "WebResourceURL": "file:///x"}
                for mime, data in subresources
            ],
        },
        fmt=plistlib.FMT_BINARY,
    )


def test_rich_copy_yields_the_image_inside_its_web_archive() -> None:
    # What Notes publishes for a copied picture: no image type, a newline as plain text.
    snapshot = {
        "pasteboard": {
            "items": [
                {
                    "types": ["public.utf8-plain-text", "com.apple.webarchive"],
                    "data": {
                        "public.utf8-plain-text": {"data": b"\n"},
                        "com.apple.webarchive": {
                            "data": _web_archive(("text/css", b"p{}"), ("image/png", b"\x89PNGnotes"))
                        },
                    },
                }
            ]
        }
    }
    content = PasteboardContent.from_snapshot(snapshot)
    assert (content.image_uti, content.image) == ("public.png", b"\x89PNGnotes")
    assert content.image_mime == "image/png"
    assert content.text is None


def test_direct_image_type_wins_over_the_web_archive() -> None:
    snapshot = {
        "items": [
            {
                "types": ["public.jpeg", "com.apple.webarchive"],
                "data": {
                    "public.jpeg": {"data": b"\xff\xd8direct"},
                    "com.apple.webarchive": {"data": _web_archive(("image/png", b"\x89PNGarchive"))},
                },
            }
        ]
    }
    assert PasteboardContent.from_snapshot(snapshot).image == b"\xff\xd8direct"


def test_text_next_to_an_image_is_kept_when_it_says_something() -> None:
    snapshot = {
        "items": [
            {
                "types": ["public.utf8-plain-text", "public.png"],
                "data": {"public.utf8-plain-text": {"data": b"caption"}, "public.png": {"data": b"\x89PNG"}},
            }
        ]
    }
    content = PasteboardContent.from_snapshot(snapshot)
    assert (content.text, content.image) == ("caption", b"\x89PNG")


def test_garbage_web_archive_is_ignored() -> None:
    snapshot = {"items": [{"types": ["com.apple.webarchive"], "data": {"com.apple.webarchive": {"data": b"nope"}}}]}
    assert not PasteboardContent.from_snapshot(snapshot)
