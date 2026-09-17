"""
Read/write the device pasteboard via the ``com.apple.coredevice.pasteboardservice``
RemoteXPC service (feature ``com.apple.coredevice.feature.pasteboard``).

Wire format reversed from Apple's ``CoreDeviceUtilities`` / ``CoreDevice``
frameworks on macOS:

* The service speaks XPC dicts directly (no ``featureIdentifier`` /
  ``messageType`` envelope; the ``command`` field on the message itself drives
  dispatch).
* Eight command verbs exist: ``PULL`` / ``PULL_REPLY`` / ``SET`` / ``SET_REPLY``
  / ``DATA`` / ``PUSH`` / ``AUTONOTIFY`` / ``RESOLVE``. This module implements
  PULL (paste-from-device) and SET with immediate data (copy-to-device, text or
  image). Promise resolution (DATA/RESOLVE) is scaffolded but not yet exposed.
* ``AUTONOTIFY`` is ``{command, pasteboardName, enable: Bool}`` and gets no
  reply. While enabled the device sends a ``PUSH`` (``{command, pasteboard:
  PasteboardSnapshot}``, data inline) for every pasteboard change -- on-device
  copies, a SET from another connection, and a SET from the subscribing
  connection itself (that PUSH arrives *instead of* a ``SET_REPLY``).
* ``dtpasteboardd`` aborts ("Attempted to send non-reply msg on the reply
  channel") on the second reply-wanting request of one connection. PULL needs
  the reply flag to be answered at all, so :meth:`PasteboardService.get` /
  :meth:`PasteboardService.set` are good for one call per connection; only
  flag-less messages can repeat freely.
* A ``PasteboardSnapshot`` carries ``items: [{types: [String], data: {UTI:
  PasteboardItemData}}]`` plus optional ``metadata`` / ``sourceMetadata``.
  ``PasteboardItemData`` on the wire is ``{data: Data}`` for immediate
  items, or ``{isPromised: true, isAvailable: false, size: Int64}`` for
  promised items (Swift property ``immediateData`` is keyed as ``data`` on
  the wire). ``Data`` is a native XPC DATA field (raw bytes), not base64.
* ``PasteboardDataInclusionPolicy`` is a Codable enum encoded as
  ``{"allResolved": {}}`` etc.; ``thresholdData`` carries its limit as
  ``{"thresholdData": {"bytes": Int64}}``. ``allResolved`` carries every
  representation inline, ``promiseSecondary`` only the first (primary) type of
  each item, ``allPromised`` none. ``matchSource`` behaves as ``allResolved`` on
  the device, and ``thresholdData`` loads every representation as well, to learn
  its size (promised entries come back as ``{size: Int64}``).
* Loading representations is where the daemon can stall: it loads them one by
  one on its main actor, and an app may advertise a type it cannot produce. Notes
  does (``public.rtf``: the NSAttributedString conversion fails after ~64 s), so
  any PULL of a Notes copy other than ``allPromised`` / ``promiseSecondary``
  takes ~64 s, and everything else sent to the daemon meanwhile queues behind
  it. There is no request for a single type: a host ``RESOLVE`` (``{command,
  pasteboardName, itemIndex: Int64, type}``, answered by ``{command: "DATA",
  data}``) loads every representation of every item before the one it names.
* An ``AUTONOTIFY`` subscription makes the daemon read every change with
  ``matchSource`` before it sends the PUSH; the subscription's ``dataPolicy`` only
  shapes a second read. So a subscriber hears about a Notes copy a minute late
  and blocks all other requests for that minute -- Apple's own ``devicectl
  device pasteboard monitor`` reports such a copy after 64 s too.
  :class:`PasteboardMonitor` therefore does not subscribe: it watches the
  ``com.apple.pasteboard.notify.changed`` Darwin notification and answers it
  with a ``promiseSecondary`` PULL.
"""

import asyncio
import contextlib
import hashlib
import logging
import plistlib
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, cast

from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type
from pymobiledevice3.services.notification_proxy import NotificationProxyService

logger = logging.getLogger(__name__)

GENERAL_PASTEBOARD = "general"

PULL_COMMAND = "PULL"
PULL_REPLY_COMMAND = "PULL_REPLY"
SET_COMMAND = "SET"
SET_REPLY_COMMAND = "SET_REPLY"
DATA_COMMAND = "DATA"
PUSH_COMMAND = "PUSH"
AUTONOTIFY_COMMAND = "AUTONOTIFY"
RESOLVE_COMMAND = "RESOLVE"

# Darwin notification posted by the device's pasteboard daemon on every change.
PASTEBOARD_CHANGED_NOTIFICATION = "com.apple.pasteboard.notify.changed"

# How long content sent by PasteboardMonitor.set_text() / set_image() is still treated as its own echo.
_ECHO_WINDOW_SECONDS = 3.0
# A full (allResolved) PULL can sit behind the daemon's ~64 s give-up on a representation.
_FULL_PULL_TIMEOUT_SECONDS = 90.0
# Own changes remembered (by change id) to tell their notifications from device copies.
_OWN_CHANGES_KEPT = 16

UTI_UTF8_PLAIN_TEXT = "public.utf8-plain-text"
UTI_PLAIN_TEXT = "public.plain-text"
UTI_TEXT = "public.text"
UTI_URL = "public.url"

# Image UTIs -> MIME type, in the order snapshot_image() prefers them (lossless first).
IMAGE_UTIS: dict[str, str] = {
    "public.png": "image/png",
    "public.jpeg": "image/jpeg",
    "public.heic": "image/heic",
    "public.tiff": "image/tiff",
    "com.compuserve.gif": "image/gif",
    "org.webmproject.webp": "image/webp",
}

# PasteboardDataInclusionPolicy presets.
POLICY_ALL_RESOLVED: dict[str, Any] = {"allResolved": {}}
POLICY_ALL_PROMISED: dict[str, Any] = {"allPromised": {}}
POLICY_MATCH_SOURCE: dict[str, Any] = {"matchSource": {}}
POLICY_PROMISE_SECONDARY: dict[str, Any] = {"promiseSecondary": {}}


def policy_threshold(threshold_bytes: int) -> dict[str, Any]:
    """Inclusion policy: include item data inline if smaller than ``threshold_bytes``, otherwise promise it.

    The daemon has to load every representation to learn its size, so this is as slow as
    ``allResolved`` (see the module docstring).
    """
    return {"thresholdData": {"bytes": XpcInt64Type(threshold_bytes)}}


def text_item(text: str, utis: Optional[list[str]] = None) -> dict[str, Any]:
    """Build a single ``PasteboardItem`` carrying ``text`` under the standard text UTIs."""
    if utis is None:
        utis = [UTI_UTF8_PLAIN_TEXT, UTI_PLAIN_TEXT, UTI_TEXT]
    payload = text.encode("utf-8")
    return {
        "types": utis,
        "data": {uti: {"data": payload} for uti in utis},
    }


def data_item(uti: str, data: bytes) -> dict[str, Any]:
    """Build a single ``PasteboardItem`` carrying raw ``data`` under one ``uti``."""
    return {
        "types": [uti],
        "data": {uti: {"data": data}},
    }


def snapshot_text(snapshot: dict[str, Any]) -> Optional[str]:
    """Best-effort extraction of UTF-8 text from a ``PasteboardSnapshot`` dict.

    Returns ``None`` if the snapshot has no items or no decodable text. Walks
    items in order and picks the first one carrying a text UTI with inline data.
    """
    pasteboard = snapshot.get("pasteboard")
    if isinstance(pasteboard, dict):
        snapshot = cast(dict[str, Any], pasteboard)
    for item in cast(list[dict[str, Any]], snapshot.get("items", []) or []):
        data_map = cast(dict[str, Any], item.get("data") or {})
        for uti in (UTI_UTF8_PLAIN_TEXT, UTI_PLAIN_TEXT, UTI_TEXT):
            datum = data_map.get(uti)
            if not isinstance(datum, dict):
                continue
            raw = cast(dict[str, Any], datum).get("data")
            if not raw:
                continue
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
    return None


UTI_WEB_ARCHIVE = "com.apple.webarchive"


def _inline_data(data_map: dict[str, Any], uti: str) -> Optional[bytes]:
    datum = data_map.get(uti)
    if isinstance(datum, dict):
        raw = cast(dict[str, Any], datum).get("data")
        if isinstance(raw, (bytes, bytearray)) and raw:
            return bytes(raw)
    return None


def _web_archive_image(archive: bytes) -> Optional[tuple[str, bytes]]:
    """First image subresource of a WebKit web archive, as ``(uti, data)``."""
    try:
        subresources = plistlib.loads(archive).get("WebSubresources", [])
    except Exception:
        return None
    uti_by_mime = {mime: uti for uti, mime in IMAGE_UTIS.items()}
    for resource in subresources:
        uti = uti_by_mime.get(resource.get("WebResourceMIMEType"))
        data = resource.get("WebResourceData")
        if uti is not None and isinstance(data, bytes) and data:
            return uti, data
    return None


def snapshot_image(snapshot: dict[str, Any]) -> Optional[tuple[str, bytes]]:
    """Return ``(uti, data)`` for the first image carried inline by a ``PasteboardSnapshot``, or ``None``.

    Apps that copy rich content (Notes, Safari selections) publish no image type of their own; the
    picture is a subresource of their ``com.apple.webarchive`` representation, which is the fallback.
    """
    pasteboard = snapshot.get("pasteboard")
    if isinstance(pasteboard, dict):
        snapshot = cast(dict[str, Any], pasteboard)
    items = cast(list[dict[str, Any]], snapshot.get("items", []) or [])
    for item in items:
        data_map = cast(dict[str, Any], item.get("data") or {})
        for uti in IMAGE_UTIS:
            data = _inline_data(data_map, uti)
            if data is not None:
                return uti, data
    for item in items:
        archive = _inline_data(cast(dict[str, Any], item.get("data") or {}), UTI_WEB_ARCHIVE)
        image = _web_archive_image(archive) if archive is not None else None
        if image is not None:
            return image
    return None


@dataclass(frozen=True)
class PasteboardContent:
    """What a pasteboard change carried, reduced to the parts that can be shared: text and/or one image."""

    text: Optional[str] = None
    image: Optional[bytes] = None
    image_uti: Optional[str] = None

    @property
    def image_mime(self) -> Optional[str]:
        return IMAGE_UTIS.get(self.image_uti) if self.image_uti is not None else None

    @classmethod
    def from_snapshot(cls, snapshot: dict[str, Any]) -> "PasteboardContent":
        image = snapshot_image(snapshot)
        text = snapshot_text(snapshot)
        if image is not None and text is not None and not text.strip("\ufffc \t\r\n"):
            text = None  # the plain-text stand-in for the picture itself (a newline / U+FFFC)
        return cls(
            text=text,
            image=image[1] if image is not None else None,
            image_uti=image[0] if image is not None else None,
        )

    def __bool__(self) -> bool:
        return self.text is not None or self.image is not None


class PasteboardService(RemoteService):
    """Client for the device pasteboard (``com.apple.coredevice.pasteboardservice``)."""

    SERVICE_NAME = "com.apple.coredevice.pasteboardservice"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def get(
        self,
        pasteboard_name: str = GENERAL_PASTEBOARD,
        data_policy: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Pull the current pasteboard contents from the device.

        Returns the raw reply dict (``{command: "PULL_REPLY", pasteboard:
        {items: [...], metadata, sourceMetadata}}``). Use :func:`snapshot_text`
        on it to extract UTF-8 text when that's all you need.
        """
        if data_policy is None:
            data_policy = POLICY_ALL_RESOLVED
        return await self.service.send_receive_request({
            "command": PULL_COMMAND,
            "pasteboardName": pasteboard_name,
            "dataPolicy": data_policy,
        })

    async def get_text(self, pasteboard_name: str = GENERAL_PASTEBOARD) -> Optional[str]:
        """Convenience wrapper: pull the pasteboard and return its UTF-8 text, or ``None``."""
        return snapshot_text(await self.get(pasteboard_name))

    async def set(
        self,
        items: list[dict[str, Any]],
        pasteboard_name: str = GENERAL_PASTEBOARD,
        source_metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Replace the device pasteboard contents with ``items``.

        Each item is a ``PasteboardItem`` dict (use :func:`text_item` or
        :func:`data_item` to build them). Returns the resulting snapshot.
        """
        return await self.service.send_receive_request({
            "command": SET_COMMAND,
            "pasteboardName": pasteboard_name,
            "items": items,
            "sourceMetadata": source_metadata,
        })

    async def set_text(self, text: str, pasteboard_name: str = GENERAL_PASTEBOARD) -> dict[str, Any]:
        """Convenience wrapper: set the pasteboard to a single UTF-8 ``text`` value."""
        return await self.set([text_item(text)], pasteboard_name)


def _change_id(snapshot: dict[str, Any]) -> Optional[tuple[Any, Any]]:
    """``(nonce, changeCount)`` of a snapshot: identifies one state of the device pasteboard."""
    pasteboard = snapshot.get("pasteboard")
    metadata = cast(dict[str, Any], pasteboard).get("metadata") if isinstance(pasteboard, dict) else None
    if not isinstance(metadata, dict):
        return None
    metadata = cast(dict[str, Any], metadata)
    return metadata.get("nonce"), metadata.get("changeCount")


def _promises_an_image(snapshot: dict[str, Any]) -> bool:
    """Whether a snapshot advertises, without carrying it, a representation :func:`snapshot_image` could use."""
    pasteboard = snapshot.get("pasteboard")
    if isinstance(pasteboard, dict):
        snapshot = cast(dict[str, Any], pasteboard)
    for item in cast(list[dict[str, Any]], snapshot.get("items", []) or []):
        data_map = cast(dict[str, Any], item.get("data") or {})
        for uti in cast(list[str], item.get("types", []) or []):
            if (uti in IMAGE_UTIS or uti == UTI_WEB_ARCHIVE) and _inline_data(data_map, uti) is None:
                return True
    return False


async def read_pasteboard(
    rsd: RemoteServiceDiscoveryService,
    pasteboard_name: str = GENERAL_PASTEBOARD,
    allow_full_pull: bool = False,
) -> tuple[dict[str, Any], PasteboardContent]:
    """Pull the device pasteboard without making the daemon stall.

    Asks for the primary type of each item only, which the daemon answers at once and which is
    the text or the picture of an ordinary copy. A picture that only exists inside a secondary
    type (Notes keeps it in its web archive) is out of reach that way: the daemon has no request
    for a single type, and loading all of them can block it -- for every client -- for a minute.
    Such a copy yields no content unless ``allow_full_pull`` accepts that. Returns
    ``(snapshot, content)``.
    """
    async with PasteboardService(rsd) as service:
        snapshot = await service.get(pasteboard_name, POLICY_PROMISE_SECONDARY)
    content = PasteboardContent.from_snapshot(snapshot)
    if content.image is None and not (content.text or "").strip("\ufffc \t\r\n") and _promises_an_image(snapshot):
        if not allow_full_pull:
            logger.info(
                "device copy holds a picture only inside a rich representation; not read (it stalls the device)"
            )
            return snapshot, PasteboardContent()
        logger.debug("pasteboard: nothing shareable in the primary types; pulling every representation")
        async with PasteboardService(rsd) as service:
            snapshot = await asyncio.wait_for(service.get(pasteboard_name), _FULL_PULL_TIMEOUT_SECONDS)
        content = PasteboardContent.from_snapshot(snapshot)
    return snapshot, content


class PasteboardMonitor:
    """Two-way bridge to the device pasteboard (text and images).

    ``on_change`` is called with the new content whenever the device pasteboard changes (the user
    copied something on the device). :meth:`set_text` / :meth:`set_image` copy host content onto the
    device; the change they cause is recognised and not reported back.

    Changes are noticed through the ``com.apple.pasteboard.notify.changed`` Darwin notification and
    read with :func:`read_pasteboard`, not through the service's own ``AUTONOTIFY`` subscription:
    that one makes the daemon resolve every representation before it says anything, which takes a
    minute for a copy made in Notes (see the module docstring). Every pasteboard request uses a
    connection of its own, as the daemon allows one reply per connection. The notification
    connection is re-established whenever it drops. ``allow_full_pull`` is passed on to
    :func:`read_pasteboard`.
    """

    def __init__(
        self,
        rsd: RemoteServiceDiscoveryService,
        on_change: Callable[[PasteboardContent], None],
        pasteboard_name: str = GENERAL_PASTEBOARD,
        reconnect_delay: float = 2.0,
        allow_full_pull: bool = False,
    ) -> None:
        self._rsd = rsd
        self._on_change = on_change
        self._pasteboard_name = pasteboard_name
        self._reconnect_delay = reconnect_delay
        self._allow_full_pull = allow_full_pull  # see read_pasteboard()
        self._task: Optional[asyncio.Task[None]] = None
        # State of the pasteboard (see _change_id) that was last looked at; None until the first look.
        self._last_change: Optional[tuple[Any, Any]] = None
        # Change ids of the latest set_text() / set_image() calls, from their SET_REPLY.
        self._own_changes: list[tuple[Any, Any]] = []
        # Fingerprints of what set_text() / set_image() recently sent, by monotonic send time: the
        # notification of a SET can be handled before its SET_REPLY named the change, and a burst
        # of SETs is coalesced by the device, so the pasteboard may show any of them.
        self._recent_host_content: dict[str, float] = {}
        # set_text() / set_image() calls still waiting for their SET_REPLY.
        self._set_tasks: set[asyncio.Task[None]] = set()

    @property
    def running(self) -> bool:
        return self._task is not None

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="pasteboard-monitor")

    async def stop(self) -> None:
        for set_task in list(self._set_tasks):
            set_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await set_task
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def set_text(self, text: str, timeout: float = 5.0) -> None:
        """Copy ``text`` onto the device pasteboard."""
        await self._set([text_item(text)], _fingerprint(text.encode("utf-8")), timeout)

    async def set_image(self, data: bytes, uti: str = "public.png", timeout: float = 5.0) -> None:
        """Copy an encoded image onto the device pasteboard."""
        await self._set([data_item(uti, data)], _fingerprint(data), timeout)

    async def _set(self, items: list[dict[str, Any]], fingerprint: str, timeout: float) -> None:
        self._recent_host_content[fingerprint] = time.monotonic()
        service = PasteboardService(self._rsd)
        await asyncio.wait_for(service.connect(), timeout)
        try:
            await service.service.send_request(
                {
                    "command": SET_COMMAND,
                    "pasteboardName": self._pasteboard_name,
                    "items": items,
                    "sourceMetadata": None,
                },
                wanting_reply=True,
            )
        except BaseException:
            await service.close()
            raise
        # The copy is on its way; the SET_REPLY is only needed to recognise the change it causes.
        # The daemon answers when it gets to it, which is a minute away while it resolves a rich
        # copy, so the wait must not hold up (or fail) the caller.
        task = asyncio.create_task(self._finish_set(service, fingerprint), name="pasteboard-set-reply")
        self._set_tasks.add(task)
        task.add_done_callback(self._set_tasks.discard)

    async def _finish_set(self, service: PasteboardService, fingerprint: str) -> None:
        try:
            reply = await asyncio.wait_for(service.service.receive_response(), _FULL_PULL_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.debug("no SET_REPLY from the device pasteboard (%s: %s)", type(e).__name__, e)
            return
        finally:
            await service.close()
        change = _change_id(reply)
        if change is not None:
            self._own_changes = [*self._own_changes, change][-_OWN_CHANGES_KEPT:]
        # The pasteboard changed now, not when the SET was sent.
        self._recent_host_content[fingerprint] = time.monotonic()

    async def _run(self) -> None:
        while True:
            try:
                async with NotificationProxyService(self._rsd) as notifications:
                    await notifications.notify_register_dispatch(PASTEBOARD_CHANGED_NOTIFICATION)
                    if self._last_change is None:
                        # What the device holds when monitoring starts is not a change.
                        async with PasteboardService(self._rsd) as service:
                            self._last_change = _change_id(
                                await service.get(self._pasteboard_name, POLICY_ALL_PROMISED)
                            )
                    else:
                        await self._check()  # a copy made while the connection was down
                    async for notification in notifications.receive_notification():
                        if notification.get("Name") == PASTEBOARD_CHANGED_NOTIFICATION:
                            await self._check()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.debug("pasteboard monitor connection lost (%s: %s); reconnecting", type(e).__name__, e)
            await asyncio.sleep(self._reconnect_delay)

    async def _check(self) -> None:
        """Look at the pasteboard and report it when it is a copy made on the device."""
        try:
            snapshot, content = await read_pasteboard(self._rsd, self._pasteboard_name, self._allow_full_pull)
        except asyncio.TimeoutError:
            # Not recorded as seen, so the next notification looks again.
            logger.warning("device pasteboard did not answer; skipping this change")
            return
        if self._set_tasks:
            # The daemon answers in order, so the SET_REPLY of a copy this snapshot shows has
            # arrived by now; let it be read before judging whose copy this is.
            await asyncio.wait(list(self._set_tasks), timeout=1.0)
        change = _change_id(snapshot)
        if change is not None and change == self._last_change:
            return
        self._last_change = change
        now = time.monotonic()
        self._recent_host_content = {
            sent: at for sent, at in self._recent_host_content.items() if now - at < _ECHO_WINDOW_SECONDS
        }
        if not content or change in self._own_changes:
            return
        payload = content.image if content.image is not None else cast(str, content.text).encode("utf-8")
        if _fingerprint(payload) in self._recent_host_content:
            return
        try:
            self._on_change(content)
        except Exception:
            logger.exception("pasteboard monitor callback failed")


def _fingerprint(payload: bytes) -> str:
    return hashlib.sha1(payload).hexdigest()
