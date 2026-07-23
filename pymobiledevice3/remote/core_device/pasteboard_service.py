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
  PULL (paste-from-device) and SET with immediate data (copy-to-device) since
  those cover the common copy-paste UX. Promise resolution (DATA/RESOLVE) and
  change monitoring (AUTONOTIFY) are scaffolded but not yet exposed.
* A ``PasteboardSnapshot`` carries ``items: [{types: [String], data: {UTI:
  PasteboardItemData}}]`` plus optional ``metadata`` / ``sourceMetadata``.
  ``PasteboardItemData`` on the wire is ``{data: Data}`` for immediate
  items, or ``{isPromised: true, isAvailable: false, size: Int64}`` for
  promised items (Swift property ``immediateData`` is keyed as ``data`` on
  the wire). ``Data`` is a native XPC DATA field (raw bytes), not base64.
* ``PasteboardDataInclusionPolicy`` is a Codable enum encoded as
  ``{"allResolved": {}}`` etc. We default to ``allResolved`` so the reply
  carries data inline and we don't need to chase promises.
"""

from typing import Any, Optional, cast

from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type

GENERAL_PASTEBOARD = "general"

PULL_COMMAND = "PULL"
PULL_REPLY_COMMAND = "PULL_REPLY"
SET_COMMAND = "SET"
SET_REPLY_COMMAND = "SET_REPLY"
DATA_COMMAND = "DATA"
PUSH_COMMAND = "PUSH"
AUTONOTIFY_COMMAND = "AUTONOTIFY"
RESOLVE_COMMAND = "RESOLVE"

UTI_UTF8_PLAIN_TEXT = "public.utf8-plain-text"
UTI_PLAIN_TEXT = "public.plain-text"
UTI_TEXT = "public.text"
UTI_URL = "public.url"

# PasteboardDataInclusionPolicy presets.
POLICY_ALL_RESOLVED: dict[str, Any] = {"allResolved": {}}
POLICY_ALL_PROMISED: dict[str, Any] = {"allPromised": {}}
POLICY_MATCH_SOURCE: dict[str, Any] = {"matchSource": {}}
POLICY_PROMISE_SECONDARY: dict[str, Any] = {"promiseSecondary": {}}


def policy_threshold(threshold_bytes: int) -> dict[str, Any]:
    """Inclusion policy: include item data inline if smaller than ``threshold_bytes``, otherwise promise it."""
    return {"thresholdData": {"_0": XpcInt64Type(threshold_bytes)}}


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
