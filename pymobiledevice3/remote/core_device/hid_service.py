"""
HID services exposed by the Developer Disk Image's ``dtuhidd`` daemon.

Two RemoteXPC services are wrapped here:

- :class:`IndigoHIDService` (``com.apple.coredevice.hid.indigo``) — generic HID
  events. Currently only the button path is implemented: it uses the
  ``{messageType, payload, featureIdentifier}`` envelope that ``dtuhidd``'s
  ``IndigoHIDServer`` recognises. Other Indigo event kinds (keyboard, scroll,
  digitizer, vendor-defined) use Apple's *Mercury* peer-event envelope, whose
  on-wire form we have not finished reverse-engineering — ``dtuhidd`` receives
  our dispatch but immediately logs ``Resetting gesture state then canceling``
  without invoking any of the known handlers. They are intentionally left out
  until a sniff of a working ``devicectl`` invocation pins down the envelope.

- :class:`UniversalHIDServiceService` (``com.apple.coredevice.hid.universalhidservice``)
  — exposes the device's already-registered HID surfaces. ``list_connected_services``
  enumerates them (each has a ``_ServiceID``) and ``send_report`` posts a raw
  HID report byte-string to a specific surface. Both use the same plain envelope
  as :class:`IndigoHIDService.send_button` and are confirmed working.
"""

import asyncio
import contextlib
import struct
import time
import uuid
from collections.abc import AsyncIterator, Iterable
from typing import Any, Optional

from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcInt64Type, XpcUInt64Type

HID_BUTTON_STATE_DOWN = 1
HID_BUTTON_STATE_UP = 2
HID_BUTTON_STATE_CANCELED = 3

# Wire formats and authentication model for the universalhidservice touch path.
# Decoded by sniffing Xcode-mirror sessions with ``misc/remotexpc_sniffer.py``.
#
# Three surfaces, three report shapes:
#
# 1) **Gesture / pointer surface** — 19-byte report (rid=0x13). Drives the
#    *visual* cursor in the mirror window. The target ``_ServiceID`` is
#    session-specific and not enumerated by :meth:`list_connected_services`
#    (sniffs of two different sessions used 0x100001007 and 0x10000aa0d —
#    both have the high bit-32 set).
#
#        | byte  | meaning                                  |
#        |-------|------------------------------------------|
#        | 0     | report ID (0x13)                         |
#        | 1-4   | X position  (Int32 LE)                   |
#        | 5-8   | Y position  (Int32 LE)                   |
#        | 9-10  | reserved (0x0000)                        |
#        | 11-16 | host timestamp (Mach-abs, 6 bytes LE)    |
#        | 17-18 | reserved (0x0000)                        |
#
# 2) **mainTouchscreen** — 58-byte report (rid=0x09), ``_ServiceID = 257``.
#    Carries the actual touch position and contact state.
#
#        | byte  | meaning                                  |
#        |-------|------------------------------------------|
#        | 0     | report ID (0x09)                         |
#        | 1-2   | constants 0x01 0x05                      |
#        | 3     | state: 0xC2 = contact, 0x02 = release    |
#        | 4-5   | X position (UInt16 LE)                   |
#        | 6-7   | Y position (UInt16 LE)                   |
#        | 8-39  | 32 reserved bytes (all 0 in captures)    |
#        | 40-43 | constant 0x02 0x00 0x00 0x00             |
#        | 44-49 | host timestamp (Mach-abs, 6 bytes LE)    |
#        | 50-57 | 8 reserved bytes (all 0 in captures)     |
#
#    A **tap** is one ``CONTACT`` + one ``RELEASE`` at the same (X, Y).
#    A **drag** is a stream of ``CONTACT`` reports advancing X/Y, terminated
#    by one ``RELEASE`` at the final position — there is no separate
#    touch-begin/end opcode; every ``CONTACT`` is "in contact at this position".
#
# 3) **Virtual keyboard** — 39-byte report (rid=0x01). Unlike the two touch
#    surfaces this one isn't pre-registered on the device; the host has to
#    call ``createService`` first with a HID keyboard report descriptor +
#    ``UniversalControlVirtualService=True`` and a chosen ``_ServiceID``
#    (decoded from a sniff of macOS Universal Control mirroring a hardware
#    keyboard onto the device).
#
#        | byte  | meaning                                  |
#        |-------|------------------------------------------|
#        | 0     | report ID (0x01)                         |
#        | 1-30  | 240-bit usage bitmap (LE bit order)      |
#        | 31-36 | host timestamp (Mach-abs, 6 bytes LE)    |
#        | 37-38 | reserved (0x0000)                        |
#
#    The bitmap covers HID Keyboard usage page 0x07. Bit ``u % 8`` of
#    byte ``1 + (u // 8)`` set ⇔ usage code ``u`` is currently pressed.
#    ASCII letters ``a..z`` are usages 0x04..0x1D; modifiers Ctrl/Shift/
#    Alt/GUI are 0xE0..0xE7. Every report carries the *full pressed set*
#    — to release a key, resend the report with that bit cleared. Each
#    keypress in the sniff = one report with the bit set, then one with
#    it cleared.
#
# **Authentication gate — an active media stream is required.** Without one,
# dtuhidd publishes our HID surfaces as ``authenticated: NO; builtIn: NO;
# eventSource: externalAccessory`` and backboardd silently drops every
# digitizer event with "ignoring digitizer event for display <main> from
# unsupported service". Firing ``action.mediastreamstart`` (the call that
# opens Xcode's screen-mirror video pipe) flips those flags to YES and
# routes the reports all the way through to UIKit as real
# ``UIEventTypeTouches``. The stream just needs to be running — its RTP
# payload can be discarded. :func:`touch_session` opens such a stream as
# an ``async with`` context.

DIGITIZER_REPORT_ID = 0x13  # gesture surface — rid byte
TOUCHSCREEN_REPORT_ID = 0x09  # mainTouchscreen — rid byte
KEYBOARD_REPORT_ID = 0x01  # virtual keyboard — rid byte
TOUCHSCREEN_STATE_CONTACT = 0xC2  # "contact in progress at this position"
TOUCHSCREEN_STATE_RELEASE = 0x02  # release contact

# _ServiceIDs of statically-registered surfaces (see ``list_connected_services``):
DIGITIZER_SURFACE_MAIN_TOUCHSCREEN = 257  # 0x101 — true digitizer (58-byte rid=0x09)
DIGITIZER_SURFACE_TOUCHSCREEN_GESTURE = 1281  # 0x501 — trackpad-style pointer (19-byte rid=0x13)
# Default _ServiceID for the host-registered virtual keyboard. The high
# bit-32 marks it as session-specific, matching the convention macOS
# Universal Control uses for its mirrored peripherals.
KEYBOARD_SURFACE_DEFAULT_SERVICE_ID = 0x100002001

# HID Keyboard usage codes (page 0x07) -- the bits that go into the
# 240-bit bitmap of :func:`build_keyboard_report`. Only the keys we
# actually translate to from the VNC/web frontends are named; arbitrary
# usages can still be sent by their raw integer.
KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G, KEY_H = 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B
KEY_I, KEY_J, KEY_K, KEY_L, KEY_M, KEY_N, KEY_O, KEY_P = 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13
KEY_Q, KEY_R, KEY_S, KEY_T, KEY_U, KEY_V, KEY_W, KEY_X = 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B
KEY_Y, KEY_Z = 0x1C, 0x1D
KEY_1, KEY_2, KEY_3, KEY_4, KEY_5 = 0x1E, 0x1F, 0x20, 0x21, 0x22
KEY_6, KEY_7, KEY_8, KEY_9, KEY_0 = 0x23, 0x24, 0x25, 0x26, 0x27
KEY_ENTER, KEY_ESC, KEY_BACKSPACE, KEY_TAB, KEY_SPACE = 0x28, 0x29, 0x2A, 0x2B, 0x2C
KEY_MINUS, KEY_EQUAL, KEY_LBRACKET, KEY_RBRACKET = 0x2D, 0x2E, 0x2F, 0x30
KEY_BACKSLASH, KEY_SEMICOLON, KEY_APOSTROPHE = 0x31, 0x33, 0x34
KEY_GRAVE, KEY_COMMA, KEY_DOT, KEY_SLASH = 0x35, 0x36, 0x37, 0x38
KEY_CAPS_LOCK = 0x39
KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5, KEY_F6 = 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
KEY_F7, KEY_F8, KEY_F9, KEY_F10, KEY_F11, KEY_F12 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x45
KEY_RIGHT, KEY_LEFT, KEY_DOWN, KEY_UP = 0x4F, 0x50, 0x51, 0x52
KEY_LEFT_CTRL, KEY_LEFT_SHIFT, KEY_LEFT_ALT, KEY_LEFT_GUI = 0xE0, 0xE1, 0xE2, 0xE3
KEY_RIGHT_CTRL, KEY_RIGHT_SHIFT, KEY_RIGHT_ALT, KEY_RIGHT_GUI = 0xE4, 0xE5, 0xE6, 0xE7

# Map a printable ASCII character to the (usage, shift?) it produces on a
# US keyboard layout. ``shift`` is True iff the host must hold Left-Shift
# to produce the character (e.g. ``!`` is shift-1). Used by the CLI's
# ``keyboard type`` and by the web viewer's keydown handler when an event
# only carries the resolved character (no ``KeyboardEvent.code``).
ASCII_TO_HID: dict[str, tuple[int, bool]] = {}
for _ch, _usage in zip("abcdefghijklmnopqrstuvwxyz", range(KEY_A, KEY_Z + 1)):
    ASCII_TO_HID[_ch] = (_usage, False)
    ASCII_TO_HID[_ch.upper()] = (_usage, True)
for _ch, _usage in zip("1234567890", range(KEY_1, KEY_0 + 1)):
    ASCII_TO_HID[_ch] = (_usage, False)
for _ch, _shifted, _usage in [
    ("!", "1", KEY_1),
    ("@", "2", KEY_2),
    ("#", "3", KEY_3),
    ("$", "4", KEY_4),
    ("%", "5", KEY_5),
    ("^", "6", KEY_6),
    ("&", "7", KEY_7),
    ("*", "8", KEY_8),
    ("(", "9", KEY_9),
    (")", "0", KEY_0),
]:
    ASCII_TO_HID[_ch] = (_usage, True)
ASCII_TO_HID.update({
    " ": (KEY_SPACE, False),
    "\t": (KEY_TAB, False),
    "\n": (KEY_ENTER, False),
    "-": (KEY_MINUS, False),
    "_": (KEY_MINUS, True),
    "=": (KEY_EQUAL, False),
    "+": (KEY_EQUAL, True),
    "[": (KEY_LBRACKET, False),
    "{": (KEY_LBRACKET, True),
    "]": (KEY_RBRACKET, False),
    "}": (KEY_RBRACKET, True),
    "\\": (KEY_BACKSLASH, False),
    "|": (KEY_BACKSLASH, True),
    ";": (KEY_SEMICOLON, False),
    ":": (KEY_SEMICOLON, True),
    "'": (KEY_APOSTROPHE, False),
    '"': (KEY_APOSTROPHE, True),
    "`": (KEY_GRAVE, False),
    "~": (KEY_GRAVE, True),
    ",": (KEY_COMMA, False),
    "<": (KEY_COMMA, True),
    ".": (KEY_DOT, False),
    ">": (KEY_DOT, True),
    "/": (KEY_SLASH, False),
    "?": (KEY_SLASH, True),
})

# HID descriptor declaring this surface as a Generic-Desktop Keyboard.
# The bitmap report we actually send doesn't match this descriptor's
# layout (modifier byte + 6-key array); dtuhidd accepts the divergence
# because the same divergence shows up in the captured Universal Control
# session. The descriptor's job is just to identify the surface as a
# keyboard so backboardd hides the on-screen software keyboard while the
# host is connected.
_KEYBOARD_REPORT_DESCRIPTOR = bytes([
    0x05,
    0x01,  # Usage Page (Generic Desktop)
    0x09,
    0x06,  # Usage (Keyboard)
    0xA1,
    0x01,  # Collection (Application)
    0x05,
    0x07,  # Usage Page (Keyboard)
    0x19,
    0xE0,
    0x29,
    0xE7,  # Usage Min/Max -> 8 modifier keys
    0x15,
    0x00,
    0x25,
    0x01,
    0x95,
    0x08,
    0x75,
    0x01,
    0x81,
    0x02,  # 8-bit modifier byte
    0x95,
    0x01,
    0x75,
    0x08,
    0x81,
    0x01,  # 8-bit reserved
    0x05,
    0x07,
    0x19,
    0x00,
    0x29,
    0xFF,
    0x15,
    0x00,
    0x26,
    0xFF,
    0x00,
    0x95,
    0x06,
    0x75,
    0x08,
    0x81,
    0x00,  # 6-key array
    0x05,
    0x08,
    0x19,
    0x01,
    0x29,
    0x05,
    0x15,
    0x00,
    0x25,
    0x01,
    0x95,
    0x05,
    0x75,
    0x01,
    0x91,
    0x02,  # LED output
    0x95,
    0x01,
    0x75,
    0x03,
    0x91,
    0x01,  # 3 padding bits
    0xC0,
])


def build_digitizer_report(x: int, y: int, timestamp: Optional[int] = None) -> bytes:
    """Build a 19-byte gesture/pointer HID report (report ID 0x13).

    ``x`` and ``y`` are signed 32-bit; ``timestamp`` is a 48-bit Mach-abs-style
    monotonic value (defaults to ``time.monotonic_ns()`` truncated to 48 bits —
    the gesture recognizer only cares about monotonicity and inter-frame deltas).
    """
    if timestamp is None:
        timestamp = time.monotonic_ns() & ((1 << 48) - 1)
    return (
        bytes([DIGITIZER_REPORT_ID])
        + struct.pack("<ii", x, y)
        + b"\x00\x00"
        + timestamp.to_bytes(6, "little")
        + b"\x00\x00"
    )


def build_keyboard_report(
    usage_codes: Iterable[int],
    timestamp: Optional[int] = None,
) -> bytes:
    """Build a 39-byte virtual-keyboard HID report (report ID 0x01).

    ``usage_codes`` is the set of HID Keyboard usages currently pressed.
    Pass an empty iterable to release all keys. ``timestamp`` is a 48-bit
    Mach-abs monotonic value (defaults to ``time.monotonic_ns()``
    truncated to 48 bits).

    Bit ``u % 8`` of byte ``1 + (u // 8)`` is set ⇔ usage ``u`` is pressed.
    Usages above 239 cannot be encoded in this report.
    """
    if timestamp is None:
        timestamp = time.monotonic_ns() & ((1 << 48) - 1)
    bitmap = bytearray(30)
    for usage in usage_codes:
        if 0 <= usage < 240:
            bitmap[usage // 8] |= 1 << (usage % 8)
    return bytes([KEYBOARD_REPORT_ID]) + bytes(bitmap) + timestamp.to_bytes(6, "little") + b"\x00\x00"


def build_touchscreen_report(
    state: int,
    x: int,
    y: int,
    timestamp: Optional[int] = None,
) -> bytes:
    """Build a 58-byte mainTouchscreen HID report (report ID 0x09).

    :param state: ``TOUCHSCREEN_STATE_CONTACT`` (0xC2) — a touch sample at
        (x, y) — or ``TOUCHSCREEN_STATE_RELEASE`` (0x02) to lift.
    :param x: X position (UInt16, 0..65535).
    :param y: Y position (UInt16, 0..65535).
    :param timestamp: 48-bit Mach-abs-style monotonic value (defaults to
        ``time.monotonic_ns()`` truncated to 48 bits).
    """
    if timestamp is None:
        timestamp = time.monotonic_ns() & ((1 << 48) - 1)
    return (
        bytes([TOUCHSCREEN_REPORT_ID, 0x01, 0x05, state])
        + struct.pack("<HH", x & 0xFFFF, y & 0xFFFF)
        + b"\x00" * 32
        + b"\x02\x00\x00\x00"
        + timestamp.to_bytes(6, "little")
        + b"\x00" * 8
    )


class IndigoHIDService(RemoteService):
    """Generic HID events (currently: hardware buttons)."""

    SERVICE_NAME = "com.apple.coredevice.hid.indigo"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def send_button(self, usage_page: int, usage_code: int, state: int) -> None:
        """Send an ``IndigoButtonEvent`` — a single hardware-button state change.

        :param usage_page: HID usage page (UInt16). E.g. ``0x0C`` (Consumer) for
                           media buttons, ``0x09`` (Button) for generic buttons.
        :param usage_code: HID usage code (UInt16). Specific to the usage page.
        :param state: One of ``HID_BUTTON_STATE_DOWN`` / ``UP`` / ``CANCELED``.
        """
        await self.service.send_request({
            "messageType": "IndigoButtonEvent",
            "payload": {
                "state": XpcUInt64Type(state),
                "usagePage": XpcUInt64Type(usage_page),
                "usageCode": XpcUInt64Type(usage_code),
            },
            "featureIdentifier": "com.apple.coredevice.feature.remote.hid.button",
        })


class UniversalHIDServiceService(RemoteService):
    """Inspect and drive the device's registered HID surfaces.

    The device exposes a small set of pre-registered surfaces (e.g. the real
    touchscreen at ``_ServiceID 257``, the trackpad-style gesture surface at
    1281, the side-button cluster at 1026); :meth:`list_connected_services`
    enumerates them and :meth:`send_report` delivers a raw HID report byte
    string to one of them.
    """

    SERVICE_NAME = "com.apple.coredevice.hid.universalhidservice"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def list_connected_services(self) -> dict[str, Any]:
        """Enumerate the device's currently registered HID surfaces."""
        return await self.service.send_receive_request({
            "featureIdentifier": "com.apple.coredevice.feature.remote.universalhidservice",
            "messageType": "Request",
            "payload": {"connectedServices": {}},
        })

    async def send_report(self, service_id: int, report: bytes) -> None:
        """Deliver a raw HID report to one of the device's HID surfaces.

        :param service_id: ``_ServiceID`` of the target surface — discoverable
                           via :meth:`list_connected_services`. Known static
                           values include ``257`` (mainTouchscreen) and
                           ``1281`` (touchscreenGesture).
        :param report: Raw HID report bytes. The layout is surface-specific
                       and only known by sniffing ``devicectl`` — see
                       ``misc/remotexpc_sniffer.py``. The first byte is the
                       HID report ID.
        """
        await self.service.send_request({
            "featureIdentifier": "com.apple.coredevice.feature.remote.universalhidservice",
            "messageType": "Request",
            "payload": {"send": {"_0": report, "_1": XpcUInt64Type(service_id)}},
        })

    async def send_digitizer(
        self,
        x: int,
        y: int,
        service_id: int,
        timestamp: Optional[int] = None,
    ) -> None:
        """Send a single 19-byte gesture/pointer report at (``x``, ``y``).

        Equivalent to ``send_report(service_id, build_digitizer_report(...))``.
        Used to move the visual cursor in the mirror window — for an actual
        on-screen touch you also need :meth:`send_touchscreen`.
        """
        await self.send_report(service_id, build_digitizer_report(x, y, timestamp))

    async def send_touchscreen(
        self,
        state: int,
        x: int,
        y: int,
        service_id: int = DIGITIZER_SURFACE_MAIN_TOUCHSCREEN,
        timestamp: Optional[int] = None,
    ) -> None:
        """Send a single 58-byte mainTouchscreen report at (``x``, ``y``).

        ``state`` is :data:`TOUCHSCREEN_STATE_CONTACT` for an in-progress touch
        sample or :data:`TOUCHSCREEN_STATE_RELEASE` to lift.
        """
        await self.send_report(service_id, build_touchscreen_report(state, x, y, timestamp))

    async def create_keyboard_service(
        self,
        service_id: int = KEYBOARD_SURFACE_DEFAULT_SERVICE_ID,
        product: str = "pymobiledevice3 virtual keyboard",
        manufacturer: str = "pymobiledevice3",
        vendor_id: int = 0x05AC,
        product_id: int = 0x0250,
    ) -> int:
        """Register a host-side virtual HID keyboard with ``dtuhidd``.

        Returns the ``_ServiceID`` ``dtuhidd`` ends up using -- usually the
        one we requested. Subsequent reports must be addressed to that ID.

        Same auth gate as touch: a media stream must be running, otherwise
        backboardd publishes the new surface as ``externalAccessory`` and
        drops every report. Open :func:`touch_session` first (or any
        equivalent ``DisplayService.start_video_stream`` context) and call
        this inside it.

        Payload structure mirrors a sniffed macOS Universal Control session
        registering a real Keychron keyboard onto the device. Notable type
        choices, all confirmed against that sniff:

        - ``PrimaryUsage``/``PrimaryUsagePage`` are ``UInt64`` at the top
          level, ``Int64`` inside ``_CoreDevice_codablePropertyStorage``.
        - ``ProductID``/``VendorID``/``DeviceUsage*`` are ``Int64`` everywhere.
        - ``_ServiceID`` is ``UInt64`` everywhere.
        - ``UniversalControlVirtualService``/``ReportDescriptor``/
          ``Manufacturer``/``Transport`` live ONLY inside the storage block.
        - Every value inside the storage block is wrapped in a Swift-
          Codable type envelope -- ``{"bool": ...}`` / ``{"int": ...}`` /
          ``{"string": ...}`` / ``{"data": ...}`` / ``{"array": [...]}`` /
          ``{"dictionary": {...}}`` / ``{"uint": ...}``. dtuhidd's
          decoder rejects raw bools/ints under that key with
          ``DecodingError.typeMismatch: dictionary required here``.
        """
        usage_page_i = XpcInt64Type(1)
        usage_i = XpcInt64Type(6)
        vendor = XpcInt64Type(vendor_id)
        prod = XpcInt64Type(product_id)
        svc_id = XpcUInt64Type(service_id)
        top_pair = {"DeviceUsage": usage_i, "DeviceUsagePage": usage_page_i}
        # Storage block follows the Swift Codable property-list shape:
        # every leaf is {<type-tag>: <value>}, every dict is
        # {"dictionary": {...}}, every list is {"array": [...]}.
        storage: dict[str, Any] = {
            "Manufacturer": {"string": manufacturer},
            "Product": {"string": product},
            "ProductID": {"int": prod},
            "VendorID": {"int": vendor},
            "PrimaryUsage": {"int": usage_i},
            "PrimaryUsagePage": {"int": usage_page_i},
            "DeviceUsagePairs": {
                "array": [
                    {
                        "dictionary": {
                            "DeviceUsage": {"int": usage_i},
                            "DeviceUsagePage": {"int": usage_page_i},
                        }
                    }
                ]
            },
            "Transport": {"string": "USB"},
            "ReportDescriptor": {"data": _KEYBOARD_REPORT_DESCRIPTOR},
            "UniversalControlVirtualService": {"bool": True},
            "_ServiceID": {"uint": svc_id},
        }
        response = await self.service.send_receive_request({
            "featureIdentifier": "com.apple.coredevice.feature.remote.universalhidservice",
            "messageType": "Request",
            "payload": {
                "createService": {
                    "_0": {
                        "DeviceUsagePairs": [top_pair],
                        "PrimaryUsage": XpcUInt64Type(6),
                        "PrimaryUsagePage": XpcUInt64Type(1),
                        "Product": product,
                        "ProductID": prod,
                        "VendorID": vendor,
                        "_CoreDevice_codablePropertyStorage": storage,
                        "_ServiceID": svc_id,
                    }
                }
            },
        })
        return int(response.get("serviceID", service_id))

    async def send_keyboard(
        self,
        service_id: int,
        usage_codes: Iterable[int] = (),
        timestamp: Optional[int] = None,
    ) -> None:
        """Send a single 39-byte virtual-keyboard report.

        ``usage_codes`` is the *full set* of HID Keyboard usages currently
        held down. Pass an empty iterable to release all keys. The report
        is delta-less: every send overwrites whatever the device thought
        was pressed.
        """
        await self.send_report(service_id, build_keyboard_report(usage_codes, timestamp))


@contextlib.asynccontextmanager
async def touch_session(
    rsd: RemoteServiceDiscoveryService,
    *,
    display_id: int = 1,
) -> AsyncIterator["UniversalHIDServiceService"]:
    """Open a :class:`UniversalHIDServiceService` with an active media stream
    holding backboardd's auth gate open.

    Yields a service handle that delivers touch reports all the way through to
    UIKit. Without the stream the same reports get silently dropped — see the
    module-level "Authentication gate" comment for the full backstory.

    Usage::

        async with touch_session(rsd) as svc:
            await svc.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, x, y)
            ...
            await svc.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, x, y)

    The stream's RTP payload is discarded by a background drain task — we just
    need a session to exist for the duration of the gestures.
    """
    # Local imports to avoid a circular dependency with display_service / screen_stream.
    from pymobiledevice3.remote.core_device.display_service import DisplayService
    from pymobiledevice3.remote.core_device.screen_stream import open_media_receiver

    sender_ip = rsd.service.address[0]

    display = DisplayService(rsd)
    await display.__aenter__()
    try:
        # Bind the (discarded) RTP receiver on the right transport — pytcp stack over the
        # userspace tunnel, host kernel socket otherwise — and advertise the matching address so
        # the device can actually reach it (a host kernel socket is unreachable over userspace).
        transport, receiver_ip = open_media_receiver(display, (1 * 1024 * 1024,))

        async def _drain() -> None:
            try:
                while True:
                    await transport.recv()
            except (asyncio.CancelledError, OSError):
                pass

        # Fail fast if the device's media-stream daemon is wedged — without
        # the timeout the call hangs indefinitely on a half-open RemoteXPC
        # channel. The user's standing advice is "reboot proactively".
        try:
            answer = await asyncio.wait_for(
                display.start_video_stream(
                    receiver_ip=receiver_ip,
                    receiver_port=transport.port,
                    sender_ip=sender_ip,
                    display_id=display_id,
                ),
                timeout=10.0,
            )
        except asyncio.TimeoutError as exc:
            raise RuntimeError(
                "Timed out starting the media stream that gates HID auth. "
                "The device's mediastream / dtuhidd daemon is likely wedged "
                "— reboot the device and retry."
            ) from exc
        # backboardd needs a brief moment to (re-)match the HID surfaces
        # against the newly-authenticated stream before our reports will
        # be dispatched as builtIn:YES. Without this delay the first frame
        # of a gesture can land while the surface is still externalAccessory.
        await asyncio.sleep(0.3)
        drain_task = asyncio.create_task(_drain())
        try:
            async with UniversalHIDServiceService(rsd) as hid:
                yield hid
        finally:
            drain_task.cancel()
            with contextlib.suppress(BaseException):
                await drain_task
            # Best-effort stop. The device routinely yanks the channel mid-stop
            # (see :meth:`DisplayService.stop_media_stream`); swallow any noise
            # from the half-dead writer — we've already dispatched the gestures.
            client_session_id = answer["connection"]["options"]["avcMediaStreamOptionClientSessionID"]["uuid"]
            if not isinstance(client_session_id, uuid.UUID):
                client_session_id = uuid.UUID(client_session_id)
            with contextlib.suppress(Exception):
                await display.stop_media_stream(client_session_id)
            transport.close()
    finally:
        with contextlib.suppress(BaseException):
            await display.__aexit__(None, None, None)
