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
import socket
import struct
import time
import uuid
from collections.abc import AsyncIterator
from typing import Optional

from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcUInt64Type

HID_BUTTON_STATE_DOWN = 1
HID_BUTTON_STATE_UP = 2
HID_BUTTON_STATE_CANCELED = 3

# Wire formats and authentication model for the universalhidservice touch path.
# Decoded by sniffing Xcode-mirror sessions with ``misc/remotexpc_sniffer.py``.
#
# Two surfaces, two report shapes:
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
TOUCHSCREEN_STATE_CONTACT = 0xC2  # "contact in progress at this position"
TOUCHSCREEN_STATE_RELEASE = 0x02  # release contact

# _ServiceIDs of statically-registered surfaces (see ``list_connected_services``):
DIGITIZER_SURFACE_MAIN_TOUCHSCREEN = 257  # 0x101 — true digitizer (58-byte rid=0x09)
DIGITIZER_SURFACE_TOUCHSCREEN_GESTURE = 1281  # 0x501 — trackpad-style pointer (19-byte rid=0x13)


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

    async def list_connected_services(self) -> dict:
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
    # Local import to avoid a circular dependency with display_service.
    from pymobiledevice3.remote.core_device.display_service import DisplayService

    sender_ip = rsd.service.address[0]
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(("::", 0))
    bound_port = sock.getsockname()[1]
    sock.setblocking(False)

    async def _drain() -> None:
        loop = asyncio.get_running_loop()
        try:
            while True:
                await loop.sock_recv(sock, 65535)
        except (asyncio.CancelledError, OSError):
            pass

    display = DisplayService(rsd)
    await display.__aenter__()
    try:
        local_ip = display.service.local_address[0]
        # Fail fast if the device's media-stream daemon is wedged — without
        # the timeout the call hangs indefinitely on a half-open RemoteXPC
        # channel. The user's standing advice is "reboot proactively".
        try:
            answer = await asyncio.wait_for(
                display.start_video_stream(
                    receiver_ip=local_ip,
                    receiver_port=bound_port,
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
            sock.close()
    finally:
        with contextlib.suppress(BaseException):
            await display.__aexit__(None, None, None)
