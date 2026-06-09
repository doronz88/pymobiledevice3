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

from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.xpc_message import XpcUInt64Type

HID_BUTTON_STATE_DOWN = 1
HID_BUTTON_STATE_UP = 2
HID_BUTTON_STATE_CANCELED = 3


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
