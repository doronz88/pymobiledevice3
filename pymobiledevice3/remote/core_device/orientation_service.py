"""
Programmatic device rotation via the ``com.apple.coredevice.devicecontrol``
RemoteXPC service.

Decoded from a Xcode-mirror sniff (``misc/remotexpc_sniffer.py``) of four
back-to-back "rotate left" clicks. Each request is an ``OrientationRequest``
envelope; the reply carries the resulting orientation state:

    request  -> {'featureIdentifier': 'com.apple.coredevice.feature.remote.devicecontrol.orientation',
                 'messageType': 'OrientationRequest',
                 'payload': {'rotate': {'_0': 'left'}}}
    response -> {'currentDeviceOrientation': 'landscapeLeft',
                 'currentDeviceNonFlatOrientation': 'landscapeLeft',
                 'currentDeviceOrientationLocked': False}

Four consecutive ``rotate=left`` calls cycle the device through
``portrait -> landscapeLeft -> portraitUpsideDown -> landscapeRight -> portrait``
- so a single request is a 90 degree CCW step, ``right`` is the CW
counterpart. ``currentDeviceOrientationLocked`` reflects iOS's own
orientation-lock toggle; the service still rotates while locked.
"""

from typing import Any

from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

ORIENTATION_FEATURE = "com.apple.coredevice.feature.remote.devicecontrol.orientation"

ROTATE_LEFT = "left"
ROTATE_RIGHT = "right"


class OrientationService(RemoteService):
    """Rotate the device 90 degrees at a time over ``com.apple.coredevice.devicecontrol``."""

    SERVICE_NAME = "com.apple.coredevice.devicecontrol"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def rotate(self, direction: str = ROTATE_LEFT) -> dict[str, Any]:
        """Rotate the device 90 degrees in ``direction`` (``'left'`` = CCW, ``'right'`` = CW).

        Returns the device's resulting orientation, e.g. ``{'currentDeviceOrientation':
        'landscapeLeft', 'currentDeviceNonFlatOrientation': 'landscapeLeft',
        'currentDeviceOrientationLocked': False}``.
        """
        if direction not in (ROTATE_LEFT, ROTATE_RIGHT):
            raise ValueError(f"direction must be 'left' or 'right', got {direction!r}")
        return await self.service.send_receive_request({
            "featureIdentifier": ORIENTATION_FEATURE,
            "messageType": "OrientationRequest",
            "payload": {"rotate": {"_0": direction}},
        })
