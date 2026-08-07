import dataclasses
import struct
from typing import Any, Optional

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

FETCH_APP_ICONS_FEATURE = "com.apple.coredevice.feature.fetchappicons"


def _to_float32(value: float) -> float:
    """Round *value* through IEEE-754 binary32 and back.

    ``FetchAppIconParams`` declares ``width``/``height``/``scale`` as Swift ``Float``, so the
    daemon's decoder rejects Double-encoded values whose low mantissa bits don't fit in Float32.
    """
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


@dataclasses.dataclass
class AppIcon:
    """A rendered application icon returned by ``com.apple.coredevice.iconservice``."""

    png_data: bytes
    #: Icon dimensions in pixels (``size`` multiplied by ``scale``).
    pixel_size: tuple[float, float]
    #: Icon dimensions in points, as actually rendered — may be smaller than requested.
    size: tuple[float, float]
    scale: float
    #: ``True`` when the device had no real icon and returned a generic placeholder.
    is_placeholder: bool


class IconService(CoreDeviceService):
    """
    Fetch application icons as PNGs (``com.apple.coredevice.iconservice``).

    Note this is a distinct service from ``com.apple.coredevice.appservice``, which does not
    advertise the ``fetchappicons`` feature and rejects the request.
    """

    SERVICE_NAME = "com.apple.coredevice.iconservice"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def fetch_icon(
        self,
        bundle_identifier: Optional[str] = None,
        app_path: Optional[str] = None,
        width: float = 60.0,
        height: float = 60.0,
        scale: float = 2.0,
        allow_placeholder: bool = True,
    ) -> AppIcon:
        """
        Fetch a single application's icon.

        Exactly one of `bundle_identifier` or `app_path` identifies the app.

        :param bundle_identifier: Bundle identifier of the app to fetch, e.g. ``com.apple.Preferences``.
        :param app_path: On-device path of the app bundle, as an alternative to `bundle_identifier`.
        :param width: Requested width in points.
        :param height: Requested height in points.
        :param scale: Requested scale factor; pixel dimensions are the point size times this.
        :param allow_placeholder: When ``True``, a generic placeholder is returned for apps with no
                                  icon instead of raising.
        :raises ValueError: if neither or both of `bundle_identifier` and `app_path` are given.
        :raises CoreDeviceError: if the device could not produce an icon.
        """
        if (bundle_identifier is None) == (app_path is None):
            raise ValueError("exactly one of bundle_identifier or app_path must be given")
        response = await self.invoke(
            FETCH_APP_ICONS_FEATURE,
            {
                "bundleIdentifier": bundle_identifier,
                "appPath": app_path,
                "width": _to_float32(width),
                "height": _to_float32(height),
                "scale": _to_float32(scale),
                "allowPlaceholder": allow_placeholder,
            },
        )
        return self._parse(response)

    @staticmethod
    def _parse(response: dict[str, Any]) -> AppIcon:
        info = response["appIconInfo"]
        pixel_size = info["pixelSize"]
        size = info["size"]
        return AppIcon(
            png_data=info["pngData"],
            pixel_size=(pixel_size[0], pixel_size[1]),
            size=(size[0], size[1]),
            scale=info["scale"],
            is_placeholder=info["isAppIconPlaceholder"],
        )
