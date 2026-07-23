import struct
from typing import Any, Optional

from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


def _to_float32(value: float) -> float:
    """Round *value* through IEEE-754 binary32 and back to a Python float.

    The CoreDevice daemon's Swift decoders for the float-valued knobs
    (e.g. ``opacity``, ``intensity``) reject Double-encoded values whose
    low mantissa bits don't fit in Float32 with "value doesn't fit in
    Float" — even for in-range values like 0.55. Xcode's captures show
    every float on the wire is a Float32-exact Double (8 bytes with the
    low 4 zero). Round-tripping through binary32 here produces the same
    bit pattern, so the device accepts every slider position.
    """
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


class ConfigurationService(CoreDeviceService):
    """Read and write device configuration knobs exposed over CoreDevice:
    appearance (dark/light), liquid-glass opacity, and the accessibility
    knobs that Xcode's accessibility-inspector toggles through the same
    service (color filter, dynamic text size, reduce motion, increase
    contrast, layout-debug borders, reduce transparency).

    Every method is a thin wrapper around a single
    ``com.apple.coredevice.action.*`` invocation; shapes were derived from
    a live Xcode capture (one round-trip per knob) and match what the
    device daemon expects byte-for-byte.
    """

    SERVICE_NAME = "com.apple.coredevice.configuration"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def get_user_interface_style(self) -> str:
        """Return the active user-interface style — ``"dark"`` or ``"light"``."""
        output = await self.invoke(action_identifier="com.apple.coredevice.action.getuserinterfacestyle")
        return output["style"]

    async def set_user_interface_style(self, style: str) -> None:
        """Set the device's user-interface style to ``"dark"`` or ``"light"``."""
        if style not in ("dark", "light"):
            raise ValueError(f"style must be 'dark' or 'light', got {style!r}")
        await self.invoke(
            input_={"style": style},
            action_identifier="com.apple.coredevice.action.setuserinterfacestyle",
        )

    async def set_liquid_glass_opacity(self, opacity: float) -> None:
        """Set the system liquid-glass opacity (0.0..1.0)."""
        if not 0.0 <= opacity <= 1.0:
            raise ValueError(f"opacity must be in [0.0, 1.0], got {opacity!r}")
        await self.invoke(
            input_={"configuration": {"opacity": _to_float32(opacity)}},
            action_identifier="com.apple.coredevice.action.setliquidglassconfiguration",
        )

    async def get_color_filter(self) -> dict[str, Any]:
        """Return the color-filter state.

        Shape: ``{"enabled": bool, "filterType": {"name": str}, "intensity": float}``.
        When the filter is disabled only ``enabled`` is present.
        """
        output = await self.invoke(action_identifier="com.apple.coredevice.action.getcolorfilter")
        return output["colorFilter"]

    async def set_color_filter(
        self, enabled: bool, filter_type: Optional[str] = None, intensity: Optional[float] = None
    ) -> None:
        """Set the color-filter state.

        :param enabled: Whether the filter is active.
        :param filter_type: Filter preset name (e.g. ``"Protanopia"``). Required when ``enabled`` is true.
        :param intensity: Filter intensity 0.0..1.0 (optional even when enabled).
        """
        body: dict[str, Any] = {"enabled": bool(enabled)}
        if enabled:
            if filter_type is None:
                raise ValueError("filter_type is required when enabled=True")
            body["filterType"] = {"name": filter_type}
            if intensity is not None:
                body["intensity"] = _to_float32(intensity)
        await self.invoke(
            input_={"colorFilter": body},
            action_identifier="com.apple.coredevice.action.setcolorfilter",
        )

    async def get_device_text_size(self) -> str:
        """Return the dynamic-type size name (e.g. ``"medium"``, ``"large"``)."""
        output = await self.invoke(action_identifier="com.apple.coredevice.action.getdevicetextsize")
        size = output["textSize"]["size"]
        return next(iter(size))

    async def set_device_text_size(self, size: str) -> None:
        """Set the dynamic-type size by name (``"medium"``, ``"large"``, etc.)."""
        await self.invoke(
            input_={"textSize": {"size": {size: {}}}},
            action_identifier="com.apple.coredevice.action.setdevicetextsize",
        )

    async def get_reduce_motion(self) -> bool:
        """Return whether Reduce Motion is enabled."""
        output = await self.invoke(action_identifier="com.apple.coredevice.action.getreducemotion")
        return bool(output["reduceMotion"]["enabled"])

    async def set_reduce_motion(self, enabled: bool) -> None:
        """Toggle Reduce Motion."""
        await self.invoke(
            input_={"reduceMotion": {"enabled": bool(enabled)}},
            action_identifier="com.apple.coredevice.action.setreducemotion",
        )

    async def set_increase_contrast(self, enabled: bool) -> None:
        """Toggle Increase Contrast (no symmetric getter is exposed by the daemon)."""
        await self.invoke(
            input_={"increaseContrast": {"enabled": bool(enabled)}},
            action_identifier="com.apple.coredevice.action.setdeviceincreasecontrast",
        )

    async def get_show_borders(self) -> bool:
        """Return whether the layout-debug borders overlay is enabled."""
        output = await self.invoke(action_identifier="com.apple.coredevice.action.getshowborders")
        return bool(output["showBorders"]["enabled"])

    async def set_show_borders(self, enabled: bool) -> None:
        """Toggle the layout-debug borders overlay."""
        await self.invoke(
            input_={"showBorders": {"enabled": bool(enabled)}},
            action_identifier="com.apple.coredevice.action.setshowborders",
        )

    async def get_reduce_transparency(self) -> bool:
        """Return whether Reduce Transparency is enabled."""
        output = await self.invoke(action_identifier="com.apple.coredevice.action.getreducetransparency")
        return bool(output["reduceTransparency"]["enabled"])

    async def set_reduce_transparency(self, enabled: bool) -> None:
        """Toggle Reduce Transparency."""
        await self.invoke(
            input_={"reduceTransparency": {"enabled": bool(enabled)}},
            action_identifier="com.apple.coredevice.action.setreducetransparency",
        )
