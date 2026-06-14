from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


class ConfigurationService(CoreDeviceService):
    """
    Read and write device configuration knobs exposed over CoreDevice
    (currently: user-interface style — i.e. dark / light mode).
    """

    SERVICE_NAME = "com.apple.coredevice.configuration"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        super().__init__(rsd, self.SERVICE_NAME)

    async def get_user_interface_style(self) -> str:
        """
        Get the active user-interface style of the device.

        :return: ``"dark"`` or ``"light"``.
        """
        output = await self.invoke(action_identifier="com.apple.coredevice.action.getuserinterfacestyle")
        return output["style"]

    async def set_user_interface_style(self, style: str) -> None:
        """
        Set the device's user-interface style.

        :param style: ``"dark"`` or ``"light"``.
        """
        if style not in ("dark", "light"):
            raise ValueError(f"style must be 'dark' or 'light', got {style!r}")
        await self.invoke(
            input_={"style": style},
            action_identifier="com.apple.coredevice.action.setuserinterfacestyle",
        )
