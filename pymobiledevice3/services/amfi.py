#!/usr/bin/env python3
import logging
from asyncio import IncompleteReadError
from typing import Optional

from pymobiledevice3.exceptions import (
    AmfiError,
    ConnectionTerminatedError,
    DeveloperModeError,
    DeviceHasPasscodeSetError,
    MuxException,
    PyMobileDevice3Exception,
)
from pymobiledevice3.lockdown import UsbmuxLockdownClient, retry_create_using_usbmux
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.heartbeat import HeartbeatService
from pymobiledevice3.usbmux import select_device

# How long the device may take to reboot and show up in usbmuxd again after Developer Mode is enabled.
DEVELOPER_MODE_RECONNECT_TIMEOUT = 180.0


class AmfiService:
    """
    Control Developer Mode on the device through the AMFI (Apple Mobile File Integrity) lockdown service.

    Each method opens its own connection to the ``com.apple.amfi.lockdown`` service and sends a single
    ``action`` request. The actions correspond to revealing the Developer Mode toggle in Settings,
    requesting that it be enabled, confirming the post-restart prompt, and trusting the developer
    app signer of an installed provisioning profile.
    """

    DEVELOPER_MODE_REVEAL = 0
    DEVELOPER_MODE_ENABLE = 1
    DEVELOPER_MODE_ACCEPT = 2
    TRUST_APP_SIGNER = 4

    SERVICE_NAME = "com.apple.amfi.lockdown"

    def __init__(self, lockdown: LockdownServiceProvider) -> None:
        self._lockdown = lockdown
        self._logger = logging.getLogger(self.__module__)

    async def reveal_developer_mode_option_in_ui(self):
        """
        Make the Developer Mode toggle visible in the device's Settings UI.

        Sends the reveal action, which causes AMFI to create an empty file at its
        ``AMFIShowOverridePath``.

        :raises PyMobileDevice3Exception: if the device does not report success.
        """
        async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_REVEAL})
        if not resp.get("success"):
            raise PyMobileDevice3Exception(f"The device did not reveal the Developer Mode setting: {resp}")

    async def enable_developer_mode(
        self, enable_post_restart: bool = True, reconnect_timeout: float = DEVELOPER_MODE_RECONNECT_TIMEOUT
    ):
        """
        Request that Developer Mode be enabled on the device.

        Sends the enable action. The device then reboots to apply the change. When
        ``enable_post_restart`` is True, this method keeps the connection alive via a heartbeat,
        waits for the same device (by UDID) to disconnect and reconnect over usbmux, and then answers
        the post-restart confirmation prompt by calling `enable_developer_mode_post_restart`.

        The reconnect always goes through usbmux, since the RSD tunnel or TCP connection the request
        was sent over does not survive the reboot. A device reached without usbmux (e.g. ``--rsd`` to a
        device that usbmuxd does not list) cannot be reconnected to, so the prompt has to be confirmed
        on the device itself.

        :param enable_post_restart: when True, wait for the device to restart and automatically
            confirm the final prompt; when False, return immediately after the enable request.
        :param reconnect_timeout: maximum time in seconds to wait for the device to come back after it
            restarts.
        :raises DeviceHasPasscodeSetError: if the device has a passcode set, which blocks the operation.
        :raises AmfiError: if AMFI returns any other error.
        :raises DeveloperModeError: if the enable or post-restart confirmation request does not succeed,
            or if the device cannot be reconnected to over usbmux after it restarts.
        """
        async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_ENABLE})
        error = resp.get("Error")

        if error is not None:
            if error == "Device has a passcode set":
                raise DeviceHasPasscodeSetError()
            raise AmfiError(f"AMFI refused to enable Developer Mode: {error}")

        if not resp.get("success"):
            raise DeveloperModeError(f"The device did not enable Developer Mode: {resp}")

        if not enable_post_restart:
            return

        udid = self._lockdown.udid
        confirm_on_device = "Once it has restarted, unlock it and confirm the Developer Mode prompt on the device."
        over_usbmux = isinstance(self._lockdown, UsbmuxLockdownClient)
        usbmux_address = self._lockdown.usbmux_address if isinstance(self._lockdown, UsbmuxLockdownClient) else None
        if udid is None or not (over_usbmux or await self._listed_by_usbmux(udid)):
            # Reached over RSD/TCP only: nothing to reconnect through once the reboot tears that down.
            raise DeveloperModeError(
                "Developer Mode was requested and the device is restarting, but it is not connected through "
                f"usbmux, so the post-restart prompt cannot be confirmed from here. {confirm_on_device}"
            )

        try:
            await HeartbeatService(self._lockdown).start()
        except (ConnectionTerminatedError, BrokenPipeError, IncompleteReadError):
            self._logger.debug("device disconnected, awaiting reconnect")

        lockdown = await retry_create_using_usbmux(reconnect_timeout, serial=udid, usbmux_address=usbmux_address)
        if lockdown is None:
            raise DeveloperModeError(
                f"Device {udid} did not reconnect over usbmux within {reconnect_timeout:.0f} seconds of "
                f"restarting. {confirm_on_device}"
            )
        self._lockdown = lockdown
        await self.enable_developer_mode_post_restart()

    @staticmethod
    async def _listed_by_usbmux(udid: str) -> bool:
        try:
            return await select_device(udid) is not None
        except MuxException:
            return False

    async def enable_developer_mode_post_restart(self):
        """
        Confirm the Developer Mode prompt shown after the device restarts.

        Sends the accept action, answering the post-restart confirmation prompt affirmatively.

        :raises DeveloperModeError: if the device does not report success.
        """
        async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_ACCEPT})
        if not resp.get("success"):
            raise DeveloperModeError(f"The device did not confirm Developer Mode after restarting: {resp}")

    async def trust_app_signer(self, profile_uuid: str) -> Optional[bool]:
        """
        Trust the developer app signer of an installed provisioning profile.

        Equivalent to tapping "Trust" under Settings > General > VPN & Device Management.

        :param profile_uuid: UUID of the installed provisioning profile whose signer should be trusted.
        :return: The ``status`` value of the reply, or None if the device omitted it.
        :raises AmfiError: if the device does not report success (e.g. no profile with that UUID).
        """
        async with await self._lockdown.start_lockdown_service(self.SERVICE_NAME) as service:
            resp = await service.send_recv_plist({"action": self.TRUST_APP_SIGNER, "input_profile_uuid": profile_uuid})
        error = resp.get("Error")
        if error is not None:
            raise AmfiError(f"AMFI refused to trust the app signer of profile {profile_uuid}: {error}")
        if not resp.get("success"):
            raise AmfiError(f"The device did not trust the app signer of profile {profile_uuid}: {resp}")
        status = resp.get("status")
        return status if isinstance(status, bool) else None
