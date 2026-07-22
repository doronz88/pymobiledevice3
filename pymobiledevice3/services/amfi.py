#!/usr/bin/env python3
import logging
from asyncio import IncompleteReadError

from pymobiledevice3.exceptions import (
    AmfiError,
    ConnectionTerminatedError,
    DeveloperModeError,
    DeviceHasPasscodeSetError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.lockdown import retry_create_using_usbmux
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.heartbeat import HeartbeatService


class AmfiService:
    """
    Control Developer Mode on the device through the AMFI (Apple Mobile File Integrity) lockdown service.

    Each method opens its own connection to the ``com.apple.amfi.lockdown`` service and sends a single
    ``action`` request. The actions correspond to revealing the Developer Mode toggle in Settings,
    requesting that it be enabled, and confirming the post-restart prompt.
    """

    DEVELOPER_MODE_REVEAL = 0
    DEVELOPER_MODE_ENABLE = 1
    DEVELOPER_MODE_ACCEPT = 2

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
        service = await self._lockdown.start_lockdown_service(self.SERVICE_NAME)
        resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_REVEAL})
        if not resp.get("success"):
            raise PyMobileDevice3Exception(f"create_AMFIShowOverridePath() failed with: {resp}")

    async def enable_developer_mode(self, enable_post_restart=True):
        """
        Request that Developer Mode be enabled on the device.

        Sends the enable action. The device then reboots to apply the change. When
        ``enable_post_restart`` is True, this method keeps the connection alive via a heartbeat,
        waits for the device to disconnect and reconnect over usbmux, and then answers the
        post-restart confirmation prompt by calling `enable_developer_mode_post_restart`.

        :param enable_post_restart: when True, wait for the device to restart and automatically
            confirm the final prompt; when False, return immediately after the enable request.
        :raises DeviceHasPasscodeSetError: if the device has a passcode set, which blocks the operation.
        :raises AmfiError: if AMFI returns any other error.
        :raises DeveloperModeError: if the enable or post-restart confirmation request does not succeed.
        """
        service = await self._lockdown.start_lockdown_service(self.SERVICE_NAME)
        resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_ENABLE})
        error = resp.get("Error")

        if error is not None:
            if error == "Device has a passcode set":
                raise DeviceHasPasscodeSetError()
            raise AmfiError(error)

        if not resp.get("success"):
            raise DeveloperModeError(f"enable_developer_mode(): {resp}")

        if not enable_post_restart:
            return

        try:
            await HeartbeatService(self._lockdown).start()
        except (ConnectionTerminatedError, BrokenPipeError, IncompleteReadError):
            self._logger.debug("device disconnected, awaiting reconnect")

        lockdown = await retry_create_using_usbmux(None, serial=self._lockdown.udid)
        self._lockdown = lockdown
        await self.enable_developer_mode_post_restart()

    async def enable_developer_mode_post_restart(self):
        """
        Confirm the Developer Mode prompt shown after the device restarts.

        Sends the accept action, answering the post-restart confirmation prompt affirmatively.

        :raises DeveloperModeError: if the device does not report success.
        """
        service = await self._lockdown.start_lockdown_service(self.SERVICE_NAME)
        resp = await service.send_recv_plist({"action": self.DEVELOPER_MODE_ACCEPT})
        if not resp.get("success"):
            raise DeveloperModeError(f"enable_developer_mode_post_restart() failed: {resp}")
