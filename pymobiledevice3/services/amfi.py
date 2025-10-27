#!/usr/bin/env python3
import logging

from pymobiledevice3.exceptions import (
    AmfiError,
    DeveloperModeError,
    DeviceHasPasscodeSetError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.lockdown import LockdownClient, retry_create_using_usbmux
from pymobiledevice3.services.heartbeat import HeartbeatService


class AmfiService:
    DEVELOPER_MODE_REVEAL = 0
    DEVELOPER_MODE_ENABLE = 1
    DEVELOPER_MODE_ACCEPT = 2

    SERVICE_NAME = "com.apple.amfi.lockdown"

    def __init__(self, lockdown: LockdownClient):
        self._lockdown = lockdown
        self._logger = logging.getLogger(self.__module__)

    def reveal_developer_mode_option_in_ui(self):
        """create an empty file at AMFIShowOverridePath"""
        service = self._lockdown.start_lockdown_service(self.SERVICE_NAME)
        resp = service.send_recv_plist({"action": self.DEVELOPER_MODE_REVEAL})
        if not resp.get("success"):
            raise PyMobileDevice3Exception(f"create_AMFIShowOverridePath() failed with: {resp}")

    def enable_developer_mode(self, enable_post_restart=True):
        """
        enable developer-mode
        if enable_post_restart is True, then wait for device restart to answer the final prompt
        with "yes"
        """
        service = self._lockdown.start_lockdown_service(self.SERVICE_NAME)
        resp = service.send_recv_plist({"action": self.DEVELOPER_MODE_ENABLE})
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
            HeartbeatService(self._lockdown).start()
        except (ConnectionAbortedError, BrokenPipeError):
            self._logger.debug("device disconnected, awaiting reconnect")

        self._lockdown = retry_create_using_usbmux(None, serial=self._lockdown.udid)
        self.enable_developer_mode_post_restart()

    def enable_developer_mode_post_restart(self):
        """answer the prompt that appears after the restart with "yes" """
        service = self._lockdown.start_lockdown_service(self.SERVICE_NAME)
        resp = service.send_recv_plist({"action": self.DEVELOPER_MODE_ACCEPT})
        if not resp.get("success"):
            raise DeveloperModeError(f"enable_developer_mode_post_restart() failed: {resp}")
