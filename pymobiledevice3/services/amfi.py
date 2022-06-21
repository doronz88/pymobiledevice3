#!/usr/bin/env python3
import logging

from pymobiledevice3.exceptions import PyMobileDevice3Exception, NoDeviceConnectedError, ConnectionFailedError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.heartbeat import HeartbeatService


class AmfiService:
    SERVICE_NAME = 'com.apple.amfi.lockdown'

    def __init__(self, lockdown: LockdownClient):
        self._lockdown = lockdown
        self._logger = logging.getLogger(self.__module__)

    def create_amfi_show_override_path_file(self):
        """ create an empty file at AMFIShowOverridePath """
        service = self._lockdown.start_service(self.SERVICE_NAME)
        resp = service.send_recv_plist({'action': 0})
        if not resp['status']:
            raise PyMobileDevice3Exception(f'create_AMFIShowOverridePath() failed with: {resp}')

    def enable_developer_mode(self, enable_post_restart=True):
        """
        enable developer-mode
        if enable_post_restart is True, then wait for device restart to answer the final prompt
        with "yes"
        """
        service = self._lockdown.start_service(self.SERVICE_NAME)
        resp = service.send_recv_plist({'action': 1})
        if not resp['success']:
            raise PyMobileDevice3Exception(f'enable_developer_mode(): {resp}')

        if not enable_post_restart:
            return

        try:
            HeartbeatService(self._lockdown).start()
        except ConnectionAbortedError:
            self._logger.debug('device disconnected, awaiting reconnect')

        while True:
            try:
                self._lockdown = LockdownClient(self._lockdown.udid)
                break
            except (NoDeviceConnectedError, ConnectionFailedError):
                pass

        self.enable_developer_mode_post_restart()

    def enable_developer_mode_post_restart(self):
        """ answer the prompt that appears after the restart with "yes" """
        service = self._lockdown.start_service(self.SERVICE_NAME)
        resp = service.send_recv_plist({'action': 2})
        if not resp['success']:
            raise PyMobileDevice3Exception(f'enable_developer_mode_post_restart() failed: {resp}')
