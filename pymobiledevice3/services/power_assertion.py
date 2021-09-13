#!/usr/bin/env python3

import logging
import time

from pymobiledevice3.lockdown import LockdownClient


class PowerAssertionService:
    SERVICE_NAME = 'com.apple.mobile.assertion_agent'

    def __init__(self, lockdown: LockdownClient):
        self.logger = logging.getLogger(__name__)
        self.lockdown = lockdown
        self.service = self.lockdown.start_service(self.SERVICE_NAME)

    def create_power_assertion(self, type_: str, name: str, timeout: int, details: str = None):
        msg = {
            'CommandKey': 'CommandCreateAssertion',
            'AssertionTypeKey': type_,
            'AssertionNameKey': name,
            'AssertionTimeoutKey': timeout,
        }

        if details is not None:
            msg['AssertionDetailKey'] = details

        self.service.send_recv_plist(msg)
        time.sleep(timeout)
