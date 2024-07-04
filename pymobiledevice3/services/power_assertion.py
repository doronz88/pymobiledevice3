#!/usr/bin/env python3
import contextlib

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class PowerAssertionService(LockdownService):
    RSD_SERVICE_NAME = 'com.apple.mobile.assertion_agent.shim.remote'
    SERVICE_NAME = 'com.apple.mobile.assertion_agent'

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    @contextlib.contextmanager
    def create_power_assertion(self, type_: str, name: str, timeout: float, details: str = None):
        """ Trigger IOPMAssertionCreateWithName """
        msg = {
            'CommandKey': 'CommandCreateAssertion',
            'AssertionTypeKey': type_,
            'AssertionNameKey': name,
            'AssertionTimeoutKey': timeout,
        }

        if details is not None:
            msg['AssertionDetailKey'] = details

        self.service.send_recv_plist(msg)
        yield
