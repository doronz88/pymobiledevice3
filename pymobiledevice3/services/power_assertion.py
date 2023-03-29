#!/usr/bin/env python3


import contextlib
from typing import Generator

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.base_service import BaseService


class PowerAssertionService(BaseService):
    SERVICE_NAME = 'com.apple.mobile.assertion_agent'

    def __init__(self, lockdown: LockdownClient) -> None:
        super().__init__(lockdown, self.SERVICE_NAME)

    @contextlib.contextmanager
    def create_power_assertion(self, type_: str, name: str, timeout: int, details: str = None) -> Generator[
        None, None, None]:
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
