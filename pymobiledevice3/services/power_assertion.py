#!/usr/bin/env python3
import contextlib
from typing import Any, Optional

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.services.lockdown_service import LockdownService


class PowerAssertionService(LockdownService):
    """
    Hold an IOKit power assertion on the device through the assertion agent lockdown service.

    A power assertion prevents the device from sleeping (or otherwise alters its power behavior)
    for as long as it is held. This is a lockdown service and is used as an async context manager;
    the RSD/tunnel variant is selected automatically for non-`LockdownClient` providers.
    """

    RSD_SERVICE_NAME = "com.apple.mobile.assertion_agent.shim.remote"
    SERVICE_NAME = "com.apple.mobile.assertion_agent"

    def __init__(self, lockdown: LockdownServiceProvider):
        if isinstance(lockdown, LockdownClient):
            super().__init__(lockdown, self.SERVICE_NAME)
        else:
            super().__init__(lockdown, self.RSD_SERVICE_NAME)

    @contextlib.asynccontextmanager
    async def create_power_assertion(self, type_: str, name: str, timeout: float, details: Optional[str] = None):
        """
        Create a power assertion on the device, held for the duration of the ``with`` block.

        Sends a create-assertion command to the agent, which calls ``IOPMAssertionCreateWithName``
        on the device. This is an async context manager: the assertion stays active while the block
        is open.

        :param type_: IOKit assertion type (e.g. the assertion-type string passed to
            ``IOPMAssertionCreateWithName``).
        :param name: human-readable name identifying the assertion.
        :param timeout: assertion timeout in seconds, after which the device may release it.
        :param details: optional descriptive detail string attached to the assertion.
        """
        msg: dict[str, Any] = {
            "CommandKey": "CommandCreateAssertion",
            "AssertionTypeKey": type_,
            "AssertionNameKey": name,
            "AssertionTimeoutKey": timeout,
        }

        if details is not None:
            msg["AssertionDetailKey"] = details

        await self.service.send_recv_plist(msg)
        yield
