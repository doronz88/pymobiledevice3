import asyncio
import time
from typing import Any, Optional, cast

import pytest

from pymobiledevice3.exceptions import NotificationTimeoutError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.services.notification_proxy import NotificationProxyService

PROBE_NOTIFICATION = "com.apple.pymobiledevice3.test.notification"


class FakeConnection:
    """Answers with the queued messages, then never again, like a device with nothing to relay."""

    def __init__(self, inbound: list[dict[str, Any]]) -> None:
        self.sent: list[dict[str, Any]] = []
        self._inbound = list(inbound)

    async def send_plist(self, d: dict[str, Any]) -> None:
        self.sent.append(d)

    async def recv_plist(self) -> dict[str, Any]:
        if self._inbound:
            return self._inbound.pop(0)
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    async def close(self) -> None:
        pass


def _service(
    inbound: Optional[list[dict[str, Any]]] = None, timeout: Optional[float] = None
) -> NotificationProxyService:
    service = NotificationProxyService(cast(LockdownServiceProvider, object()), timeout=timeout)
    service._service = cast(ServiceConnection, FakeConnection(inbound if inbound is not None else []))
    return service


def test_timeout_does_not_connect() -> None:
    # The service connects lazily, so the constructor must not touch the connection.
    service = NotificationProxyService(cast(LockdownServiceProvider, object()), timeout=5)

    assert service.timeout == 5
    assert service._service is None


@pytest.mark.asyncio
async def test_receive_notification_times_out() -> None:
    service = _service(timeout=0.1)

    start = time.monotonic()
    with pytest.raises(NotificationTimeoutError):
        async for _ in service.receive_notification():
            pass
    assert time.monotonic() - start < 2


@pytest.mark.asyncio
async def test_receive_notification_yields_before_timeout() -> None:
    relayed = {"Command": "RelayNotification", "Name": PROBE_NOTIFICATION}
    service = _service([relayed], timeout=0.1)

    received = []
    with pytest.raises(NotificationTimeoutError):
        async for event in service.receive_notification():
            received.append(event)
    assert received == [relayed]


@pytest.mark.asyncio
async def test_receive_notification_times_out_on_device(lockdown: LockdownClient) -> None:
    async with NotificationProxyService(lockdown, timeout=1) as service:
        await service.notify_register_dispatch(PROBE_NOTIFICATION)
        start = time.monotonic()
        with pytest.raises(NotificationTimeoutError):
            async for _ in service.receive_notification():
                pass
        assert time.monotonic() - start < 5
