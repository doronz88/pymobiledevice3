import asyncio

import pytest

from pymobiledevice3.exceptions import NotificationTimeoutError
from pymobiledevice3.services.notification_proxy import NotificationProxyService


class _FakeConnection:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True

    async def recv_plist(self) -> dict:
        await asyncio.Future()


class _FakeLockdown:
    def __init__(self) -> None:
        self.connection = _FakeConnection()
        self.started_services = []

    async def start_lockdown_service(self, service_name: str, include_escrow_bag: bool = False):
        self.started_services.append((service_name, include_escrow_bag))
        return self.connection


@pytest.mark.asyncio
async def test_notification_proxy_timeout_does_not_touch_lazy_connection() -> None:
    lockdown = _FakeLockdown()
    service = NotificationProxyService(lockdown, timeout=7)

    assert lockdown.started_services == []

    await service.connect()

    assert lockdown.started_services == [(NotificationProxyService.SERVICE_NAME, False)]


@pytest.mark.asyncio
async def test_receive_notification_raises_notification_timeout() -> None:
    service = NotificationProxyService(_FakeLockdown(), timeout=0.01)
    await service.connect()

    with pytest.raises(NotificationTimeoutError):
        async for _ in service.receive_notification():
            pass
