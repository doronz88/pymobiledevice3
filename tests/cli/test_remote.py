import pytest

from pymobiledevice3.cli import remote
from pymobiledevice3.exceptions import NoDeviceConnectedError
from pymobiledevice3.remote.common import ConnectionType


@pytest.mark.asyncio
async def test_start_tunnel_task_retries_empty_discovery(monkeypatch):
    service = object()
    discoveries = iter(([], [service]))
    tunnel_services_calls = 0
    tunnel_task_service = None

    async def get_tunnel_services(udid=None):
        nonlocal tunnel_services_calls
        tunnel_services_calls += 1
        return next(discoveries)

    async def tunnel_task(selected_service, **kwargs):
        nonlocal tunnel_task_service
        tunnel_task_service = selected_service

    monkeypatch.setattr(remote, "get_core_device_tunnel_services", get_tunnel_services)
    monkeypatch.setattr(remote, "tunnel_task", tunnel_task)

    await remote.start_tunnel_task(ConnectionType.USB, secrets=None)

    assert tunnel_services_calls == 2
    assert tunnel_task_service is service


@pytest.mark.asyncio
async def test_start_tunnel_task_raises_after_discovery_retries(monkeypatch):
    tunnel_services_calls = 0

    async def get_tunnel_services(udid=None):
        nonlocal tunnel_services_calls
        tunnel_services_calls += 1
        return []

    monkeypatch.setattr(remote, "get_core_device_tunnel_services", get_tunnel_services)

    with pytest.raises(NoDeviceConnectedError):
        await remote.start_tunnel_task(ConnectionType.USB, secrets=None)

    assert tunnel_services_calls == remote.TUNNEL_SERVICE_DISCOVERY_ATTEMPTS
