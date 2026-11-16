import asyncio
import time
from contextlib import AbstractAsyncContextManager
from typing import Any

import pytest

import pymobiledevice3.remote.tunnel_service as tunnel_service
import pymobiledevice3.remote.userspace_tunnel as ut
from pymobiledevice3.remote.tunnel_service import RemotePairingTunnelService, StartTcpTunnel, TunnelResult


class _ProviderError(Exception):
    pass


class _FailingProvider(StartTcpTunnel):
    def __init__(self) -> None:
        self.closed = False

    @property
    def remote_identifier(self) -> str:
        return "UDID"

    def start_tcp_tunnel(self) -> AbstractAsyncContextManager[TunnelResult]:
        raise _ProviderError

    async def close(self) -> None:
        self.closed = True


async def _never_connects(*args: Any, **kwargs: Any) -> Any:
    await asyncio.sleep(3600)


@pytest.mark.asyncio
async def test_provider_factory_replaces_the_default_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    async def default_selection(*args: Any, **kwargs: Any) -> ut.TunnelProvider:
        raise AssertionError("the default provider selection must not run")

    monkeypatch.setattr(ut, "_create_no_root_tunnel_provider", default_selection)
    monkeypatch.setattr(ut, "_active_tunnel", None)
    provider = _FailingProvider()

    async def factory() -> ut.TunnelProvider:
        return ut.TunnelProvider(provider)

    tunnel = ut.UserspaceRsdTunnel(serial="UDID", provider_factory=factory)
    with pytest.raises(_ProviderError):
        await tunnel.aopen()
    assert provider.closed
    assert tunnel.rsd is None
    assert ut._active_tunnel is None


@pytest.mark.asyncio
async def test_connect_timeout_overrides_the_module_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tunnel_service, "TIMEOUT", 3600)
    monkeypatch.setattr(tunnel_service.asyncio, "open_connection", _never_connects)
    service = RemotePairingTunnelService("identifier", "192.0.2.1", 49152, connect_timeout=0.05)
    started = time.monotonic()
    with pytest.raises(asyncio.TimeoutError):
        await service.connect(autopair=False)
    assert time.monotonic() - started < 5


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "create",
    [
        tunnel_service.create_core_device_tunnel_service_using_remotepairing,
        tunnel_service.create_core_device_service_using_remotepairing_manual_pairing,
    ],
)
async def test_creators_forward_the_connect_timeout(monkeypatch: pytest.MonkeyPatch, create: Any) -> None:
    monkeypatch.setattr(tunnel_service, "TIMEOUT", 3600)
    monkeypatch.setattr(tunnel_service.asyncio, "open_connection", _never_connects)
    started = time.monotonic()
    with pytest.raises(asyncio.TimeoutError):
        await create("identifier", "192.0.2.1", 49152, autopair=False, connect_timeout=0.05)
    assert time.monotonic() - started < 5


def test_connect_timeout_defaults_to_the_module_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tunnel_service, "TIMEOUT", 7)
    assert RemotePairingTunnelService("identifier", "192.0.2.1", 49152)._connect_timeout == 7
