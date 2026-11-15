import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any, cast
from unittest.mock import AsyncMock, Mock

import pytest

from pymobiledevice3.exceptions import QuicProtocolNotSupportedError
from pymobiledevice3.remote import tunnel_service
from pymobiledevice3.remote.tunnel_service import RemotePairingProtocol, RemotePairingQuicTunnel, RemotePairingTunnel


@pytest.mark.asyncio
async def test_stop_tunnel_closes_the_tun_device_after_the_keep_alive_failed() -> None:
    # A device that vanished leaves a ping unanswered, so the keep-alive task has already ended with
    # the connection's error by the time the tunnel is stopped.
    async def failed_keep_alive() -> None:
        raise ConnectionError("ping was never answered")

    tunnel = cast(Any, RemotePairingQuicTunnel.__new__(RemotePairingQuicTunnel))
    RemotePairingTunnel.__init__(tunnel)
    tun = Mock(close=Mock(return_value=None))
    tunnel.tun = tun
    tunnel._keep_alive_task = asyncio.create_task(failed_keep_alive())
    await asyncio.wait({tunnel._keep_alive_task})

    await tunnel.stop_tunnel()

    tun.close.assert_called_once_with()
    assert tunnel.tun is None


def _quic_protocol(client: Mock, monkeypatch: pytest.MonkeyPatch) -> Any:
    @asynccontextmanager
    async def fake_connect(host: str, port: int, **kwargs: Any):
        yield client

    monkeypatch.setattr(tunnel_service, "aioquic_connect", fake_connect)
    return Mock(
        create_quic_listener=AsyncMock(return_value={"port": 1}),
        hostname="fd00::1",
        remote_identifier="DEVICE",
        auxiliary_metadata=None,
        logger=logging.getLogger(__name__),
    )


def _quic_client(**overrides: Any) -> Mock:
    handshake = {
        "clientParameters": {"address": "fd00::2", "mtu": 1280},
        "serverAddress": "fd00::1",
        "serverRSDPort": 2,
    }
    methods: dict[str, Any] = {
        "wait_connected": AsyncMock(),
        "request_tunnel_establish": AsyncMock(return_value=handshake),
        "start_tunnel": AsyncMock(),
        "stop_tunnel": AsyncMock(),
    }
    methods.update(overrides)
    return Mock(**methods)


@pytest.mark.asyncio
async def test_a_refused_quic_connection_is_reported_as_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _quic_client(wait_connected=AsyncMock(side_effect=ConnectionError()))
    protocol = _quic_protocol(client, monkeypatch)

    with pytest.raises(QuicProtocolNotSupportedError):
        async with RemotePairingProtocol.start_quic_tunnel(protocol):
            pass


@pytest.mark.asyncio
async def test_a_dropped_quic_tunnel_is_not_reported_as_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _quic_client()
    protocol = _quic_protocol(client, monkeypatch)

    with pytest.raises(ConnectionResetError):
        async with RemotePairingProtocol.start_quic_tunnel(protocol):
            raise ConnectionResetError("the device went away")

    client.stop_tunnel.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_a_quic_tunnel_cancelled_while_starting_closes_the_tun_device(monkeypatch: pytest.MonkeyPatch) -> None:
    # The userspace tun device comes up asynchronously, so a cancellation can land once the device
    # exists but before the tunnel is handed to the caller.
    blocked = asyncio.Event()

    async def hanging_up() -> None:
        blocked.set()
        await asyncio.Event().wait()

    tun = Mock(up=hanging_up, close=Mock(return_value=None))
    monkeypatch.setattr(tunnel_service, "create_tun_device", lambda interface_name: tun)
    client = cast(Any, RemotePairingQuicTunnel.__new__(RemotePairingQuicTunnel))
    RemotePairingTunnel.__init__(client)
    client._keep_alive_task = None
    client.wait_connected = AsyncMock()
    client.request_tunnel_establish = AsyncMock(return_value={"clientParameters": {"address": "fd00::2", "mtu": 1280}})
    protocol = _quic_protocol(client, monkeypatch)

    async def start() -> None:
        async with RemotePairingProtocol.start_quic_tunnel(protocol):
            pass

    task = asyncio.create_task(start())
    await asyncio.wait_for(blocked.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    tun.close.assert_called_once_with()
    assert client.tun is None
