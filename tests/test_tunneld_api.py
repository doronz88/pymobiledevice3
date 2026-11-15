import asyncio
import socket
import struct
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from pymobiledevice3.exceptions import DeviceNotFoundError
from pymobiledevice3.remote.remotexpc import HTTP2_MAGIC
from pymobiledevice3.tunneld import api as tunneld_api
from pymobiledevice3.tunneld import server as tunneld_server
from pymobiledevice3.tunneld.api import _create_rsds_from_tunnels, get_tunneld_device_by_udid


@pytest.mark.asyncio
async def test_create_rsds_skips_a_tunnel_that_resets_the_handshake():
    async def reset_after_preface(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readexactly(len(HTTP2_MAGIC))
        # Linger 0 makes the close send RST instead of FIN
        writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        writer.transport.abort()

    server = await asyncio.start_server(reset_after_preface, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        tunnels = {"dead": [{"tunnel-address": "127.0.0.1", "tunnel-port": port, "interface": "utun-test"}]}
        assert await _create_rsds_from_tunnels(tunnels, ("127.0.0.1", 49151), bridge=False) == []
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_device_by_udid_lists_tunneld_off_the_event_loop(monkeypatch):
    # The listing is a blocking HTTP request: it must not stall the event loop.
    import threading

    listed_on = []

    def list_tunnels(address):
        listed_on.append(threading.current_thread())
        return {}

    monkeypatch.setattr(tunneld_api, "_list_tunnels", list_tunnels)

    assert await get_tunneld_device_by_udid("UDID") is None
    assert listed_on and listed_on[0] is not threading.main_thread()


async def test_device_by_udid_returns_none_when_no_tunnel_under_the_key_connects(monkeypatch):
    async def nothing_connects(tunnels, address, bridge=None):
        return []

    monkeypatch.setattr(tunneld_api, "_list_tunnels", lambda address: {"UDID": [{}]})
    monkeypatch.setattr(tunneld_api, "_create_rsds_from_tunnels", nothing_connects)

    assert await get_tunneld_device_by_udid("UDID") is None


async def test_start_tunnel_falls_back_to_wifi_for_a_device_not_on_usb(monkeypatch):
    """Without a connection_type, /start-tunnel tries usbmux first; a device usbmux does not list
    must fall through to the other connection types instead of failing the request."""

    async def not_on_usb(udid, usbmux_address=None):
        raise DeviceNotFoundError(udid, f"Device not found: usbmux has no device matching udid {udid}")

    async def no_rsds(bonjour_timeout=None, udid=None):
        return []

    remotepairing = Mock(hostname="fd00::2", remote_identifier="DEVICE", close=AsyncMock())

    async def remote_pairing_services(bonjour_timeout=None, udid=None, excluded_identifiers=()):
        assert udid == "DEVICE"
        return [remotepairing]

    closed = asyncio.Event()

    @asynccontextmanager
    async def fake_start_tunnel(protocol_handler, protocol=None):
        client = Mock(wait_closed=closed.wait, stop_tunnel=AsyncMock())
        yield Mock(client=client, interface="utun9", address="fd00::3", port=1234, auxiliary_metadata={})

    monkeypatch.setattr(tunneld_server, "create_using_usbmux", not_on_usb)
    monkeypatch.setattr(tunneld_server, "get_rsds", no_rsds)
    monkeypatch.setattr(tunneld_server, "get_remote_pairing_tunnel_services", remote_pairing_services)
    monkeypatch.setattr(tunneld_server, "start_tunnel", fake_start_tunnel)
    runner = tunneld_server.TunneldRunner(
        "127.0.0.1", 0, usb_monitor=False, wifi_monitor=False, usbmux_monitor=False, mobdev2_monitor=False
    )
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=runner._app), base_url="http://t") as client:
            response = await client.get("/start-tunnel", params={"udid": "DEVICE"})
        assert response.status_code == 200, response.text
        assert response.json()["address"] == "fd00::3"
        assert runner._tunneld_core.get_tunnel("DEVICE") is not None
    finally:
        closed.set()
        await runner._tunneld_core.close()
