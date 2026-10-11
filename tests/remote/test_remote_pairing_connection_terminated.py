import asyncio
import socket
import struct
from contextlib import suppress
from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import ConnectionTerminatedError
from pymobiledevice3.remote.core_device.file_service import FEATURE_TRANSFER_FILES, Domain, FileServiceService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.remote.tunnel_service import (
    PairableHost,
    PairableHostInfo,
    RemotePairingTcpTunnel,
    RemotePairingTunnelService,
)

DROPS = pytest.mark.parametrize("reset", [False, True], ids=["close", "reset"])


async def _dropped_connection(reset: bool) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Streams of a loopback connection the peer then closed (FIN) or reset (RST)."""
    with socket.create_server(("127.0.0.1", 0)) as server:
        host = socket.create_connection(server.getsockname())
        device, _ = server.accept()
    streams = await asyncio.open_connection(sock=host)
    if reset:
        # Linger 0 makes close() send RST instead of FIN
        device.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    device.close()
    return streams


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with suppress(OSError):
        await writer.wait_closed()


async def _keep_sending(send: Any) -> None:
    # asyncio only notices the drop once it reads it, so the first sends may still be accepted
    for _ in range(200):
        await send()
        await asyncio.sleep(0.01)


@pytest.mark.asyncio
@DROPS
async def test_remote_pairing_receive_after_peer_dropped_raises_connection_terminated(reset: bool) -> None:
    service = RemotePairingTunnelService("identifier", "127.0.0.1", 0)
    service._reader, service._writer = await _dropped_connection(reset)
    try:
        with pytest.raises(ConnectionTerminatedError):
            await service.receive_response()
    finally:
        await service.close()


@pytest.mark.asyncio
@DROPS
async def test_remote_pairing_send_after_peer_dropped_raises_connection_terminated(reset: bool) -> None:
    service = RemotePairingTunnelService("identifier", "127.0.0.1", 0)
    service._reader, service._writer = await _dropped_connection(reset)
    try:
        with pytest.raises(ConnectionTerminatedError):
            await _keep_sending(lambda: service.send_request({"key": "value"}))
    finally:
        await service.close()


@pytest.mark.asyncio
@DROPS
async def test_remote_pairing_close_after_failed_receive_does_not_raise(reset: bool) -> None:
    # connect() closes the service on its way out of a failure, so an error from close() would replace the real one
    service = RemotePairingTunnelService("identifier", "127.0.0.1", 0)
    service._reader, service._writer = await _dropped_connection(reset)
    with pytest.raises(ConnectionTerminatedError):
        await service.receive_response()
    await service.close()


@pytest.mark.asyncio
@DROPS
async def test_tunnel_establish_after_peer_dropped_raises_connection_terminated(reset: bool) -> None:
    reader, writer = await _dropped_connection(reset)
    try:
        with pytest.raises(ConnectionTerminatedError):
            await RemotePairingTcpTunnel(reader, writer).request_tunnel_establish()
    finally:
        await _close(writer)


@pytest.mark.asyncio
@DROPS
async def test_pairable_host_accept_after_peer_dropped_raises_connection_terminated(reset: bool) -> None:
    reader, writer = await _dropped_connection(reset)
    host = PairableHost(reader, writer, PairableHostInfo(name="My Mac", model="Mac17,7", udid="HOST-UDID-1234"))
    try:
        with pytest.raises(ConnectionTerminatedError):
            await host.accept()
    finally:
        await _close(writer)


@pytest.mark.asyncio
@DROPS
async def test_pairable_host_send_after_peer_dropped_raises_connection_terminated(reset: bool) -> None:
    reader, writer = await _dropped_connection(reset)
    host = PairableHost(reader, writer, PairableHostInfo(name="My Mac", model="Mac17,7", udid="HOST-UDID-1234"))
    try:
        with pytest.raises(ConnectionTerminatedError):
            await _keep_sending(lambda: host._send_plain({"key": "value"}))
    finally:
        await _close(writer)


@pytest.mark.asyncio
@DROPS
async def test_retrieve_file_after_data_channel_dropped_raises_connection_terminated(reset: bool) -> None:
    class ControlConnection:
        address = ("127.0.0.1", 0)

        async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
            return {"Response": 1, "NewFileID": 2}

    writers: list[asyncio.StreamWriter] = []

    async def open_connection(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await _dropped_connection(reset)
        writers.append(writer)
        return reader, writer

    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0), open_connection=open_connection)
    rsd.peer_info = {
        "Properties": {"OSVersion": "26.0"},
        "Services": {
            FileServiceService.CTRL_SERVICE_NAME: {
                "Port": "1024",
                "Properties": {"Features": [FEATURE_TRANSFER_FILES]},
            },
            "com.apple.coredevice.fileservice.data": {"Port": "1025"},
        },
    }
    rsd.udid = "udid"
    service = FileServiceService(rsd, Domain.TEMPORARY)
    service.session = "session-id"
    service._service = cast(RemoteXPCConnection, ControlConnection())
    try:
        with pytest.raises(ConnectionTerminatedError):
            await service.retrieve_file("file")
    finally:
        for writer in writers:
            await _close(writer)
