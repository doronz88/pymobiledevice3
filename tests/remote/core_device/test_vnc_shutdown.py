import asyncio
import contextlib
import socket
from typing import Any

from pymobiledevice3.remote.core_device import vnc_server
from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.vnc_server import VncStreamServer
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


def _rsd() -> RemoteServiceDiscoveryService:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {"Properties": {"OSVersion": "27.0"}, "Services": {}}
    return rsd


class _Transport:
    port = 0

    def __init__(self) -> None:
        self.sent: list[tuple[bytes, str, int]] = []

    async def sendto(self, data: bytes, host: str, port: int) -> None:
        self.sent.append((data, host, port))

    def close(self) -> None:
        pass


def _without_device(monkeypatch: Any, serving: asyncio.Event) -> None:
    async def nothing(*args: Any, **kwargs: Any) -> None:
        pass

    async def start_video_stream(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {"connection": {"streamConfig": {}}}

    async def forever(*args: Any, **kwargs: Any) -> None:
        await asyncio.Event().wait()

    async def rtcp_send_loop(self: VncStreamServer, transport: Any) -> None:
        serving.set()  # started right before the listener, which serve() then waits on
        await asyncio.Event().wait()

    monkeypatch.setattr(DisplayService, "connect", nothing)
    monkeypatch.setattr(DisplayService, "close", nothing)
    monkeypatch.setattr(DisplayService, "start_video_stream", start_video_stream)
    monkeypatch.setattr(DisplayService, "stop_all_streams", nothing)
    monkeypatch.setattr(vnc_server, "open_media_receiver", lambda *args: (_Transport(), "127.0.0.1"))
    monkeypatch.setattr(VncStreamServer, "_udp_recv_and_pipe", forever)
    monkeypatch.setattr(VncStreamServer, "_decoder_refresh_loop", forever)
    monkeypatch.setattr(VncStreamServer, "_rtcp_send_loop", rtcp_send_loop)


async def test_shutdown_leaves_other_tasks_running_and_stops_its_clients(monkeypatch: Any) -> None:
    serving = asyncio.Event()
    _without_device(monkeypatch, serving)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = VncStreamServer(_rsd(), port=port)
    other = asyncio.create_task(asyncio.Event().wait())
    serve = asyncio.create_task(server.serve())
    await serving.wait()

    # a client still waiting for the first frame when the server stops
    while True:
        with contextlib.suppress(OSError):
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            break
        await asyncio.sleep(0.01)
    try:
        while not server._client_tasks:
            await asyncio.sleep(0.01)

        serve.cancel()
        await serve
        assert not server._client_tasks
        assert not other.done()
    finally:
        other.cancel()
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()


async def test_audio_keepalive_starts_before_any_audio_arrives() -> None:
    server = VncStreamServer(_rsd())
    server._audio_rtcp_dest = ("fd00::1", 5000)
    server._audio_local_ssrc = 1
    server._audio_remote_ssrc = 2
    transport = _Transport()
    loop_task = asyncio.create_task(server._audio_rtcp_send_loop(transport))  # type: ignore[arg-type]
    try:
        # a silent screen sends no audio, and the device reaps a session without RRs after ~20 s
        await asyncio.wait_for(_first_send(transport), timeout=3.0)
    finally:
        loop_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await loop_task
    assert transport.sent[0][1:] == ("fd00::1", 5000)


async def _first_send(transport: _Transport) -> None:
    while not transport.sent:
        await asyncio.sleep(0.05)
