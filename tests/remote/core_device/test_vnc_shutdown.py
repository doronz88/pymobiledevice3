import asyncio
import contextlib
import socket
from typing import Any

from pymobiledevice3.remote.core_device import vnc_server
from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.vnc_server import VncStreamServer
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


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
    server = VncStreamServer(RemoteServiceDiscoveryService(("127.0.0.1", 0)), port=port)
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
