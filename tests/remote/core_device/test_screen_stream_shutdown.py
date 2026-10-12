import asyncio

from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.screen_stream import ScreenStreamServer
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


async def test_cancelling_serve_leaves_other_tasks_running(monkeypatch):
    serving = asyncio.Event()

    async def no_device(*args, **kwargs):
        pass

    async def keep_awake(self):
        serving.set()  # runs once serve() is waiting to be stopped

    monkeypatch.setattr(ScreenStreamServer, "_eager_stream_start", no_device)
    monkeypatch.setattr(ScreenStreamServer, "_keep_awake_loop", keep_awake)
    monkeypatch.setattr(DisplayService, "stop_all_streams", no_device)

    server = ScreenStreamServer(RemoteServiceDiscoveryService(("127.0.0.1", 0)), http_port=0)
    other = asyncio.create_task(asyncio.Event().wait())
    serve = asyncio.create_task(server.serve())
    await serving.wait()

    serve.cancel()
    await serve
    assert not other.done()
    other.cancel()
