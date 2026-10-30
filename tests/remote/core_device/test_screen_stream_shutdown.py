import asyncio
import contextlib
import socket

from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.screen_stream import ScreenStreamServer
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService


def _rsd() -> RemoteServiceDiscoveryService:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {"Properties": {"OSVersion": "27.0"}, "Services": {}}
    return rsd


async def test_cancelling_serve_leaves_other_tasks_running(monkeypatch):
    serving = asyncio.Event()

    async def no_device(*args, **kwargs):
        pass

    async def keep_awake(self):
        serving.set()  # runs once serve() is waiting to be stopped

    monkeypatch.setattr(ScreenStreamServer, "_eager_stream_start", no_device)
    monkeypatch.setattr(ScreenStreamServer, "_keep_awake_loop", keep_awake)
    monkeypatch.setattr(DisplayService, "stop_all_streams", no_device)

    server = ScreenStreamServer(_rsd(), http_port=0)
    other = asyncio.create_task(asyncio.Event().wait())
    serve = asyncio.create_task(server.serve())
    await serving.wait()

    serve.cancel()
    await serve
    assert not other.done()
    other.cancel()


async def test_shutdown_stops_connection_handlers_before_the_device_side(monkeypatch):
    serving = asyncio.Event()
    live_handlers_at_teardown = []

    async def no_device(*args, **kwargs):
        pass

    async def keep_awake(self):
        serving.set()  # runs once serve() is waiting to be stopped

    async def stop_hid(self):
        # the first device-side teardown step: a handler alive past this point could
        # bring back what the teardown stops, with nothing left to stop it again
        live_handlers_at_teardown.extend(task for task in self._http_tasks if not task.done())

    monkeypatch.setattr(ScreenStreamServer, "_eager_stream_start", no_device)
    monkeypatch.setattr(ScreenStreamServer, "_keep_awake_loop", keep_awake)
    monkeypatch.setattr(ScreenStreamServer, "_stop_hid", stop_hid)
    monkeypatch.setattr(DisplayService, "stop_all_streams", no_device)

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = ScreenStreamServer(_rsd(), http_port=port)
    serve = asyncio.create_task(server.serve())
    await serving.wait()

    # an idle keep-alive connection: its handler waits for a request that never comes
    _, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        while not server._http_tasks:
            await asyncio.sleep(0.01)

        serve.cancel()
        started = asyncio.get_running_loop().time()
        await serve
        assert live_handlers_at_teardown == []
        assert not server._http_tasks
        # and the listener closes at once instead of waiting out its timeout on the handler
        assert asyncio.get_running_loop().time() - started < 1.5
    finally:
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
