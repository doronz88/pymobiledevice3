import asyncio
import contextlib

from pymobiledevice3.remote.core_device import screen_stream
from pymobiledevice3.remote.core_device.display_service import DisplayService
from pymobiledevice3.remote.core_device.screen_stream import ScreenStreamServer
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

_REAL_SLEEP = asyncio.sleep


def _server() -> ScreenStreamServer:
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
    rsd.peer_info = {"Properties": {"OSVersion": "27.0"}, "Services": {DisplayService.SERVICE_NAME: {"Port": "1024"}}}
    server = ScreenStreamServer(rsd, http_port=0)
    server._subscribers[asyncio.Queue()] = screen_stream._SubState()
    server._active_service = object()
    return server


def _fast(monkeypatch, server: ScreenStreamServer, real_au_after_restart: bool) -> list[int]:
    restarts: list[int] = []

    async def fast_sleep(_delay):
        await _REAL_SLEEP(0.01)

    async def restart(force=False):
        loop = asyncio.get_running_loop()
        restarts.append(server._consecutive_restarts)
        server._last_good_au_t = loop.time()  # the grace period a fresh session gets
        if real_au_after_restart:
            await _REAL_SLEEP(0.05)  # the clock must tick between the restart and the AU
            server._last_real_au_t = loop.time()

    monkeypatch.setattr(screen_stream.asyncio, "sleep", fast_sleep)
    monkeypatch.setattr(screen_stream, "_STALL_RESTART_SECS", 0.1)
    monkeypatch.setattr(screen_stream, "_STALL_RESTART_COOLDOWN_SECS", 0.1)
    monkeypatch.setattr(server, "_ensure_fresh_stream", restart)
    return restarts


async def _run_watchdog(server: ScreenStreamServer, seconds: float) -> None:
    task = asyncio.create_task(server._stall_watchdog())
    await _REAL_SLEEP(seconds)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


async def test_restarts_stop_at_the_limit_when_no_au_ever_arrives(monkeypatch):
    server = _server()
    restarts = _fast(monkeypatch, server, real_au_after_restart=False)

    await _run_watchdog(server, 1.5)

    assert len(restarts) == screen_stream._MAX_STALL_RESTARTS
    assert server._consecutive_restarts == screen_stream._MAX_STALL_RESTARTS


async def test_counter_is_forgiven_once_an_au_arrives_after_a_restart(monkeypatch):
    server = _server()
    restarts = _fast(monkeypatch, server, real_au_after_restart=True)

    await _run_watchdog(server, 1.5)

    assert len(restarts) > screen_stream._MAX_STALL_RESTARTS
    assert set(restarts) == {1}  # every stall starts a fresh episode
