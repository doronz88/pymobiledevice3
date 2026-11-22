import asyncio
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import pytest
from hyperframe.frame import Frame, PingFrame

from pymobiledevice3.remote.core_device import screen_stream
from pymobiledevice3.remote.core_device.screen_stream import ScreenStreamServer
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

TICK = 1.25


def _server() -> tuple[ScreenStreamServer, asyncio.Queue[bytes]]:
    server = ScreenStreamServer(RemoteServiceDiscoveryService(("127.0.0.1", 0)))
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    server._subscribers[queue] = screen_stream._SubState()
    return server, queue


def _run(server: ScreenStreamServer, start: float, seconds: float, sender_reports: bool) -> list[float]:
    """Tick the watchdog over *seconds*; a restart opens a fresh session, as the real one does."""
    restarts = []
    now = start
    while now < start + seconds:
        now += TICK
        if sender_reports:
            server._last_packet_t = now
        if server._stall_restart_due(now):
            restarts.append(now)
            server._stream_started_t = now
    return restarts


def _online_states(queue: asyncio.Queue[bytes]) -> list[bool]:
    states = []
    while not queue.empty():
        message = queue.get_nowait()
        assert message[4] == 5
        states.append(json.loads(message[5:])["online"])
    return states


def test_an_idle_screen_is_not_a_stall():
    # No frame for ten minutes, only the device's once-a-second sender reports.
    server, queue = _server()
    server._stream_started_t = 100.0

    assert _run(server, 100.0, 600.0, sender_reports=True) == []
    assert _online_states(queue) == []


def test_a_silent_device_is_restarted_up_to_the_limit():
    server, queue = _server()
    server._stream_started_t = server._last_packet_t = 100.0

    restarts = _run(server, 100.0, 600.0, sender_reports=False)

    assert len(restarts) == screen_stream._MAX_STALL_RESTARTS
    assert restarts[0] - 100.0 > screen_stream._STALL_RESTART_SECS
    assert all(b - a >= screen_stream._STALL_RESTART_COOLDOWN_SECS for a, b in zip(restarts, restarts[1:]))
    # Told once: the grace period of each fresh session is not the device coming back.
    assert _online_states(queue) == [False]
    # Silence alone is not the device leaving: only a failed reachability probe is.
    assert not server._device_disconnected.is_set()


def test_a_device_that_answers_the_restart_is_forgiven():
    server, queue = _server()
    server._stream_started_t = server._last_packet_t = 100.0

    first = _run(server, 100.0, 12.0, sender_reports=False)
    assert len(first) == 1
    _run(server, 112.0, 30.0, sender_reports=True)

    assert server._consecutive_restarts == 0
    assert not server._device_disconnected.is_set()
    assert _online_states(queue) == [False, True]


def test_the_online_message_carries_the_current_state():
    server, _queue = _server()
    server._device_silent = True

    assert json.loads(server._device_online_message()[5:]) == {"online": False}


@asynccontextmanager
async def _device(answers_pings: bool = True, hangs_up: bool = False) -> AsyncGenerator[ScreenStreamServer, None]:
    """A server whose RSD connection reaches a peer speaking just enough HTTP/2 to be pinged."""

    async def peer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while not hangs_up:
                frame, size = Frame.parse_frame_header(memoryview(await reader.readexactly(9)))
                frame.parse_body(memoryview(await reader.readexactly(size)))
                if isinstance(frame, PingFrame) and answers_pings:
                    writer.write(PingFrame(opaque_data=frame.opaque_data, flags=["ACK"]).serialize())
        except asyncio.IncompleteReadError:
            pass
        finally:
            writer.close()

    listener = await asyncio.start_server(peer, "127.0.0.1", 0)
    async with listener:
        rsd = RemoteServiceDiscoveryService(("127.0.0.1", 0))
        rsd.service._reader, rsd.service._writer = await asyncio.open_connection(*listener.sockets[0].getsockname())
        try:
            yield ScreenStreamServer(rsd)
        finally:
            await rsd.service.close()


async def test_a_device_that_answers_the_ping_is_reachable():
    async with _device() as server:
        assert await asyncio.wait_for(server._device_reachable(), 5.0)
        # (And again: the connection is left usable.)
        assert await asyncio.wait_for(server._device_reachable(), 5.0)


async def test_a_device_that_never_answers_is_not_reachable(monkeypatch: pytest.MonkeyPatch):
    # Unplugged: nothing closes the connection, the answer just never comes.
    monkeypatch.setattr(screen_stream, "_REACHABILITY_PROBE_TIMEOUT_SECS", 0.2)

    async with _device(answers_pings=False) as server:
        assert not await asyncio.wait_for(server._device_reachable(), 5.0)


async def test_a_device_whose_connection_closed_is_not_reachable():
    async with _device(hangs_up=True) as server:
        assert not await asyncio.wait_for(server._device_reachable(), 5.0)


def test_the_probe_runs_only_while_nothing_arrives():
    server, _queue = _server()
    # Never started (the eager start failed): asked right away, then once per interval.
    assert server._reachability_probe_due(1000.0)
    server._last_probe_t = 1000.0
    assert not server._reachability_probe_due(1000.0 + screen_stream._REACHABILITY_PROBE_INTERVAL_SECS - 1)
    assert server._reachability_probe_due(1000.0 + screen_stream._REACHABILITY_PROBE_INTERVAL_SECS)
    # A session that sends, or one still within its grace period: not asked.
    server._last_packet_t = 2000.0
    assert not server._reachability_probe_due(2001.0)
    server._stream_started_t = 3000.0
    assert not server._reachability_probe_due(3001.0)
    assert server._reachability_probe_due(3000.0 + screen_stream._STALL_RESTART_SECS + 1)


async def _watch(server: ScreenStreamServer, seconds: float) -> None:
    watchdog = asyncio.create_task(server._stall_watchdog())
    try:
        await asyncio.wait_for(server._device_disconnected.wait(), seconds)
    except asyncio.TimeoutError:
        pass
    finally:
        watchdog.cancel()
        await asyncio.gather(watchdog, return_exceptions=True)


async def test_a_disconnect_is_noticed_when_the_stream_never_started(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(screen_stream, "_STALL_RESTART_SECS", 0.2)

    async with _device(hangs_up=True) as server:
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        server._subscribers[queue] = screen_stream._SubState()

        await _watch(server, 5.0)

    assert server._device_disconnected.is_set()
    # The viewers are told why their stream is about to end.
    assert json.loads(queue.get_nowait()[5:]) == {"online": False, "disconnected": True}


async def test_a_wedged_display_daemon_is_not_a_disconnect(monkeypatch: pytest.MonkeyPatch):
    # The device answers pings while its media session stays silent and restarts fail.
    monkeypatch.setattr(screen_stream, "_STALL_RESTART_SECS", 0.2)
    monkeypatch.setattr(screen_stream, "_STALL_RESTART_COOLDOWN_SECS", 0.3)
    monkeypatch.setattr(screen_stream, "_REACHABILITY_PROBE_INTERVAL_SECS", 0.3)
    restarts = 0

    async def failing_restart(force: bool = False) -> None:
        nonlocal restarts
        restarts += 1
        raise ConnectionRefusedError

    async with _device() as server:
        monkeypatch.setattr(server, "_ensure_fresh_stream", failing_restart)
        server._stream_started_t = server._last_packet_t = asyncio.get_running_loop().time()

        await _watch(server, 3.0)

    assert restarts == screen_stream._MAX_STALL_RESTARTS
    assert not server._device_disconnected.is_set()


async def test_the_watchdog_does_not_queue_behind_a_restart_in_flight(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(screen_stream, "_STALL_RESTART_SECS", 0.2)
    restarts = 0

    async def restart(force: bool = False) -> None:
        nonlocal restarts
        restarts += 1

    async with _device() as server:
        monkeypatch.setattr(server, "_ensure_fresh_stream", restart)
        server._stream_started_t = server._last_packet_t = asyncio.get_running_loop().time()

        async with server._stream_lock:
            await _watch(server, 1.5)

    assert restarts == 0
