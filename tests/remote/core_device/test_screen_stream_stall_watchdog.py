import asyncio
import json

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
    # The grace period of each fresh session reads as "back", then "gone" again.
    states = _online_states(queue)
    assert states[0] is False
    assert states[-1] is False


def test_a_device_that_answers_the_restart_is_forgiven():
    server, queue = _server()
    server._stream_started_t = server._last_packet_t = 100.0

    first = _run(server, 100.0, 12.0, sender_reports=False)
    assert len(first) == 1
    _run(server, 112.0, 30.0, sender_reports=True)

    assert server._consecutive_restarts == 0
    assert _online_states(queue)[-1] is True


def test_the_online_message_carries_the_current_state():
    server, _queue = _server()
    server._device_silent = True

    assert json.loads(server._device_online_message()[5:]) == {"online": False}
