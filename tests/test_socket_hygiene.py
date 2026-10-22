import asyncio
import socket

import pytest

from tests.conftest import _fd_kind, _leaks, _open_fds, _recording_sockets


@pytest.mark.skipif(not hasattr(socket, "AF_ROUTE"), reason="needs a socket family socket() cannot describe")
def test_inspecting_an_undescribable_socket_opens_no_fd() -> None:
    try:
        route = socket.socket(socket.AF_ROUTE, socket.SOCK_RAW)
    except OSError:
        pytest.skip("cannot open an AF_ROUTE socket here")
    with route:
        before = _open_fds()
        assert before is not None
        for _ in range(10):
            assert _fd_kind(route.fileno()) is not None
        assert _open_fds() == before


# fds_before=None below is how the check runs where fds can't be listed (Windows): the socket
# objects alone must reveal the leak.


def test_an_open_socket_is_a_leak_until_closed() -> None:
    with _recording_sockets() as recording:
        left, right = socket.socketpair()
        assert len(_leaks(recording, None)) == 2
        left.close()
        right.close()
        assert _leaks(recording, None) == []


def test_an_accepted_socket_is_a_leak_until_closed() -> None:
    server = socket.create_server(("127.0.0.1", 0))
    client = socket.create_connection(server.getsockname())
    with server, client, _recording_sockets() as recording:
        accepted, _ = server.accept()
        assert len(_leaks(recording, None)) == 1
        accepted.close()


def test_an_unclosed_event_loop_is_a_leak() -> None:
    with _recording_sockets() as recording:
        loop = asyncio.new_event_loop()
        assert _leaks(recording, None) != []
        loop.close()
        assert _leaks(recording, None) == []


def test_ending_a_nested_recording_leaves_the_outer_one_recording() -> None:
    with _recording_sockets() as outer:
        with _recording_sockets():
            pass
        left, right = socket.socketpair()
        assert len(_leaks(outer, None)) == 2
        left.close()
        right.close()
