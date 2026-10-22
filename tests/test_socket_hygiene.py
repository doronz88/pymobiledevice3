import asyncio
import socket
from pathlib import Path

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
        assert _leaks(recording, None) == {}


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
        assert _leaks(recording, None) != {}
        loop.close()
        assert _leaks(recording, None) == {}


def test_ending_a_nested_recording_leaves_the_outer_one_recording() -> None:
    with _recording_sockets() as outer:
        with _recording_sockets():
            pass
        left, right = socket.socketpair()
        assert len(_leaks(outer, None)) == 2
        left.close()
        right.close()


_LEAKY_FIXTURE_SUITE = """
import socket

import pytest

_kept = []


@pytest.fixture(scope="module")
def leaky_server():
    _kept.append(socket.socket())
    yield


@pytest.fixture(scope="session")
def session_server():
    sock = socket.socket()
    yield
    sock.close()


def test_uses_a_leaky_module_fixture(leaky_server, session_server):
    pass
"""

_LEAKY_TEST_SUITE = """
import socket

import pytest

_kept = []


@pytest.fixture(scope="module")
def clean_server():
    with socket.socket():
        yield


def test_leaks_a_socket(clean_server):
    _kept.append(socket.socket())


def test_uses_a_clean_module_fixture(clean_server):
    pass
"""


def test_a_leak_is_reported_once_by_whoever_opened_it(pytester: pytest.Pytester) -> None:
    tests = Path(__file__).parent
    pytester.makeini((tests.parent / "pytest.ini").read_text())
    pytester.makeconftest((tests / "conftest.py").read_text())
    pytester.makepyfile(test_a_leaky_fixture=_LEAKY_FIXTURE_SUITE, test_b_leaky_test=_LEAKY_TEST_SUITE)
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider")
    result.assert_outcomes(passed=3, errors=2)
    result.stdout.fnmatch_lines(["ERROR test_a_leaky_fixture.py::test_uses_a_leaky_module_fixture - *"])
    result.stdout.fnmatch_lines(["ERROR test_b_leaky_test.py::test_leaks_a_socket - *"])
    fixture_leaks = [line for line in result.outlines if "fixture '" in line and "' left: " in line]
    assert fixture_leaks
    assert all("fixture 'leaky_server' left: " in line for line in fixture_leaks)
