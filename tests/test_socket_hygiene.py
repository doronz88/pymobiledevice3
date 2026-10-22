import socket

import pytest

from tests.conftest import _fd_kind, _open_fds


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
