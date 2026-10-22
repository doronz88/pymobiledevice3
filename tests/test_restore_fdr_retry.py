import asyncio
import socket

import pytest

from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionTerminatedError
from pymobiledevice3.restore import fdr
from pymobiledevice3.service_connection import ServiceConnection


class _StubService:
    async def close(self) -> None:
        pass


class _StubClient:
    def __init__(self) -> None:
        self.service = _StubService()

    async def poll_and_handle_message(self) -> None:
        raise ConnectionTerminatedError()


@pytest.mark.asyncio
async def test_ctrl_listener_retries_until_the_device_reappears(monkeypatch):
    """Regression: the reverse-proxy control connection failed for good when the device re-enumerated."""
    calls = []

    async def fake_create(type_, udid=None):
        calls.append(type_)
        if len(calls) < 3:
            raise ConnectionFailedError()
        return _StubClient()

    async def no_sleep(_delay):
        pass

    monkeypatch.setattr(fdr.FDRClient, "create", staticmethod(fake_create))
    monkeypatch.setattr(fdr.asyncio, "sleep", no_sleep)

    await fdr.run_fdr_listener(fdr.fdr_type.FDR_CTRL)

    assert calls == [fdr.fdr_type.FDR_CTRL] * 3


@pytest.mark.asyncio
async def test_ctrl_listener_gives_up_after_the_attempt_budget(monkeypatch):
    calls = []

    async def fake_create(type_, udid=None):
        calls.append(type_)
        raise ConnectionFailedError()

    async def no_sleep(_delay):
        pass

    monkeypatch.setattr(fdr.FDRClient, "create", staticmethod(fake_create))
    monkeypatch.setattr(fdr.asyncio, "sleep", no_sleep)

    with pytest.raises(ConnectionFailedError):
        await fdr.run_fdr_listener(fdr.fdr_type.FDR_CTRL)

    assert len(calls) == fdr.CTRL_CONNECT_ATTEMPTS


@pytest.mark.asyncio
async def test_conn_listener_does_not_retry(monkeypatch):
    calls = []

    async def fake_create(type_, udid=None):
        calls.append(type_)
        raise ConnectionFailedError()

    monkeypatch.setattr(fdr.FDRClient, "create", staticmethod(fake_create))

    with pytest.raises(ConnectionFailedError):
        await asyncio.wait_for(fdr.run_fdr_listener(fdr.fdr_type.FDR_CONN), timeout=5)

    assert len(calls) == 1


@pytest.mark.asyncio
async def test_listener_finalized_mid_poll_releases_its_socket(monkeypatch):
    """A listener coroutine closed while it waits (GeneratorExit) cannot await its cleanup; it must
    still release the connection's socket."""
    sock, peer = socket.socketpair()
    service = await ServiceConnection.from_socket(sock)
    parked: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    class _Client:
        def __init__(self) -> None:
            self.service = service

        async def poll_and_handle_message(self) -> None:
            await parked

    async def fake_create(type_, udid=None):
        return _Client()

    monkeypatch.setattr(fdr, "_create_fdr_client", fake_create)
    listener = fdr.run_fdr_listener(fdr.fdr_type.FDR_CTRL)
    try:
        listener.send(None)  # runs until the poll waits on `parked`
        listener.close()
        await asyncio.sleep(0)  # let the transport's close callback run
        assert sock.fileno() == -1
    finally:
        parked.cancel()
        peer.close()
