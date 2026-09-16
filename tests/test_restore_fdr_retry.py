import asyncio

import pytest

from pymobiledevice3.exceptions import ConnectionFailedError, ConnectionTerminatedError
from pymobiledevice3.restore import fdr


class _StubService:
    socket = None

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
