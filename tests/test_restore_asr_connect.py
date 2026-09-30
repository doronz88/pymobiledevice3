import pytest

from pymobiledevice3.exceptions import ConnectionFailedError
from pymobiledevice3.restore import asr


class _StubService:
    async def start(self) -> None:
        pass


async def _no_sleep(_delay):
    pass


@pytest.mark.asyncio
async def test_connect_retries_until_asr_listens(monkeypatch):
    calls = []

    async def fake_create(udid, port, connection_type=None):
        calls.append(port)
        if len(calls) < 3:
            raise ConnectionFailedError()
        return _StubService()

    async def fake_recv_plist(self):
        return {"Command": "Initiate"}

    monkeypatch.setattr(asr.ServiceConnection, "create_using_usbmux", staticmethod(fake_create))
    monkeypatch.setattr(asr.ASRClient, "recv_plist", fake_recv_plist)
    monkeypatch.setattr(asr.asyncio, "sleep", _no_sleep)

    await asr.ASRClient("udid").connect(asr.DEFAULT_ASR_SYNC_PORT)

    assert calls == [asr.DEFAULT_ASR_SYNC_PORT] * 3


@pytest.mark.asyncio
async def test_connect_gives_up_after_the_attempt_budget(monkeypatch):
    """Regression: the ASR connect loop retried forever, without a delay, when restored never listened."""
    calls = []

    async def fake_create(udid, port, connection_type=None):
        calls.append(port)
        raise ConnectionFailedError()

    monkeypatch.setattr(asr.ServiceConnection, "create_using_usbmux", staticmethod(fake_create))
    monkeypatch.setattr(asr.asyncio, "sleep", _no_sleep)

    with pytest.raises(ConnectionFailedError):
        await asr.ASRClient("udid").connect(asr.DEFAULT_ASR_SYNC_PORT)

    assert len(calls) == asr.ASR_CONNECT_ATTEMPTS
