import io
import plistlib

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


@pytest.mark.asyncio
async def test_validation_handles_second_initiate(monkeypatch):
    """A further Initiate during validation (iBridgeOS 9.0+) re-sends the packet info and switches Checksum Chunks."""
    filesystem = io.BytesIO(bytes(range(256)) * 4)
    incoming = [
        {"Command": "OOBData", "OOB Offset": 0, "OOB Length": 64},
        {"Command": "Initiate", "Checksum Chunks": True},
        {"Command": "OOBData", "OOB Offset": 128, "OOB Length": 16},
        {"Command": "Payload"},
    ]
    sent = []

    async def fake_recv_plist(self):
        return incoming.pop(0)

    async def fake_send_buffer(self, buf):
        sent.append(buf)

    monkeypatch.setattr(asr.ASRClient, "recv_plist", fake_recv_plist)
    monkeypatch.setattr(asr.ASRClient, "send_buffer", fake_send_buffer)

    client = asr.ASRClient("udid")
    await client.perform_validation(filesystem)

    assert incoming == []
    assert client.checksum_chunks is True
    assert len(sent) == 4
    first_info, first_oob, second_info, second_oob = sent
    assert "Checksum Chunk Size" not in plistlib.loads(first_info)
    assert first_oob == filesystem.getvalue()[:64]
    second = plistlib.loads(second_info)
    assert second["Checksum Chunk Size"] == asr.ASR_CHECKSUM_CHUNK_SIZE
    assert second["Payload"] == {"Port": 1, "Size": len(filesystem.getvalue())}
    assert second_oob == filesystem.getvalue()[128:144]
