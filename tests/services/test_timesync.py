import struct
from typing import Any, cast

import pytest

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
from pymobiledevice3.services.timesync import NTP_UNIX_EPOCH_DELTA, TimeSyncService


def _timestamp(unix_time: float) -> bytes:
    return struct.pack(">II", int(unix_time) + NTP_UNIX_EPOCH_DELTA, int((unix_time % 1) * (1 << 32)))


class FakeSntpServer:
    """Answers each request like the device does: a clock `skew` seconds ahead, replying instantly."""

    def __init__(self, skew: float = 0.0, mode: int = 4, echo_originate: bool = True) -> None:
        self.requests: list[dict[str, Any]] = []
        self._skew = skew
        self._mode = mode
        self._echo_originate = echo_originate

    async def send_receive_request(self, request: dict[str, Any]) -> dict[str, Any]:
        self.requests.append(request)
        payload = request["TimesyncPayload"]
        seconds, fraction = struct.unpack(">II", payload[40:])
        now = _timestamp(seconds - NTP_UNIX_EPOCH_DELTA + fraction / (1 << 32) + self._skew)
        originate = payload[40:] if self._echo_originate else bytes(8)
        header = bytes([(4 << 3) | self._mode, 1, 0, 0]) + bytes(4) + struct.pack(">I", 0x8000) + b"LCOL"
        return {"TimesyncPayload": header + bytes(8) + originate + now + now}


def _service(server: FakeSntpServer) -> TimeSyncService:
    service = TimeSyncService(cast(RemoteServiceDiscoveryService, object()))
    service._service = cast(RemoteXPCConnection, server)
    return service


@pytest.mark.asyncio
async def test_exchange_sends_an_sntp_client_packet() -> None:
    server = FakeSntpServer()

    await _service(server).exchange()

    (request,) = server.requests
    assert request["MessageType"] == "Timesync"
    payload = request["TimesyncPayload"]
    assert len(payload) == 48 and payload[0] == 0x23 and payload[1:40] == bytes(39)


@pytest.mark.asyncio
async def test_exchange_reports_the_device_clock_skew() -> None:
    sample = await _service(FakeSntpServer(skew=5.0)).exchange()

    assert sample.offset == pytest.approx(5.0, abs=0.05)
    assert 0 <= sample.delay < 0.1
    assert sample.root_dispersion == 0.5
    assert sample.stratum == 1 and sample.reference_id == b"LCOL"


@pytest.mark.asyncio
@pytest.mark.parametrize("server", [FakeSntpServer(mode=3), FakeSntpServer(echo_originate=False)])
async def test_exchange_rejects_a_reply_that_does_not_answer_the_request(server: FakeSntpServer) -> None:
    with pytest.raises(PyMobileDevice3Exception):
        await _service(server).exchange()


@pytest.mark.asyncio
async def test_measure_performs_the_requested_number_of_exchanges() -> None:
    server = FakeSntpServer()

    await _service(server).measure(samples=5)

    assert len(server.requests) == 5


@pytest.mark.asyncio
async def test_device_clock_is_close_to_host_clock_on_device(service_provider) -> None:
    """Several exchanges on one connection; an automatically set device clock is within seconds of the host's."""
    if not isinstance(service_provider, RemoteServiceDiscoveryService):
        pytest.skip("timesync requires an RSD tunnel")

    async with TimeSyncService(service_provider) as timesync:
        sample = await timesync.measure()

    assert sample.delay >= 0
    assert abs(sample.offset) < 10
