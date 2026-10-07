import dataclasses
import struct
import time

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.remote.remote_service import RemoteService
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

SNTP_PACKET_SIZE = 48
# LI = 0 (no warning), VN = 4, Mode = 3 (client)
SNTP_CLIENT_HEADER = 0x23
SNTP_MODE_SERVER = 4
# Seconds between the NTP epoch (1900) and the Unix epoch (1970)
NTP_UNIX_EPOCH_DELTA = 2208988800

_ORIGINATE_TIMESTAMP_OFFSET = 24
_RECEIVE_TIMESTAMP_OFFSET = 32
_TRANSMIT_TIMESTAMP_OFFSET = 40


def _pack_timestamp(unix_time: float) -> bytes:
    seconds = int(unix_time)
    return struct.pack(">II", seconds + NTP_UNIX_EPOCH_DELTA, int((unix_time - seconds) * (1 << 32)))


def _unpack_timestamp(buf: bytes) -> float:
    seconds, fraction = struct.unpack(">II", buf)
    return seconds - NTP_UNIX_EPOCH_DELTA + fraction / (1 << 32)


@dataclasses.dataclass(frozen=True)
class TimeSyncSample:
    """The outcome of one SNTP exchange with the device."""

    #: Seconds the device clock is ahead of the host clock (negative when it is behind).
    offset: float
    #: Round-trip network delay of the exchange, in seconds. The offset is accurate to half of it.
    delay: float
    #: Device wall-clock time (Unix timestamp) when it sent its reply.
    device_time: float
    #: The device's own estimate of how far its clock may be from true time, in seconds.
    root_dispersion: float
    stratum: int
    reference_id: bytes


class TimeSyncService(RemoteService):
    """
    Measure the device clock against the host clock over RemoteXPC.

    The device's ``timed`` answers SNTP (RFC 4330) requests carried as RemoteXPC messages instead of
    UDP datagrams, which gives a sub-millisecond reading of the device's wall clock without touching
    it. The service only answers; it does not let the host set the device time.

    Requires an RSD tunnel. Verified on iOS 27.2. Use as an async context manager.
    """

    SERVICE_NAME = "com.apple.timed.remote"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        """
        :param rsd: RSD provider used to open the RemoteXPC service.
        """
        super().__init__(rsd, self.SERVICE_NAME)

    async def exchange(self) -> TimeSyncSample:
        """
        Perform a single SNTP exchange.

        :returns: the measured offset and delay, along with the server fields of the reply.
        :raises PyMobileDevice3Exception: if the device's reply is not a valid answer to the request.
        """
        t1 = time.time()
        transmit_timestamp = _pack_timestamp(t1)
        request = bytes([SNTP_CLIENT_HEADER]) + bytes(_TRANSMIT_TIMESTAMP_OFFSET - 1) + transmit_timestamp
        response = await self.service.send_receive_request({"MessageType": "Timesync", "TimesyncPayload": request})
        t4 = time.time()

        payload = response.get("TimesyncPayload")
        if not isinstance(payload, bytes) or len(payload) != SNTP_PACKET_SIZE:
            raise PyMobileDevice3Exception(f"invalid timesync response: {response}")
        if payload[0] & 0x7 != SNTP_MODE_SERVER:
            raise PyMobileDevice3Exception(f"timesync response is not an SNTP server packet: {payload.hex()}")
        if payload[_ORIGINATE_TIMESTAMP_OFFSET:_RECEIVE_TIMESTAMP_OFFSET] != transmit_timestamp:
            raise PyMobileDevice3Exception("timesync response does not answer the request that was sent")

        t2 = _unpack_timestamp(payload[_RECEIVE_TIMESTAMP_OFFSET:_TRANSMIT_TIMESTAMP_OFFSET])
        t3 = _unpack_timestamp(payload[_TRANSMIT_TIMESTAMP_OFFSET:])
        return TimeSyncSample(
            offset=((t2 - t1) + (t3 - t4)) / 2,
            delay=(t4 - t1) - (t3 - t2),
            device_time=t3,
            root_dispersion=struct.unpack(">I", payload[8:12])[0] / (1 << 16),
            stratum=payload[1],
            reference_id=payload[12:16],
        )

    async def measure(self, samples: int = 8) -> TimeSyncSample:
        """
        Perform several exchanges and keep the one with the smallest round-trip delay.

        The offset error of an exchange is bounded by half its delay, so the quickest exchange is
        the most accurate one.

        :param samples: number of exchanges to perform.
        :returns: the sample with the lowest delay.
        """
        best = await self.exchange()
        for _ in range(samples - 1):
            sample = await self.exchange()
            if sample.delay < best.delay:
                best = sample
        return best
