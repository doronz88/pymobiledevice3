import asyncio
import logging
import random
import re
from abc import abstractmethod
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple, Optional

from defusedxml import ElementTree as DefusedET

# The xsd:dateTime of a GPX <time>, with the leniency GPS loggers need: a space for the "T",
# unpadded fields, any number of fraction digits, and an offset with or without its colon.
_GPX_TIME = re.compile(
    r"^(\d{4})-(\d{1,2})-(\d{1,2})[T ](\d{1,2}):(\d{1,2}):(\d{1,2})(?:\.(\d{1,15}))?"
    r"(Z|[+\-\u2212]\d{2}:?(?:\d{2})?)?$"
)


class GpxPoint(NamedTuple):
    latitude: float
    longitude: float
    time: Optional[datetime]


def _parse_gpx_time(text: Optional[str]) -> Optional[datetime]:
    """Parse a GPX ``<time>``. A missing or unreadable one is ``None``, which leaves the point unpaced."""
    match = _GPX_TIME.match(text) if text else None
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    microsecond = int((match.group(7) or "0")[:6].ljust(6, "0"))
    zone = match.group(8)
    try:
        tzinfo = None
        if zone == "Z":
            tzinfo = timezone.utc
        elif zone:
            digits = zone[1:].replace(":", "")
            offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:] or 0))
            tzinfo = timezone(offset if zone[0] == "+" else -offset)
        return datetime(year, month, day, hour, minute, second, microsecond, tzinfo)
    except ValueError:
        # Well-formed, but not a real date, time or offset
        return None


def _local_name(element: Any) -> str:
    # GPX 1.0 and 1.1 differ only in namespace, and some writers leave it out
    return element.tag.rpartition("}")[2]


def iter_gpx_track_points(filename: str) -> Iterator[GpxPoint]:
    """Yield the track points of a GPX file, in order, across all of its tracks and segments."""
    root = DefusedET.parse(filename).getroot()
    if root is None:
        return
    for track in (e for e in root if _local_name(e) == "trk"):
        for segment in (e for e in track if _local_name(e) == "trkseg"):
            for point in (e for e in segment if _local_name(e) == "trkpt"):
                time = next((e.text for e in point if _local_name(e) == "time"), None)
                try:
                    latitude, longitude = float(point.attrib["lat"]), float(point.attrib["lon"])
                except (KeyError, ValueError) as e:
                    raise ValueError(f"GPX track point without a valid lat/lon: {point.attrib}") from e
                yield GpxPoint(latitude, longitude, _parse_gpx_time(time))


class LocationSimulationBase:
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    async def set(self, latitude: float, longitude: float) -> None:
        pass

    @abstractmethod
    async def clear(self) -> None:
        pass

    async def play_gpx_file(self, filename: str, disable_sleep: bool = False, timing_randomness_range: int = 0):
        # Read the whole file first, so a malformed one fails before any location is set
        points = list(iter_gpx_track_points(filename))

        last_time = None
        gpx_timing_noise = None
        for point in points:
            # GPX points may individually lack a timestamp; only pace between two timed points.
            if last_time is not None and point.time is not None:
                duration = (point.time - last_time).total_seconds()
                if duration >= 0 and not disable_sleep:
                    if timing_randomness_range:
                        gpx_timing_noise = random.randint(-timing_randomness_range, timing_randomness_range) / 1000
                        duration += gpx_timing_noise

                    self.logger.info(f"waiting for {duration:.3f}s")
                    await asyncio.sleep(duration)
            last_time = point.time
            self.logger.info(f"set location to {point.latitude} {point.longitude}")
            await self.set(point.latitude, point.longitude)
