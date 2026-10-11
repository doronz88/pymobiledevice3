from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from pymobiledevice3.services.dvt.instruments.location_simulation_base import (
    GpxPoint,
    LocationSimulationBase,
    iter_gpx_track_points,
)

GPX = """<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="test"{namespace}>
  <wpt lat="1" lon="2"><time>2020-01-01T00:00:00Z</time></wpt>
  <rte><rtept lat="3" lon="4"/></rte>
  <trk>
    <name>first</name>
    <trkseg>
      <trkpt lat="32.1" lon="34.8"><ele>5</ele><time>2024-01-02T03:04:05Z</time></trkpt>
      <trkpt lat="32.2" lon="34.9"><time>2024-01-02T03:04:07.5Z</time></trkpt>
    </trkseg>
    <trkseg>
      <trkpt lat="-1.5" lon="-2.5"></trkpt>
    </trkseg>
  </trk>
  <trk>
    <trkseg>
      <trkpt lat="0" lon="0"><time>2024-01-02T05:04:10+02:00</time></trkpt>
    </trkseg>
  </trk>
</gpx>
"""


def _write(tmp_path: Path, content: str) -> str:
    path = tmp_path / "track.gpx"
    path.write_text(content, encoding="utf-8")
    return str(path)


@pytest.mark.parametrize(
    "namespace",
    ["", ' xmlns="http://www.topografix.com/GPX/1/1"', ' xmlns="http://www.topografix.com/GPX/1/0"'],
    ids=["no-namespace", "gpx-1.1", "gpx-1.0"],
)
def test_track_points_are_read_in_order_across_tracks_and_segments(tmp_path: Path, namespace: str) -> None:
    points = list(iter_gpx_track_points(_write(tmp_path, GPX.format(namespace=namespace))))

    assert points == [
        GpxPoint(32.1, 34.8, datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)),
        GpxPoint(32.2, 34.9, datetime(2024, 1, 2, 3, 4, 7, 500000, tzinfo=timezone.utc)),
        GpxPoint(-1.5, -2.5, None),
        GpxPoint(0.0, 0.0, datetime(2024, 1, 2, 5, 4, 10, tzinfo=timezone(timedelta(hours=2)))),
    ]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2024-01-02 03:04:05", datetime(2024, 1, 2, 3, 4, 5)),
        ("2024-1-2T3:4:5-0530", datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone(-timedelta(hours=5, minutes=30)))),
        ("2024-01-02T03:04:05+02", datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone(timedelta(hours=2)))),
        ("2024-01-02T03:04:05.123456789Z", datetime(2024, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc)),
        # Unreadable times leave the point unpaced instead of failing the whole file
        ("yesterday", None),
        ("2024-13-02T03:04:05Z", None),
        ("", None),
    ],
)
def test_track_point_time_formats(tmp_path: Path, text: str, expected: object) -> None:
    doc = f'<gpx><trk><trkseg><trkpt lat="1" lon="2"><time>{text}</time></trkpt></trkseg></trk></gpx>'
    assert [point.time for point in iter_gpx_track_points(_write(tmp_path, doc))] == [expected]


@pytest.mark.parametrize("attributes", ['lon="2"', 'lat="x" lon="2"'], ids=["missing", "not-a-number"])
def test_track_point_without_coordinates_is_an_error(tmp_path: Path, attributes: str) -> None:
    doc = f"<gpx><trk><trkseg><trkpt {attributes}/></trkseg></trk></gpx>"
    with pytest.raises(ValueError, match="lat/lon"):
        list(iter_gpx_track_points(_write(tmp_path, doc)))


class _Recorder(LocationSimulationBase):
    def __init__(self) -> None:
        super().__init__()
        self.locations: list[tuple[float, float]] = []

    async def set(self, latitude: float, longitude: float) -> None:
        self.locations.append((latitude, longitude))

    async def clear(self) -> None:
        self.locations.clear()


@pytest.mark.asyncio
async def test_play_gpx_file_sets_every_track_point(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    waits: list[float] = []

    async def record_sleep(duration: float) -> None:
        waits.append(duration)

    monkeypatch.setattr("pymobiledevice3.services.dvt.instruments.location_simulation_base.asyncio.sleep", record_sleep)
    simulation = _Recorder()

    await simulation.play_gpx_file(_write(tmp_path, GPX.format(namespace="")))

    assert simulation.locations == [(32.1, 34.8), (32.2, 34.9), (-1.5, -2.5), (0.0, 0.0)]
    # 2.5 s between the first two points; the untimed third point is not paced and resets the pacing
    assert waits == [2.5]


@pytest.mark.asyncio
async def test_play_gpx_file_sets_nothing_from_a_malformed_file(tmp_path: Path) -> None:
    doc = '<gpx><trk><trkseg><trkpt lat="1" lon="2"/><trkpt lon="2"/></trkseg></trk></gpx>'
    simulation = _Recorder()

    with pytest.raises(ValueError, match="lat/lon"):
        await simulation.play_gpx_file(_write(tmp_path, doc))

    assert simulation.locations == []
