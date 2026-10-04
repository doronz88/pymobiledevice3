import asyncio
from types import SimpleNamespace
from typing import Any, cast

from pymobiledevice3.dtx_service_provider import DtxServiceProvider
from pymobiledevice3.services.dvt.instruments.graphics import Graphics


class _FakeProvider:
    dtx = SimpleNamespace(register_service=lambda service_class: None)

    async def connect(self) -> None:
        pass


class _FakeGraphicsService:
    def __init__(self, events: list[Any]) -> None:
        self.events: asyncio.Queue[Any] = asyncio.Queue()
        for event in events:
            self.events.put_nowait(event)
        self.calls: list[str] = []

    async def start_sampling_at_time_interval_(self, interval: float) -> None:
        self.calls.append("start")

    async def stop_sampling(self) -> None:
        self.calls.append("stop")


async def _take(samples: Any, count: int) -> list[Any]:
    taken = []
    async for sample in samples:
        taken.append(sample)
        if len(taken) == count:
            return taken
    raise AssertionError("the sampler stopped early")


async def test_fps_skips_the_first_sample_and_other_events() -> None:
    service = _FakeGraphicsService([
        {"CoreAnimationFramesPerSecond": 0, "XRVideoCardRunTimeStamp": 1224},
        ("someSelector:", [1]),
        {"CoreAnimationFramesPerSecond": 60, "XRVideoCardRunTimeStamp": 1013158},
        {"CoreAnimationFramesPerSecond": 0, "XRVideoCardRunTimeStamp": 2033491},
    ])
    graphics = Graphics(cast(DtxServiceProvider, _FakeProvider()))
    graphics._service = cast(Any, service)

    async with graphics:
        assert await _take(graphics.fps(), 2) == [60, 0]

    assert service.calls == ["start", "stop"]


async def test_fps(dvt) -> None:
    async with Graphics(dvt) as graphics:
        (fps,) = await _take(graphics.fps(), 1)

    assert isinstance(fps, int)
    assert fps >= 0
