import asyncio

import pytest

from pymobiledevice3.cli.developer import wda

pytestmark = [pytest.mark.cli]


async def test_a_failing_command_still_stops_its_xctrunner() -> None:
    runner = asyncio.ensure_future(asyncio.Event().wait())

    @wda._stops_xctrunner
    async def command(_xctrunner: "asyncio.Future[None]") -> None:
        raise RuntimeError("no such element")

    with pytest.raises(RuntimeError):
        await command(_xctrunner=runner)
    assert runner.cancelled()


async def test_a_command_without_xctrunner_needs_no_cleanup() -> None:
    @wda._stops_xctrunner
    async def command(_xctrunner: None) -> None:
        pass

    await command(_xctrunner=None)
