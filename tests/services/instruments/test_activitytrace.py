import asyncio

import pytest

from pymobiledevice3.exceptions import InvalidServiceError
from pymobiledevice3.services.dvt.instruments.activity_trace_tap import ActivityTraceTap
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider


async def test_activitytrace(service_provider) -> None:
    received = None
    try:
        async with DvtProvider(service_provider) as dvt, ActivityTraceTap(dvt) as tap, asyncio.timeout(2):
            async for data in tap:
                received = data
                break

        assert received is not None
    except InvalidServiceError:
        pytest.skip("Skipping screenshot test since DVT provider service isn't accessible")
