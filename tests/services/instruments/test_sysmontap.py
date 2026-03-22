import asyncio

import pytest

from pymobiledevice3.exceptions import InvalidServiceError
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap


async def test_sysmontap(service_provider) -> None:
    received = None
    try:
        async with DvtProvider(service_provider) as dvt, await Sysmontap.create(dvt) as sysmon, asyncio.timeout(2):
            async for process_snapshot in sysmon.iter_processes():
                received = process_snapshot
                break
        assert received is not None
    except InvalidServiceError:
        pytest.skip("Skipping sysmontap test since DVT provider service isn't accessible")
