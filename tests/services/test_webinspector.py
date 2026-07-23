from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import pytest

from pymobiledevice3.exceptions import WebInspectorNotEnabledError
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.webinspector import SAFARI, WebinspectorService


@asynccontextmanager
async def webinspector_service(lockdown: LockdownClient) -> AsyncGenerator[WebinspectorService, None]:
    inspector = WebinspectorService(lockdown=lockdown)
    try:
        try:
            await inspector.connect()
        except WebInspectorNotEnabledError:
            pytest.xfail("Web Inspector is disabled on the device")
        async with inspector:
            yield inspector
    finally:
        await inspector.close()


async def testp_opening_app(lockdown: LockdownClient) -> None:
    async with webinspector_service(lockdown) as inspector:
        safari = await inspector.open_app(SAFARI)
        pages = await inspector.get_open_pages()
        # Might take a while to update.
        if safari.name not in pages:
            await inspector.flush_input(1)
        pages = await inspector.get_open_pages()
        assert safari.name in pages
        assert pages[safari.name]
