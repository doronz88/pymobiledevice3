import pytest

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.web_protocol.driver import WebDriver
from pymobiledevice3.services.webinspector import SAFARI, WebinspectorService


@pytest.fixture
async def webdriver(lockdown: LockdownClient):
    inspector = WebinspectorService(lockdown=lockdown)
    await inspector.connect()
    safari = await inspector.open_app(SAFARI)
    await inspector.flush_input(1)
    session = await inspector.automation_session(safari)
    driver = WebDriver(session)
    await driver.start_session()
    try:
        yield driver
    finally:
        await inspector.close()
