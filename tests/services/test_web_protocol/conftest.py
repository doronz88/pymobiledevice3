import pytest

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.web_protocol.driver import WebDriver
from pymobiledevice3.services.webinspector import SAFARI, WebinspectorService


@pytest.fixture
def webdriver(lockdown: LockdownClient):
    inspector = WebinspectorService(lockdown=lockdown)
    inspector.connect()
    safari = inspector.open_app(SAFARI)
    inspector.flush_input(1)
    session = inspector.automation_session(safari)
    driver = WebDriver(session)
    driver.start_session()
    try:
        yield driver
    finally:
        inspector.close()
        inspector.loop.close()
