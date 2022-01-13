import time

import pytest

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.web_protocol.driver import WebDriver
from pymobiledevice3.services.webinspector import WebinspectorService, SAFARI


@pytest.fixture
def webdriver(lockdown: LockdownClient):
    inspector = WebinspectorService(lockdown=lockdown)
    with inspector.connect():
        safari = inspector.open_app(SAFARI)
        time.sleep(1)
        with inspector.automation_session(safari) as session:
            driver = WebDriver(session)
            driver.start_session()
            yield driver
