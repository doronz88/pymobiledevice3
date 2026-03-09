import pytest

from pymobiledevice3.exceptions import InvalidServiceError
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot

PNG_HEADER = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"
TIFF_HEADER = b"\x4d\x4d\x00\x2a"


async def test_screenshot(service_provider) -> None:
    """
    Test that taking a screenshot returns a PNG.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    try:
        async with DvtProvider(service_provider) as dvt, Screenshot(dvt) as screenshot_service:
            screenshot = await screenshot_service.get_screenshot()
    except InvalidServiceError:
        pytest.skip("Skipping screenshot test since DVT provider service isn't accessible")
    assert screenshot.startswith(PNG_HEADER) or screenshot.startswith(TIFF_HEADER)
