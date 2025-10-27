from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot

PNG_HEADER = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"
TIFF_HEADER = b"\x4d\x4d\x00\x2a"


def test_screenshot(dvt):
    """
    Test that taking a screenshot returns a PNG.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    screenshot = Screenshot(dvt).get_screenshot()
    assert screenshot.startswith(PNG_HEADER) or screenshot.startswith(TIFF_HEADER)
