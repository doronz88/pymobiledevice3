# -*- coding:utf-8 -*-
from pymobiledevice3.services.springboard import SpringBoardServicesService

PNG_HEADER = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'


def test_get_icon_png_data(lockdown):
    """
    Test that getting icon's data returns a valid PNG.
    :param pymobiledevice3.lockdown.LockdownClient lockdown: Lockdown client.
    """
    springboard = SpringBoardServicesService(lockdown)
    icon_data = springboard.get_icon_pngdata("com.apple.weather")
    assert icon_data.startswith(PNG_HEADER)
