from pymobiledevice3 import usbmux


def test_list_devices(lockdown):
    assert len(usbmux.list_devices()) >= 1
