import time

from pymobiledevice3.bonjour import browse

BROWSE_TIMEOUT = 1


def test_bonjour(lockdown):
    lockdown.enable_wifi_connections = True
    # give the os some time to start the bonjour broadcast
    time.sleep(3)
    assert len(browse(BROWSE_TIMEOUT).keys()) >= 1
