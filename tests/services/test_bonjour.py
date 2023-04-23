from pymobiledevice3.bonjour import browse

BROWSE_TIMEOUT = 1


def test_bonjour(lockdown):
    lockdown.enable_wifi_connections = True
    assert len(browse(BROWSE_TIMEOUT).keys()) >= 1
